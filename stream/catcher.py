"""
流量擷取：NFStream + NFPlugin → CICIoT2023 46 個特徵。

提供給 pipeline / API 呼叫的函數
--------------------------------
  離線（pcap）
    iter_flows(source, ...)          逐條 yield record（metadata + 46 特徵）
    extract_pcap(path, ...)          一次讀完 pcap，回傳 DataFrame
  即時（網卡）
    start_capture(loop, queue, ...)  在獨立子行程擷取，record 送進 asyncio.Queue
    stop_capture(timeout)            停止擷取並清理 NFStreamer 的 meter 行程
    get_capture_status()             目前狀態（是否執行中、來源、flow 數、錯誤訊息…）
  相容舊介面
    Start(loop, queue) / Stop()

record 格式
-----------
  META_COLUMNS（source_ip、destination_ip、source_port、destination_port、protocol、
  start_time、end_time、duration_ms、packet_count、byte_count）
  + CICIOT2023_COLUMNS（46 個特徵，順序與資料集及模型 feature_names 相同）

為什麼即時擷取要開子行程
------------------------
NFStreamer 會另外 fork 出 meter 行程抓封包，且只在迭代中收到 KeyboardInterrupt 時才會
終止它們；直接 break 出迴圈會讓 meter 行程殘留、在背景持續擷取（已實測：殘留 7 個）。
因此擷取放在獨立子行程，停止時送 SIGINT，讓 NFStreamer 走自己的清理流程。

聚合單位
--------
以 NFStream 的「5-tuple 雙向 flow」為聚合單位，**刻意不複刻** CICIoT2023 官方的
100-packet 滑動視窗。官方 CSV 的一列是視窗平均值，證據（實測 data/*.csv 73 萬列）：
  * Number  的值為 1, 1.5, 2, 2.5 … 即封包序號的移動平均，95.7% 的列固定為 9.5
  * Weight  的值為 1, 2.5, 4.667, 7.5 … 即 i² 的移動平均，95.7% 的列固定為 141.55
  * Variance 只有 0.19 / 0.95 / 0.18 這類兩位小數 → k/100，直接透露視窗大小是 100
因此 Number / Weight / Variance / IAT / *_count 的「數值分佈」無法與官方 CSV 對齊，
但欄位名稱、型別與計算語意是一致的。詳見下表 MATCH 欄。

欄位對照（✓=已用 data/*.csv 驗證；~=定義相同但分佈受官方視窗影響；!=NFStream 限制）
-----------------------------------------------------------------------------
  flow_duration    ~  flow 持續時間（秒）
  Header_Length    ✓  mean(raw_size - payload_size)，TCP/UDP 才算，其餘 0
                      → TCP 無 option 時 14+20+20=54，UDP 14+20+8=42，ICMP 0
                      （資料集 TCP 眾數正是 54、UDP 低端 42、ICMP 中位數 0）
  Protocol Type    ✓  L4 協定號（1/6/17…）
  Duration         ✓  平均 TTL（不是時間！資料集 min 0 / max 255 / mean 66.4）
  Rate             ✓  封包數 / 持續時間
  Srate / Drate    ~  上行 / 下行速率（官方 CSV 中 Srate 恆等於 Rate、Drate 恆為 0）
  *_flag_number    ✓  二元 0/1（官方 CSV 只有 {0.0, 1.0}）
  *_count          ~  該 flag 的封包數（官方 CSV 是視窗平均故為小數）
  HTTP … IRC       ✓  依 port 判定
  TCP/UDP/ICMP     ✓  依 L4 協定，互斥
  ARP / IPv / LLC  !  NFStream 只處理 IP flow，ARP 永遠 0、IPv/LLC 永遠 1
                      （官方 CSV 中 IPv==LLC 為 100%，且 99.99% 為 1，故吻合）
  Tot sum          ✓  flow 總位元組數
  Min/Max/AVG/Std  ✓  封包長度統計（含 L2，資料集 Min 下限 42 一致）
  Tot size         ~  封包長度 → 用平均封包長度
  IAT              ~  平均封包間隔（µs）。官方 CSV 該欄混入了錄製當下的絕對時間戳，
                      數值無法重現
  Number           ~  flow 封包數
  Magnitue         ✓  sqrt(avg_in + avg_out)，單向 flow 缺的那方回退成整體 AVG
                      （實測資料集 Magnitue²/AVG 中位數與 IQR 皆為 2.0）
  Radius           ✓  sqrt(var_in + var_out)，單向 flow 同上回退
  Covariance       ~  cov(上行長度, 下行長度)，兩序列截到等長配對
  Variance         ~  var_in / var_out（官方 CSV 該欄是 k/100 的視窗產物）
  Weight           !  上行封包數 × 下行封包數。官方 CSV 實際是 i² 的移動平均
                      （95.7% 恆為 141.55、最小值 1），單向 flow 這裡會得到 0，無法對齊
"""

import asyncio
import datetime
import math
import multiprocessing as mp
import os
import queue as queue_mod
import signal
import threading

from nfstream import NFStreamer, NFPlugin

# 與 data/*.csv 及模型 feature_names 完全相同的欄位順序（不含 label）
CICIOT2023_COLUMNS = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate",
    "Srate", "Drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP",
    "DHCP", "ARP", "ICMP", "IPv", "LLC",
    "Tot sum", "Min", "Max", "AVG", "Std", "Tot size", "IAT", "Number",
    "Magnitue", "Radius", "Covariance", "Variance", "Weight",
]

# 對應 flow 資料表的欄位
META_COLUMNS = [
    "source_ip", "destination_ip", "source_port", "destination_port", "protocol",
    "start_time", "end_time", "duration_ms", "packet_count", "byte_count",
]

DEFAULT_IDLE_TIMEOUT = 5      # 秒，flow 閒置多久視為結束
DEFAULT_ACTIVE_TIMEOUT = 30   # 秒，長連線每隔多久強制切出一條 flow

_PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}

# port → 應用層旗標欄位名
_PORT_APP = {
    80: "HTTP", 443: "HTTPS", 53: "DNS", 23: "Telnet",
    25: "SMTP", 22: "SSH", 194: "IRC", 67: "DHCP", 68: "DHCP",
}

# 每個方向最多保留多少封包長度（給 Covariance / Variance 用），避免長 flow 吃爆記憶體
_MAX_KEEP = 4096


# --- 特徵計算 -------------------------------------------------

class CICIOT2023Plugin(NFPlugin):
    """補齊 NFStream 原生沒有的欄位：TTL、header 長度、應用層 port 旗標、各方向長度序列。"""

    def on_init(self, packet, flow):
        flow.udps.ttl_sum = 0
        flow.udps.ttl_n = 0
        flow.udps.hdr_sum = 0
        flow.udps.hdr_n = 0
        flow.udps.app = {name: 0 for name in
                         ("HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "DHCP")}
        flow.udps.src2dst_ps = []   # 上行封包長度
        flow.udps.dst2src_ps = []   # 下行封包長度
        self._accumulate(packet, flow)

    def on_update(self, packet, flow):
        self._accumulate(packet, flow)

    def _accumulate(self, packet, flow):
        # --- TTL: 從原始 IP header 取 (v4 offset 8 / v6 hop limit offset 7) ---
        ip = packet.ip_packet
        if ip:
            if packet.ip_version == 4 and len(ip) > 8:
                flow.udps.ttl_sum += ip[8]
                flow.udps.ttl_n += 1
            elif packet.ip_version == 6 and len(ip) > 7:
                flow.udps.ttl_sum += ip[7]
                flow.udps.ttl_n += 1

        # --- Header_Length: L2+L3+L4 表頭總長，僅 TCP/UDP 計算 ---
        # raw_size 含 Ethernet 表頭，扣掉 payload 即為全部表頭長度。
        # TCP 無 option → 14+20+20=54、UDP → 14+20+8=42，與資料集眾數吻合。
        if packet.protocol in (6, 17):
            hdr = max(packet.raw_size - packet.payload_size, 0)
        else:
            hdr = 0
        flow.udps.hdr_sum += hdr
        flow.udps.hdr_n += 1

        # --- 應用層協定（依 port）---
        for port in (packet.src_port, packet.dst_port):
            name = _PORT_APP.get(port)
            if name:
                flow.udps.app[name] = 1

        # --- 各方向封包長度序列（Covariance / Variance 用）---
        if packet.direction == 0:
            if len(flow.udps.src2dst_ps) < _MAX_KEEP:
                flow.udps.src2dst_ps.append(packet.raw_size)
        else:
            if len(flow.udps.dst2src_ps) < _MAX_KEEP:
                flow.udps.dst2src_ps.append(packet.raw_size)


# NFStream 的 *_stddev_ps 用的是樣本標準差（分母 n-1，已實測確認），
# 以下兩個函式一併採用 n-1，確保 Variance / Covariance 與 Std / Radius 對變異數的定義一致。
def _variance(xs):
    n = len(xs)
    if n < 2:
        return 0.0
    mean = sum(xs) / n
    return sum((x - mean) ** 2 for x in xs) / (n - 1)


def _covariance(xs, ys):
    """cov(上行長度, 下行長度)。兩序列長度不同，截到等長後逐一配對。"""
    n = min(len(xs), len(ys))
    if n < 2:
        return 0.0
    xs, ys = xs[:n], ys[:n]
    mx = sum(xs) / n
    my = sum(ys) / n
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (n - 1)


def build_feature(flow):
    """把一條 NFStream flow 轉成 CICIoT2023 的 46 個特徵。"""
    n = flow.bidirectional_packets
    dur_s = flow.bidirectional_duration_ms / 1000.0
    proto = flow.protocol

    ttl_mean = flow.udps.ttl_sum / flow.udps.ttl_n if flow.udps.ttl_n else 0.0
    hdr_mean = flow.udps.hdr_sum / flow.udps.hdr_n if flow.udps.hdr_n else 0.0

    # 封包長度統計（需要 statistical_analysis=True）
    avg_ps = float(flow.bidirectional_mean_ps or 0.0)
    std_ps = float(flow.bidirectional_stddev_ps or 0.0)
    # 單向 flow（洪水攻擊幾乎都是）缺少的那一方，資料集實際上是回退成整體統計量：
    # 實測 Magnitue²/AVG 的中位數與四分位距都是 2.0，即 avg_in、avg_out 同時等於 AVG。
    # 若直接以 0 代入，單向 flow 會算出 sqrt(AVG)，低於資料集 Magnitue 的最小值 9.165。
    up_mean = float(flow.src2dst_mean_ps or 0.0) if flow.src2dst_packets else avg_ps
    dn_mean = float(flow.dst2src_mean_ps or 0.0) if flow.dst2src_packets else avg_ps
    up_std = float(flow.src2dst_stddev_ps or 0.0) if flow.src2dst_packets else std_ps
    dn_std = float(flow.dst2src_stddev_ps or 0.0) if flow.dst2src_packets else std_ps

    # Variance = 上行長度變異數 / 下行長度變異數
    up_var, dn_var = _variance(flow.udps.src2dst_ps), _variance(flow.udps.dst2src_ps)
    variance = (up_var / dn_var) if dn_var > 0 else 0.0

    app = flow.udps.app

    return {
        "flow_duration": dur_s,
        "Header_Length": hdr_mean,
        "Protocol Type": float(proto),
        "Duration": ttl_mean,                       # 資料集這欄是 TTL，不是時間
        "Rate": (n / dur_s) if dur_s > 0 else 0.0,
        "Srate": (flow.src2dst_packets / dur_s) if dur_s > 0 else 0.0,
        "Drate": (flow.dst2src_packets / dur_s) if dur_s > 0 else 0.0,

        # ── flag_number = 二元旗標（資料集只有 0.0 / 1.0）──
        "fin_flag_number": 1.0 if flow.bidirectional_fin_packets else 0.0,
        "syn_flag_number": 1.0 if flow.bidirectional_syn_packets else 0.0,
        "rst_flag_number": 1.0 if flow.bidirectional_rst_packets else 0.0,
        "psh_flag_number": 1.0 if flow.bidirectional_psh_packets else 0.0,
        "ack_flag_number": 1.0 if flow.bidirectional_ack_packets else 0.0,
        "ece_flag_number": 1.0 if flow.bidirectional_ece_packets else 0.0,
        "cwr_flag_number": 1.0 if flow.bidirectional_cwr_packets else 0.0,

        # ── count = 帶該 flag 的封包數 ──
        "ack_count": float(flow.bidirectional_ack_packets),
        "syn_count": float(flow.bidirectional_syn_packets),
        "fin_count": float(flow.bidirectional_fin_packets),
        "urg_count": float(flow.bidirectional_urg_packets),
        "rst_count": float(flow.bidirectional_rst_packets),

        # ── 協定 one-hot ──
        "HTTP": float(app["HTTP"]),
        "HTTPS": float(app["HTTPS"]),
        "DNS": float(app["DNS"]),
        "Telnet": float(app["Telnet"]),
        "SMTP": float(app["SMTP"]),
        "SSH": float(app["SSH"]),
        "IRC": float(app["IRC"]),
        "TCP": 1.0 if proto == 6 else 0.0,
        "UDP": 1.0 if proto == 17 else 0.0,
        "DHCP": float(app["DHCP"]),
        "ARP": 0.0,                                 # NFStream 只處理 IP flow
        "ICMP": 1.0 if proto in (1, 58) else 0.0,   # 58 = ICMPv6
        "IPv": 1.0,                                 # 同上，能成流的一定是 IP
        "LLC": 1.0,                                 # 資料集中 LLC 與 IPv 100% 相同

        # ── 封包長度統計 ──
        "Tot sum": float(flow.bidirectional_bytes),
        "Min": float(flow.bidirectional_min_ps or 0.0),
        "Max": float(flow.bidirectional_max_ps or 0.0),
        "AVG": avg_ps,
        "Std": std_ps,
        "Tot size": avg_ps,                         # 官方為單封包長度，flow 層取平均
        "IAT": float(flow.bidirectional_mean_piat_ms or 0.0) * 1000.0,   # ms → µs
        "Number": float(n),
        "Magnitue": math.sqrt(up_mean + dn_mean),   # 保留資料集的 typo
        "Radius": math.sqrt(up_std ** 2 + dn_std ** 2),
        "Covariance": _covariance(flow.udps.src2dst_ps, flow.udps.dst2src_ps),
        "Variance": variance,
        "Weight": float(flow.src2dst_packets * flow.dst2src_packets),
    }


def flow_metadata(flow):
    """flow 的識別資訊，欄位名稱對應 flow 資料表。"""
    return {
        "source_ip": flow.src_ip,
        "destination_ip": flow.dst_ip,
        "source_port": flow.src_port,
        "destination_port": flow.dst_port,
        "protocol": _PROTO_NAME.get(flow.protocol, str(flow.protocol)),
        "start_time": datetime.datetime.fromtimestamp(flow.bidirectional_first_seen_ms / 1000.0),
        "end_time": datetime.datetime.fromtimestamp(flow.bidirectional_last_seen_ms / 1000.0),
        "duration_ms": int(flow.bidirectional_duration_ms),
        "packet_count": int(flow.bidirectional_packets),
        "byte_count": int(flow.bidirectional_bytes),
    }


def flow_to_record(flow):
    """metadata + 46 個特徵合成一筆 record。"""
    return {**flow_metadata(flow), **build_feature(flow)}


# --- 離線擷取 -------------------------------------------------

def iter_flows(source, bpf_filter=None, idle_timeout=DEFAULT_IDLE_TIMEOUT,
               active_timeout=DEFAULT_ACTIVE_TIMEOUT, limit=None):
    """
    對 source（網卡名稱或 pcap 路徑）擷取，逐條 yield record。

    要提前結束請用 limit，不要在呼叫端 break：break 會讓 NFStreamer 的 meter 行程殘留。
    """
    streamer = NFStreamer(
        source=source,
        bpf_filter=bpf_filter or None,
        idle_timeout=idle_timeout,
        active_timeout=active_timeout,
        statistical_analysis=True,
        max_nflows=limit or 0,
        udps=CICIOT2023Plugin(),
    )
    for flow in streamer:
        yield flow_to_record(flow)


def extract_pcap(path, bpf_filter=None, idle_timeout=DEFAULT_IDLE_TIMEOUT,
                 active_timeout=DEFAULT_ACTIVE_TIMEOUT, limit=None):
    """讀完整個 pcap，回傳 DataFrame（欄位 = META_COLUMNS + CICIOT2023_COLUMNS）。"""
    import pandas as pd

    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    rows = list(iter_flows(path, bpf_filter, idle_timeout, active_timeout, limit))
    return pd.DataFrame(rows, columns=META_COLUMNS + CICIOT2023_COLUMNS)


# --- 即時擷取 -------------------------------------------------

def _capture_worker(source, bpf_filter, idle_timeout, active_timeout, out_q):
    """子行程主體：擷取 flow 並送回主行程。"""
    # SIGINT → KeyboardInterrupt，讓 NFStreamer 自行終止 meter 行程。
    # 不要攔 SIGTERM：NFStreamer 用 SIGTERM 終止 meter，meter 是從這裡 fork 的，會繼承 handler。
    signal.signal(signal.SIGINT, signal.default_int_handler)

    try:
        for record in iter_flows(source, bpf_filter, idle_timeout, active_timeout):
            out_q.put(("flow", record))
    except KeyboardInterrupt:
        pass
    except Exception as e:   # 網卡不存在、權限不足、BPF 語法錯誤等
        out_q.put(("error", f"{type(e).__name__}: {e}"))
    finally:
        out_q.put(("done", None))


class _CaptureSession:
    def __init__(self, source, bpf_filter, idle_timeout, active_timeout, loop, queue):
        self.source = source
        self.bpf_filter = bpf_filter
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.loop = loop
        self.queue = queue
        self.flow_count = 0
        self.error = None
        self.started_at = datetime.datetime.now()
        self.stopped_at = None
        self.stop_requested = threading.Event()

        # 用 spawn 而非 fork：主行程（uvicorn）已有事件迴圈與多個執行緒，fork 可能繼承到被鎖住的鎖
        ctx = mp.get_context("spawn")
        self.out_q = ctx.Queue(maxsize=10000)
        self.proc = ctx.Process(
            target=_capture_worker,
            args=(source, bpf_filter, idle_timeout, active_timeout, self.out_q),
            name="xaids-capture",
        )
        self.forwarder = threading.Thread(target=self._forward, name="xaids-capture-forwarder",
                                          daemon=True)

    def start(self):
        self.proc.start()
        self.forwarder.start()

    @property
    def running(self):
        return self.stopped_at is None

    def _forward(self):
        """把子行程送回的 record 轉進 asyncio.Queue。"""
        while True:
            try:
                kind, payload = self.out_q.get(timeout=1.0)
            except queue_mod.Empty:
                if not self.proc.is_alive():   # 子行程被強制結束，沒送出 done
                    break
                continue

            if kind == "done":
                break
            if kind == "error":
                self.error = payload
            elif kind == "flow" and not self.stop_requested.is_set():
                self.flow_count += 1
                if self.loop is not None and self.queue is not None:
                    try:
                        asyncio.run_coroutine_threadsafe(self.queue.put(payload), self.loop)
                    except RuntimeError:       # 事件迴圈已關閉
                        break

        self.proc.join(timeout=5)
        self._mark_stopped()

    def _mark_stopped(self):
        if self.stopped_at is None:
            self.stopped_at = datetime.datetime.now()

    def stop(self, timeout):
        self.stop_requested.set()
        if self.proc.is_alive():
            os.kill(self.proc.pid, signal.SIGINT)
            self.proc.join(timeout)
        if self.proc.is_alive():   # 最後手段
            self.proc.kill()
            self.proc.join(2)
        self.forwarder.join(timeout=2)
        self._mark_stopped()

    def status(self):
        return {
            "running": self.running,
            "source": self.source,
            "bpf_filter": self.bpf_filter,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "stopped_at": self.stopped_at.isoformat(timespec="seconds") if self.stopped_at else None,
            "flow_count": self.flow_count,
            "error": self.error,
        }


_session = None
_session_lock = threading.Lock()


def start_capture(loop, queue, source=None, bpf_filter=None,
                  idle_timeout=DEFAULT_IDLE_TIMEOUT, active_timeout=DEFAULT_ACTIVE_TIMEOUT):
    """
    開始即時擷取，每條結束的 flow 以 record 形式放進 queue。

    source / bpf_filter 為 None 時使用 config 的 CAPTURE_IFACE / CAPTURE_FILTER；
    bpf_filter 傳空字串表示不過濾。

    回傳 (ok, message)。子行程啟動後才發生的錯誤（例如權限不足）不會反映在回傳值，
    請用 get_capture_status()["error"] 查詢。
    """
    global _session
    with _session_lock:
        if _session is not None and _session.running:
            return False, "已有擷取正在執行中"
        if source is None or bpf_filter is None:
            from config import CAPTURE_IFACE, CAPTURE_FILTER
            source = CAPTURE_IFACE if source is None else source
            bpf_filter = CAPTURE_FILTER if bpf_filter is None else bpf_filter

        session = _CaptureSession(source, bpf_filter or None, idle_timeout, active_timeout,
                                  loop, queue)
        session.start()
        _session = session
    return True, "started"


def stop_capture(timeout=5.0):
    """停止即時擷取。沒有正在執行的擷取時回傳 False。會阻塞最多約 timeout + 2 秒。"""
    with _session_lock:
        session = _session
    if session is None or not session.running:
        return False
    session.stop(timeout)
    return True


def get_capture_status():
    """目前（或最近一次）擷取的狀態。"""
    with _session_lock:
        session = _session
    if session is None:
        return {"running": False, "source": None, "bpf_filter": None, "started_at": None,
                "stopped_at": None, "flow_count": 0, "error": None}
    return session.status()


# --- 相容舊介面（core/pipeline.py 使用）-----------------------

def Start(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
    return start_capture(loop, queue)


def Stop():
    return stop_capture()
