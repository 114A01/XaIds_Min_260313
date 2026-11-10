"""
流量擷取：NFStream 5-tuple 雙向 flow → 模型特徵。

特徵算法與離線萃取（stream/pcap_feature_extractor.py）完全相同：
兩邊都從 stream/flow_features.py 取得 NFSTREAM_PARAMS 和 FEATURES，
直接使用 nfstream 內建欄位，不另外計算。各特徵的定義見 document/nfstream_features.md。

提供給 pipeline / API 呼叫的函數
--------------------------------
  離線（pcap）
    iter_flows(source, ...)          逐條 yield record（metadata + FEATURES）
    extract_pcap(path, ...)          一次讀完 pcap，回傳 DataFrame
  即時（網卡）
    start_capture(loop, queue, ...)  在獨立子行程擷取，record 送進 asyncio.Queue
    stop_capture(timeout)            停止擷取並清理 NFStreamer 的 meter 行程
    get_capture_status()             目前狀態（是否執行中、來源、flow 數、錯誤訊息…）
  相容舊介面
    Start(loop, queue) / Stop()

record 格式
-----------
  META_COLUMNS（source_ip、destination_ip、source_port、destination_port、protocol_name、
  start_time、end_time、duration_ms、packet_count、byte_count），對應 flow 資料表
  + FEATURES（模型特徵，順序與訓練資料及模型 feature_names 相同）

  protocol 是特徵，值為協定號碼（6 = TCP、17 = UDP…）；
  協定名稱（"TCP"）放在 protocol_name，寫入 flow 資料表的 protocol 欄位（見 db/repository.py）。

timeout 不開放調整
------------------
idle_timeout / active_timeout 決定 flow 怎麼切，會直接改變 duration、packets 等特徵，
必須和訓練資料相同，所以固定使用 NFSTREAM_PARAMS 的值（idle 30 秒、active 60 秒）。
代價是 flow 要閒置 30 秒或持續 60 秒才會送出分析，偵測會有對應的延遲。

為什麼即時擷取要開子行程
------------------------
NFStreamer 會另外 fork 出 meter 行程抓封包，且只在迭代中收到 KeyboardInterrupt 時才會
終止它們；直接 break 出迴圈會讓 meter 行程殘留、在背景持續擷取（已實測：殘留 7 個）。
因此擷取放在獨立子行程，停止時送 SIGINT，讓 NFStreamer 走自己的清理流程。
"""

import asyncio
import datetime
import multiprocessing as mp
import os
import queue as queue_mod
import signal
import threading

from nfstream import NFStreamer

from stream.flow_features import FEATURES, NFSTREAM_PARAMS, flow_features

# 對應 flow 資料表的欄位
META_COLUMNS = [
    "source_ip", "destination_ip", "source_port", "destination_port", "protocol_name",
    "start_time", "end_time", "duration_ms", "packet_count", "byte_count",
]

IDLE_TIMEOUT = NFSTREAM_PARAMS["idle_timeout"]
ACTIVE_TIMEOUT = NFSTREAM_PARAMS["active_timeout"]

# 即時擷取時每個封包最多抓幾個 byte。nfstream 預設 1536，超過就會截斷；
# 截斷會讓部分封包解析不出完整標頭，改變 flow 和特徵（已用截短的 pcap 實測）。
# 離線 pcap 的長度由檔案本身決定，不受這個值影響。
LIVE_SNAPSHOT_LENGTH = 65535

_PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


# --- 特徵 -----------------------------------------------------

def flow_metadata(flow):
    """flow 的識別資訊，對應 flow 資料表（protocol_name 寫入 protocol 欄位）。"""
    return {
        "source_ip": flow.src_ip,
        "destination_ip": flow.dst_ip,
        "source_port": flow.src_port,
        "destination_port": flow.dst_port,
        "protocol_name": _PROTO_NAME.get(flow.protocol, str(flow.protocol)),
        "start_time": datetime.datetime.fromtimestamp(flow.bidirectional_first_seen_ms / 1000.0),
        "end_time": datetime.datetime.fromtimestamp(flow.bidirectional_last_seen_ms / 1000.0),
        "duration_ms": int(flow.bidirectional_duration_ms),
        "packet_count": int(flow.bidirectional_packets),
        "byte_count": int(flow.bidirectional_bytes),
    }


def flow_to_record(flow):
    """metadata + 模型特徵合成一筆 record。"""
    return {**flow_metadata(flow), **flow_features(flow)}


# --- 離線擷取 -------------------------------------------------

def iter_flows(source, bpf_filter=None, limit=None):
    """
    對 source（網卡名稱或 pcap 路徑）擷取，逐條 yield record。

    要提前結束請用 limit，不要在呼叫端 break：break 會讓 NFStreamer 的 meter 行程殘留。
    """
    streamer = NFStreamer(
        source=source,
        bpf_filter=bpf_filter or None,
        snapshot_length=LIVE_SNAPSHOT_LENGTH,
        max_nflows=limit or 0,
        **NFSTREAM_PARAMS,
    )
    for flow in streamer:
        yield flow_to_record(flow)


def extract_pcap(path, bpf_filter=None, limit=None):
    """讀完整個 pcap，回傳 DataFrame（欄位 = metadata + FEATURES）。"""
    import pandas as pd

    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return pd.DataFrame(list(iter_flows(path, bpf_filter, limit)))


# --- 即時擷取 -------------------------------------------------

def _capture_worker(source, bpf_filter, out_q):
    """子行程主體：擷取 flow 並送回主行程。"""
    # SIGINT → KeyboardInterrupt，讓 NFStreamer 自行終止 meter 行程。
    # 不要攔 SIGTERM：NFStreamer 用 SIGTERM 終止 meter，meter 是從這裡 fork 的，會繼承 handler。
    signal.signal(signal.SIGINT, signal.default_int_handler)

    try:
        for record in iter_flows(source, bpf_filter):
            out_q.put(("flow", record))
    except KeyboardInterrupt:
        pass
    except Exception as e:   # 網卡不存在、權限不足、BPF 語法錯誤等
        out_q.put(("error", f"{type(e).__name__}: {e}"))
    finally:
        out_q.put(("done", None))


class _CaptureSession:
    def __init__(self, source, bpf_filter, loop, queue):
        self.source = source
        self.bpf_filter = bpf_filter
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
            args=(source, bpf_filter, self.out_q),
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
            "idle_timeout": IDLE_TIMEOUT,
            "active_timeout": ACTIVE_TIMEOUT,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "stopped_at": self.stopped_at.isoformat(timespec="seconds") if self.stopped_at else None,
            "flow_count": self.flow_count,
            "error": self.error,
        }


_session = None
_session_lock = threading.Lock()


def start_capture(loop, queue, source=None, bpf_filter=None):
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

        session = _CaptureSession(source, bpf_filter or None, loop, queue)
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
        return {"running": False, "source": None, "bpf_filter": None,
                "idle_timeout": IDLE_TIMEOUT, "active_timeout": ACTIVE_TIMEOUT,
                "started_at": None, "stopped_at": None, "flow_count": 0, "error": None}
    return session.status()


# --- 相容舊介面（core/pipeline.py 使用）-----------------------

def Start(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
    return start_capture(loop, queue)


def Stop():
    return stop_capture()
