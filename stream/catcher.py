import asyncio
import math 
import threading

from nfstream import NFStreamer, NFPlugin

from config import CAPTURE_IFACE, CAPTURE_FILTER


_active_queue: asyncio.Queue | None = None
_active_loop: asyncio.AbstractEventLoop | None = None
_capture_started = False

_port_mapping = {
    80:  'http',
    443: 'https',
    53:  'dns',
    22:  'ssh',
    23:  'telnet',
    25:  'smtp',
    194: 'irc',
    67:  'is_dhcp',
    68:  'is_dhcp',
}

def _detect_app(packet, flow):
    for port in (packet.src_port, packet.dst_port):
        attr = _port_mapping.get(port)
        if attr:
            setattr(flow.udps, attr, True)

class _CustomStats(NFPlugin):
    
    def on_init(self, packet, flow):
        # 累積 header 長度（ip_size 含 IP header，transport_size 只含 payload）
        flow.udps.header_length = packet.ip_size - packet.transport_size
        # 累積 index × size，用來計算 Covariance
        flow.udps.sum_is = 1 * packet.raw_size   # 第一個封包 index=1
        # 應用層 protocol 旗標
        flow.udps.http = 0;  flow.udps.https = 0;  flow.udps.dns = 0
        flow.udps.telnet = 0; flow.udps.smtp = 0; flow.udps.ssh = 0
        flow.udps.irc = 0;   flow.udps.is_dhcp = 0
        _detect_app(packet, flow)

    def on_update(self, packet, flow):
        flow.udps.header_length += packet.ip_size - packet.transport_size
        # on_update 呼叫時 bidirectional_packets 已含本封包，即當前 index
        flow.udps.sum_is += flow.bidirectional_packets * packet.raw_size
        _detect_app(packet, flow)


def _to_features(flow) -> dict | None:
    n = flow.bidirectional_packets
    if n == 0:
        return None

    dur   = flow.bidirectional_duration_ms / 1000.0   # 轉成秒
    rate  = n / max(dur, 1e-9)
    srate = flow.src2dst_packets / max(dur, 1e-9)
    drate = flow.dst2src_packets / max(dur, 1e-9)

    # IAT：NFStream 給 ms，模型訓練資料用 µs
    iat = (flow.bidirectional_mean_piat_ms or 0.0) * 1000.0

    avg_s     = float(flow.bidirectional_mean_ps   or 0)
    std_s     = float(flow.bidirectional_stddev_ps or 0)
    variance  = std_s ** 2

    # Magnitue = sqrt(fwd_mean^2 + bwd_mean^2)
    fwd_mean = float(flow.src2dst_mean_ps   or 0)
    bwd_mean = float(flow.dst2src_mean_ps   or 0)
    magnitue = math.sqrt(fwd_mean ** 2 + bwd_mean ** 2)

    # Radius = sqrt(fwd_var + bwd_var)
    fwd_std  = float(flow.src2dst_stddev_ps or 0)
    bwd_std  = float(flow.dst2src_stddev_ps or 0)
    radius   = math.sqrt(fwd_std ** 2 + bwd_std ** 2)

    # Covariance(packet_index, packet_size)
    # = E[I*S] - E[I]*E[S]
    mean_i   = (n + 1) / 2.0
    mean_is  = flow.udps.sum_is / n
    covariance = mean_is - mean_i * avg_s

    weight = float(flow.bidirectional_bytes) / n

    proto   = flow.protocol
    is_tcp  = 1 if proto == 6  else 0
    is_udp  = 1 if proto == 17 else 0
    is_icmp = 1 if proto == 1  else 0
    is_ipv  = 1 if flow.ip_version in (4, 6) else 0

    return {
        "flow_duration":   dur,
        "Header_Length":   float(flow.udps.header_length),
        "Protocol Type":   float(proto),
        "Duration":        64.0,   # TTL NFStream 無法取得，填入 Linux 預設值
        "Rate":            rate,
        "Srate":           srate,
        "Drate":           drate,
        "fin_flag_number": float(flow.bidirectional_fin_packets),
        "syn_flag_number": float(flow.bidirectional_syn_packets),
        "rst_flag_number": float(flow.bidirectional_rst_packets),
        "psh_flag_number": float(flow.bidirectional_psh_packets),
        "ack_flag_number": float(flow.bidirectional_ack_packets),
        "ece_flag_number": float(flow.bidirectional_ece_packets),
        "cwr_flag_number": float(flow.bidirectional_cwr_packets),
        "ack_count":       float(flow.bidirectional_ack_packets),
        "syn_count":       float(flow.bidirectional_syn_packets),
        "fin_count":       float(flow.bidirectional_fin_packets),
        "urg_count":       float(flow.bidirectional_urg_packets),
        "rst_count":       float(flow.bidirectional_rst_packets),
        "HTTP":            float(flow.udps.http),
        "HTTPS":           float(flow.udps.https),
        "DNS":             float(flow.udps.dns),
        "Telnet":          float(flow.udps.telnet),
        "SMTP":            float(flow.udps.smtp),
        "SSH":             float(flow.udps.ssh),
        "IRC":             float(flow.udps.irc),
        "TCP":             float(is_tcp),
        "UDP":             float(is_udp),
        "DHCP":            float(flow.udps.is_dhcp),
        "ARP":             0.0,   # ARP 是 L2，NFStream 擷取不到
        "ICMP":            float(is_icmp),
        "IPv":             float(is_ipv),
        "LLC":             0.0,   # LLC 是 L2，NFStream 擷取不到
        "Tot sum":         float(flow.bidirectional_bytes),
        "Min":             float(flow.bidirectional_min_ps or 0),
        "Max":             float(flow.bidirectional_max_ps or 0),
        "AVG":             avg_s,
        "Std":             std_s,
        "Tot size":        float(flow.bidirectional_bytes),
        "IAT":             iat,
        "Number":          float(n),
        "Magnitue":        magnitue,   # 保持訓練資料的 typo
        "Radius":          radius,
        "Covariance":      covariance,
        "Variance":        variance,
        "Weight":          weight,
    }

def Stop():
    global _active_queue, _active_loop
    _active_loop = None
    _active_queue = None

def _capture_loop():
    streamer = NFStreamer(
        source=CAPTURE_IFACE,
        statistical_analysis= True,
        udps=_CustomStats(),
        bpf_filter=CAPTURE_FILTER
    )
    for flow in streamer:
        q = _active_queue
        lp = _active_loop
        if q is not None and lp is not None:
            features = _to_features(flow)
            if features:
                asyncio.run_coroutine_threadsafe(q.put(features), lp)

def Start(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue):
    global _active_queue, _active_loop, _capture_started
    _active_loop = loop
    _active_queue = queue

    if not _capture_started:
        _capture_started = True
        threading.Thread(target=_capture_loop, daemon=True).start()