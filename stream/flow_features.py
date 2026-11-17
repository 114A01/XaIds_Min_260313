"""
離線萃取（stream/pcap_feature_extractor.py）與即時擷取（stream/catcher.py）共用的
nfstream 參數和特徵定義。

模型是用這組參數和特徵訓練的，兩邊必須完全一致：
  * 改 NFSTREAM_PARAMS → 重跑 extract、export，並重新訓練模型
  * 改 FEATURES        → 重跑 export，並重新訓練模型
config.py 載入模型時，會檢查模型 bundle 記錄的參數和特徵是否與這裡相同。
各特徵的計算方式見 document/nfstream_features.md。
"""

NFSTREAM_PARAMS = dict(
    idle_timeout=30,            # 秒，flow 閒置多久視為結束
    active_timeout=60,          # 秒，flow 持續多久就強制切出一條
    accounting_mode=1,          # IP 層，避開鏈路層差異（nfstream 預設為 0）
    statistical_analysis=True,  # 沒開就沒有 ps / piat / flags 欄位
    n_dissections=0,
    splt_analysis=0,
    decode_tunnels=True,        # 同預設值，明確寫出以便離線和線上一致
)

FEATURES = [
    # 原本的 12 個
    "protocol",
    "bidirectional_duration_ms",
    "bidirectional_mean_piat_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "dst2src_packets",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_syn_packets",
    "bidirectional_ack_packets",
    "bidirectional_rst_packets",
    # 7 類模型新增的 10 個（分方向的封包統計，見 MODEL_CARD_7class.md）
    "src2dst_stddev_ps",
    "bidirectional_min_ps",
    "dst2src_stddev_ps",
    "src2dst_min_ps",
    "bidirectional_min_piat_ms",
    "src2dst_ack_packets",
    "src2dst_psh_packets",
    "bidirectional_max_ps",
    "src2dst_max_ps",
    "src2dst_mean_ps",
]


def flow_features(flow):
    """從 nfstream flow 取出 FEATURES，順序與訓練資料相同。"""
    return {name: getattr(flow, name) for name in FEATURES}
