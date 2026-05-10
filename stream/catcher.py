import asyncio
import threading
import pandas as pd
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

mode = "replay"  # "replay" 或 "pcap"
# mode = "pcap"

def Start(loop: asyncio.AbstractEventLoop, queue: asyncio.Queue): #外部程式呼叫，開始捕獲封包的流程
    threads = threading.Thread(target=_capture_loop, args=(loop, queue), daemon=True)
    threads.start()

def _replay_loop(loop, queue): #重放封包的迴圈
    df = pd.read_csv("/mnt/d/DATASET/CSV/DDoS-HTTP_Flood/DDoS-HTTP_Flood-.pcap.csv")
    for _, row in df.iterrows():
        record = row.to_dict()  #將資料庫中的資料轉換成可儲存的特徵資料
        asyncio.run_coroutine_threadsafe(queue.put(record), loop)  #將特徵資料放入佇列中，等待後續處理
        # 只讀取一筆資料進行測試
        if _ == 0:
            break

def _capture_loop(loop, queue): #擷取風包的迴圈
    sniff(
        iface="utun4",
        prn=lambda packet: _on_package(packet, queue, loop),
        store=False
    )

def _on_package(packet, queue, loop):   #當擷取到封包時呼叫
    record = _extract_features(packet)  #將擷取到的封包轉換成可儲存的特徵資料
    if record:
        asyncio.run_coroutine_threadsafe(queue.put(record), loop)  #將特徵資料放入佇列中，等待後續處理

def _extract_features(packet) -> dict | None:  #將擷取到的封包轉換成可儲存的特徵資料
    if not packet.haslayer(IP):
        return None
    

    ip = packet[IP]
    protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"

    return {
        "time": datetime.now().isoformat(),
        "source_ip": ip.src,
        "destination_ip": ip.dst,
        "protocol": protocol,
        "size": len(packet),
        "raw_features": packet.summary()  # 可以根據需要提取更多特徵
    }


