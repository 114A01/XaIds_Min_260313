#!/usr/bin/env python3
"""
擷取測試工具：用 stream/catcher.py 的函數擷取流量，輸出 CSV 並與資料集比對。

特徵計算方式與欄位對照說明見 stream/catcher.py。

用法：
  python stream/nfstream_flow_capture.py -s some.pcap --verify 'data/*.csv'
  sudo python stream/nfstream_flow_capture.py -s eth0 -f 'port 80' -n 100 -o out.csv
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from stream.catcher import (CICIOT2023_COLUMNS, DEFAULT_ACTIVE_TIMEOUT,  # noqa: E402
                            DEFAULT_IDLE_TIMEOUT, META_COLUMNS, iter_flows)


def main():
    ap = argparse.ArgumentParser(
        description="用 NFStream 擷取流量並組成 CICIoT2023 的 46 個特徵")
    ap.add_argument("-s", "--source", default="eth0",
                    help="網卡名稱或 pcap 檔路徑（預設 eth0；用 pcap 可免 root 離線測試）")
    ap.add_argument("-f", "--bpf", default=None, help="BPF 過濾條件，例如 'tcp port 80'")
    ap.add_argument("-o", "--out", default=None, help="輸出 CSV 路徑")
    ap.add_argument("-n", "--limit", type=int, default=None, help="擷取到幾條 flow 後停止")
    ap.add_argument("--idle-timeout", type=int, default=DEFAULT_IDLE_TIMEOUT)
    ap.add_argument("--active-timeout", type=int, default=DEFAULT_ACTIVE_TIMEOUT)
    ap.add_argument("--verify", metavar="GLOB", default=None,
                    help="與資料集比對欄位與數值範圍，例如 'data/*.csv'")
    args = ap.parse_args()

    print(f"來源: {args.source}    BPF: {args.bpf or '(無)'}")
    print("=" * 96)
    print(f"{'源IP':<16}{'源Port':<8}{'目標IP':<16}{'目標Port':<9}"
          f"{'協議':<7}{'Packets':<9}{'Bytes':<9}{'TTL':<7}{'HdrLen'}")
    print("=" * 96)

    rows = []
    try:
        for rec in iter_flows(args.source, args.bpf, args.idle_timeout,
                              args.active_timeout, args.limit):
            rows.append(rec)
            print(f"{rec['source_ip']:<16}{rec['source_port']:<8}"
                  f"{rec['destination_ip']:<16}{rec['destination_port']:<9}"
                  f"{rec['protocol']:<7}{rec['packet_count']:<9}{rec['byte_count']:<9}"
                  f"{rec['Duration']:<7.1f}{rec['Header_Length']:.1f}")
    except KeyboardInterrupt:
        print("\n(收到 Ctrl+C，停止擷取)")
    except (PermissionError, ValueError) as e:
        print(f"\n錯誤: {e}\n擷取網卡需要 root 或 CAP_NET_RAW；"
              f"可改用 sudo，或用 --source 指定 pcap 檔離線測試。", file=sys.stderr)
        return 1

    print("=" * 96)
    print(f"擷取完成，共 {len(rows)} 條 flow")

    if not rows:
        return 0

    import pandas as pd
    df = pd.DataFrame(rows, columns=META_COLUMNS + CICIOT2023_COLUMNS)

    if args.out:
        df.to_csv(args.out, index=False)
        print(f"已寫出 {args.out}")

    if args.verify:
        verify_against_dataset(df[CICIOT2023_COLUMNS], args.verify)

    return 0


def verify_against_dataset(df, pattern):
    """比對產出的欄位與資料集：名稱、順序、數值範圍。"""
    import glob
    import pandas as pd

    files = sorted(glob.glob(pattern))
    if not files:
        print(f"找不到資料集檔案: {pattern}", file=sys.stderr)
        return
    ds = pd.concat([pd.read_csv(f) for f in files[:3]])
    ds_cols = [c for c in ds.columns if c != "label"]

    print("\n" + "=" * 96)
    print("欄位比對")
    print("=" * 96)
    missing = [c for c in ds_cols if c not in df.columns]
    extra = [c for c in df.columns if c not in ds_cols]
    order_ok = list(df.columns) == ds_cols
    print(f"資料集欄位數 {len(ds_cols)}、產出欄位數 {len(df.columns)}")
    print(f"缺少: {missing or '無'}")
    print(f"多出: {extra or '無'}")
    print(f"順序一致: {'是' if order_ok else '否'}")

    print("\n" + "=" * 96)
    print(f"{'欄位':<18}{'資料集 min':>13}{'中位數':>13}{'max':>13}"
          f"{'  │':>3}{'擷取 min':>13}{'中位數':>13}{'max':>13}  判定")
    print("=" * 96)
    for c in ds_cols:
        if c not in df.columns:
            continue
        d, m = ds[c], df[c]
        # 判定：擷取值是否落在資料集的值域內
        inside = ((m >= d.min()) & (m <= d.max())).mean()
        mark = "OK" if inside == 1.0 else (f"部分越界 {inside:.0%}" if inside > 0 else "全部越界")
        print(f"{c:<18}{d.min():>13.4g}{d.median():>13.4g}{d.max():>13.4g}"
              f"{'  │':>3}{m.min():>13.4g}{m.median():>13.4g}{m.max():>13.4g}  {mark}")


if __name__ == "__main__":
    sys.exit(main())
