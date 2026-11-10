#!/usr/bin/env python3
"""
CICIoT2023 PCAP → nfstream flow 特徵 → 訓練用 CSV。

分成兩個子命令，把耗時的萃取和輸出分開：

  extract  每類 PCAP → output/flows/<類別>.parquet（保留 nfstream 全部欄位）
  export   flow 檔 → output/dataset/<類別>.csv（FEATURES + label）

CSV 不做 train / test 切分、去重或抽樣，這些在訓練模型時處理。
每個 CSV 內的列依 flow 開始時間由早到晚排序，可直接依列的順序做時間切分。

用法（需要 MLEnv：nfstream、pyarrow）：
  python stream/pcap_feature_extractor.py extract --classes SqlInjection
  python stream/pcap_feature_extractor.py extract --classes DoS-UDP_Flood --max-files 1
  python stream/pcap_feature_extractor.py extract
  python stream/pcap_feature_extractor.py export

NFSTREAM_PARAMS 和 FEATURES 定義在 stream/flow_features.py，與即時擷取共用。
只改 FEATURES 時重跑 export 即可；改 NFSTREAM_PARAMS 則要重跑 extract。
"""

import argparse
import json
import multiprocessing as mp
import os
import shutil
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# 和即時擷取（stream/catcher.py）共用同一份參數和特徵清單
from stream.flow_features import FEATURES, NFSTREAM_PARAMS  # noqa: E402

# 資料夾名稱和標籤不同的類別；其餘類別的標籤就是資料夾名稱。
FOLDER_LABELS = {"Benign_Final": "Benign"}

TIME_COLUMN = "bidirectional_first_seen_ms"
BATCH_SIZE = 500_000
DEFAULT_PCAP_ROOT = Path("/mnt/d/bominwang/ciciot2023_pcap/PCAP")
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "output"

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


# --- 找出 PCAP ------------------------------------------------

def first_packet_time(path):
    """回傳第一個封包的時間（秒）；沒有封包時回傳 None。只支援傳統 pcap 格式。"""
    with open(path, "rb") as f:
        header = f.read(24)
        if header[:4] not in _PCAP_MAGIC:
            raise ValueError(f"不是傳統 pcap 格式: {path}")
        endian, unit = _PCAP_MAGIC[header[:4]]
        record = f.read(8)
    if len(record) < 8:
        return None
    sec, frac = struct.unpack(endian + "II", record)
    return sec + frac * unit


def discover_classes(pcap_root, selected=None):
    """回傳 {標籤: 資料夾}。selected 可以用標籤或資料夾名稱指定。"""
    folders = {}
    for folder in sorted(Path(pcap_root).iterdir()):
        if folder.is_dir() and any(folder.glob("*.pcap")):
            folders[FOLDER_LABELS.get(folder.name, folder.name)] = folder
    if not selected:
        return folders

    chosen = {}
    for name in selected:
        for label, folder in folders.items():
            if name in (label, folder.name):
                chosen[label] = folder
                break
        else:
            raise SystemExit(f"找不到類別 {name}，可用: {', '.join(folders)}")
    return chosen


def ordered_pcaps(folder):
    """依第一個封包的時間排序。字典序會變成 Flood1, Flood10, Flood11…，不能用。"""
    timed = []
    for path in folder.glob("*.pcap"):
        start = first_packet_time(path)
        if start is None:
            print(f"  警告：略過沒有封包的檔案 {path.name}", flush=True)
        else:
            timed.append((start, path))
    return [path for _, path in sorted(timed)]


def check_overlap(files):
    """用 capinfos 檢查相鄰檔案的時間是否重疊。要掃完整個檔案，所以預設不跑。"""
    if not shutil.which("capinfos"):
        raise SystemExit("--check-overlap 需要 capinfos（Wireshark 工具）")
    spans = []
    for path in files:
        out = subprocess.run(
            ["capinfos", "-T", "-m", "-r", "-a", "-e", "-S", str(path)],
            capture_output=True, text=True, check=True).stdout
        start, end = out.strip().rsplit(",", 2)[-2:]
        spans.append((float(start), float(end), path.name))
    for prev, cur in zip(spans, spans[1:]):
        if cur[0] < prev[1]:
            print(f"  警告：{prev[2]} 和 {cur[2]} 的時間重疊 "
                  f"{prev[1] - cur[0]:.3f} 秒", flush=True)


# --- extract --------------------------------------------------

def nfstream_version():
    from importlib.metadata import version
    return version("nfstream")


def _arrow_schema(flow, label_type):
    """依第一條 flow 的 Python 型別決定欄位型別，後續每批都用同一份 schema。"""
    import pyarrow as pa
    types = {int: pa.int64(), float: pa.float64(), str: pa.string()}
    fields = [pa.field(name, types[type(value)])
              for name, value in zip(flow.keys(), flow.values())]
    return pa.schema(fields + [pa.field("label", label_type)])


def _write_batch(writer, rows, label):
    import pyarrow as pa
    columns = list(zip(*rows))
    arrays = [pa.array(col, type=field.type)
              for col, field in zip(columns, writer.schema)]
    arrays.append(pa.array([label] * len(rows), type=pa.string()))
    writer.write_table(pa.Table.from_arrays(arrays, schema=writer.schema))


def _extract_worker(label, files, flows_dir, n_meters, partial):
    """處理一個類別。必須在獨立行程執行，原因見 cmd_extract。"""
    import pyarrow as pa
    import pyarrow.parquet as pq
    from nfstream import NFStreamer

    target = flows_dir / f"{label}.parquet"
    tmp = flows_dir / f"{label}.parquet.tmp"
    started = time.time()
    writer = None
    rows = []
    n_flows = n_packets = 0
    packets_index = None

    streamer = NFStreamer(source=[str(p) for p in files], n_meters=n_meters, **NFSTREAM_PARAMS)
    print(f"[{label}] 開始：{len(files)} 個檔案，{streamer.n_meters} 個 meter", flush=True)
    try:
        for flow in streamer:
            if writer is None:
                writer = pq.ParquetWriter(tmp, _arrow_schema(flow, pa.string()),
                                          compression="zstd")
                packets_index = list(flow.keys()).index("bidirectional_packets")
            values = flow.values()
            rows.append(values)
            n_flows += 1
            n_packets += values[packets_index]
            if len(rows) >= BATCH_SIZE:
                _write_batch(writer, rows, label)
                rows = []
                elapsed = time.time() - started
                print(f"[{label}] {n_flows:,} flows，{n_packets:,} packets，"
                      f"{elapsed:,.0f} 秒", flush=True)
        if writer is None:
            raise RuntimeError(f"{label} 沒有產生任何 flow")
        if rows:
            _write_batch(writer, rows, label)
    finally:
        if writer is not None:
            writer.close()

    os.replace(tmp, target)
    manifest = {
        "label": label,
        "nfstream_version": nfstream_version(),
        "params": NFSTREAM_PARAMS,
        "n_meters": streamer.n_meters,
        "sources": [p.name for p in files],
        "source_bytes": sum(p.stat().st_size for p in files),
        "partial": partial,
        "flows": n_flows,
        "packets": n_packets,
        "elapsed_seconds": round(time.time() - started, 1),
        "finished_at": datetime.now(timezone.utc).isoformat(),
    }
    _manifest_path(flows_dir, label).write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"[{label}] 完成：{n_flows:,} flows，{n_packets:,} packets，"
          f"{manifest['elapsed_seconds']:,} 秒", flush=True)


def _manifest_path(flows_dir, label):
    return flows_dir / f"{label}.manifest.json"


def _already_done(flows_dir, label, files):
    """只有來源檔、參數和 nfstream 版本都相同，才算完成，避免試跑結果被當成全量。"""
    manifest_path = _manifest_path(flows_dir, label)
    if not (flows_dir / f"{label}.parquet").exists() or not manifest_path.exists():
        return False
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    return (manifest["sources"] == [p.name for p in files]
            and manifest["params"] == NFSTREAM_PARAMS
            and manifest["nfstream_version"] == nfstream_version())


def cmd_extract(args):
    flows_dir = args.output / "flows"
    flows_dir.mkdir(parents=True, exist_ok=True)

    # nfstream 迭代時會把主行程的 CPU affinity 綁到 2 顆（streamer.py 的 set_affinity），
    # 同一行程下一次建立 NFStreamer 就只剩 1 個 meter。所以每類各開一個行程。
    ctx = mp.get_context("spawn")
    failed = []
    for label, folder in discover_classes(args.pcap_root, args.classes).items():
        files = ordered_pcaps(folder)
        partial = args.max_files is not None and args.max_files < len(files)
        if args.max_files is not None:
            files = files[:args.max_files]
        if args.check_overlap:
            check_overlap(files)
        if not args.force and _already_done(flows_dir, label, files):
            print(f"[{label}] 已完成，略過（--force 可強制重算）", flush=True)
            continue

        worker = ctx.Process(target=_extract_worker,
                             args=(label, files, flows_dir, args.n_meters, partial))
        worker.start()
        worker.join()
        if worker.exitcode != 0:
            print(f"[{label}] 失敗，exit code {worker.exitcode}", file=sys.stderr, flush=True)
            failed.append(label)

    if failed:
        print(f"失敗的類別: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


# --- export ---------------------------------------------------

def _load_manifests(flows_dir, allow_partial):
    manifests = {}
    for path in sorted(flows_dir.glob("*.manifest.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if not (flows_dir / f"{manifest['label']}.parquet").exists():
            raise SystemExit(f"{path.name} 沒有對應的 parquet 檔")
        manifests[manifest["label"]] = manifest
    if not manifests:
        raise SystemExit(f"{flows_dir} 沒有 flow 檔，請先跑 extract")

    partial = [label for label, m in manifests.items() if m["partial"]]
    if partial and not allow_partial:
        raise SystemExit(f"這些類別只萃取了部分檔案: {', '.join(partial)}"
                         "（試跑時可加 --allow-partial）")
    versions = {(m["nfstream_version"], json.dumps(m["params"], sort_keys=True))
                for m in manifests.values()}
    if len(versions) > 1:
        raise SystemExit(f"各類別的 nfstream 版本或參數不一致，請重新萃取: {versions}")
    return manifests


def _export_class(label, flows_path, csv_path):
    """flow 檔 → FEATURES + label 的 CSV。列依 flow 開始時間排序，不做切分、去重或抽樣。"""
    import pyarrow as pa
    import pyarrow.compute as pc
    import pyarrow.csv as pacsv
    import pyarrow.parquet as pq

    table = pq.read_table(flows_path, columns=FEATURES + [TIME_COLUMN])
    # meter 交錯輸出，flow 檔的順序不固定；依時間排序後，每次輸出都相同，
    # 下一步也能直接依列的順序做時間切分。
    table = table.sort_by([(TIME_COLUMN, "ascending")] +
                          [(name, "ascending") for name in FEATURES])
    first_ms = table[TIME_COLUMN][0].as_py()
    last_ms = table[TIME_COLUMN][-1].as_py()
    table = table.select(FEATURES)
    table = table.append_column("label", pa.array([label] * len(table), type=pa.string()))

    missing = sum(table[name].null_count for name in FEATURES)
    missing += sum(pc.sum(pc.is_nan(table[name])).as_py() or 0
                   for name in FEATURES if pa.types.is_floating(table[name].type))

    tmp = csv_path.with_name(csv_path.name + ".tmp")
    pacsv.write_csv(table, tmp)
    os.replace(tmp, csv_path)
    return {
        "rows": len(table),
        "missing_values": int(missing),
        "first_seen_ms": first_ms,
        "last_seen_ms": last_ms,
        "csv_bytes": csv_path.stat().st_size,
    }


def cmd_export(args):
    flows_dir = args.output / "flows"
    dataset_dir = args.output / "dataset"
    manifests = _load_manifests(flows_dir, args.allow_partial)
    dataset_dir.mkdir(parents=True, exist_ok=True)

    per_class = {}
    for label in manifests:
        print(f"[{label}] 輸出中…", flush=True)
        stats = _export_class(label, flows_dir / f"{label}.parquet",
                              dataset_dir / f"{label}.csv")
        per_class[label] = stats
        print(f"[{label}] {stats['rows']:,} 列，缺失值 {stats['missing_values']}", flush=True)

    first = next(iter(manifests.values()))
    summary = {
        "nfstream_version": first["nfstream_version"],
        "params": first["params"],
        "features": FEATURES,
        "row_order": f"每個 CSV 內依 {TIME_COLUMN} 由早到晚排序",
        "partial_classes": [label for label, m in manifests.items() if m["partial"]],
        "classes": per_class,
    }
    (dataset_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"已輸出到 {dataset_dir}", flush=True)
    return 0


# --- CLI ------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="CICIoT2023 PCAP → nfstream 特徵 → 訓練資料")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help=f"輸出資料夾（預設 {DEFAULT_OUTPUT}）")
    sub = parser.add_subparsers(dest="command", required=True)

    extract = sub.add_parser("extract", help="PCAP → 每類一份完整 flow 檔")
    extract.add_argument("--pcap-root", type=Path, default=DEFAULT_PCAP_ROOT)
    extract.add_argument("--classes", nargs="+", help="只處理指定類別（標籤或資料夾名稱）")
    extract.add_argument("--max-files", type=int, help="每類只取最早的 N 個檔（試跑用）")
    extract.add_argument("--n-meters", type=int, default=0, help="0 表示由 nfstream 決定")
    extract.add_argument("--check-overlap", action="store_true",
                         help="用 capinfos 檢查檔案時間是否重疊（要掃完整個檔案）")
    extract.add_argument("--force", action="store_true", help="已完成的類別也重算")
    extract.set_defaults(func=cmd_extract)

    export = sub.add_parser("export", help="flow 檔 → 每類一份訓練用 CSV")
    export.add_argument("--allow-partial", action="store_true",
                        help="允許使用 --max-files 試跑產生的 flow 檔")
    export.set_defaults(func=cmd_export)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())


