#!/usr/bin/env python3
"""
API 冒煙測試：對一個已啟動的 XaIDS 伺服器實際跑幾次短的測試，檢查結果後把自己建立的測試刪掉。

    # 另開一個驗證用的伺服器（不要用正在 demo 的那一個）
    uvicorn api.main:app --port 8099
    python tools/smoke_test.py --base http://localhost:8099

只用標準函式庫。測試會寫進同一個資料庫，結束時刪除；加 --keep 可以保留（例如接著跑 tools/audit.py）。
需要 data/pcap/syn-flood_1110.pcap 與 CSV 目錄（預設 data/csv/）裡的 ciciot2023_cleaned_Benign.csv。
"""

import argparse
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

PREFIX = "smoke "          # 這支程式建立的測試名稱都用這個開頭，方便在歷史頁辨認


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="http://localhost:8099")
    ap.add_argument("--keep", action="store_true", help="結束時不刪除建立的測試")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    failures = []
    created = []           # 這次建立的 run_id；結束時只刪這些，不依名稱刪，避免誤刪別人的測試

    def call(path, method="GET", body=None, raw=False):
        req = urllib.request.Request(
            base + path, method=method,
            data=(json.dumps(body).encode() if body is not None else None),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                data = r.read()
                return r.status, (data if raw else json.loads(data)), dict(r.headers)
        except urllib.error.HTTPError as e:
            data = e.read()
            try:
                return e.code, json.loads(data), dict(e.headers)
            except ValueError:
                return e.code, data, dict(e.headers)

    def check(name, ok, detail=""):
        print(f"  [{'OK' if ok else 'FAIL'}] {name}{'　' + str(detail) if detail else ''}", flush=True)
        if not ok:
            failures.append(name)

    def wait_done():
        while call("/run/status")[1]["running"]:
            time.sleep(0.5)

    def run(body):
        t = time.time()
        code, r, _ = call("/run/start", "POST", body)
        if code != 200:
            check(f"啟動 {body['name']}", False, f"{code} {r}")
            return None, 0.0
        created.append(r["run_id"])
        wait_done()
        s = call("/run/status")[1]
        secs = time.time() - t
        print(f"  {body['name']}: {s['processed']} / {s['total']} 筆，{secs:.1f} 秒"
              f"（每筆 {secs / max(s['processed'], 1):.2f} 秒），error={s['error']}", flush=True)
        return r["run_id"], secs

    cfg = call("/api/config")[1]
    print(f"模型 {cfg['model_name']}，{len(cfg['class_names'])} 類，{len(cfg['feature_names'])} 個特徵，"
          f"SHAP 參考分布 {cfg['shap_reference']}")
    if call("/run/status")[1]["running"]:
        raise SystemExit("伺服器上已有測試在執行，請換一個伺服器或先停止。")

    try:
        print("1. 參數檢查")
        for bad in (0, cfg["max_rows_limit"] + 1):
            code = call("/run/start", "POST", {"source_type": "pcap", "source": "syn-flood_1110.pcap",
                                               "name": PREFIX + "bad", "max_rows": bad})[0]
            check(f"max_rows={bad} 被拒絕", code == 422, code)

        print("2. pcap 重播（中文名稱、LIME 重複 3 次）")
        name = PREFIX + "pcap 中文名稱"
        rid, _ = run({"source_type": "pcap", "source": "syn-flood_1110.pcap", "name": name,
                      "expected_label": "DoS", "max_rows": 100, "lime_repeats": 3})
        if rid:
            flows = call(f"/api/runs/{rid}/flows?limit=2000")[1]["items"]
            check("100 條 flow 都有三個 k 的一致性", len(flows) == 100 and all(len(f["consistency"]) == len(cfg["ks"]) for f in flows))
            check("都判為 DoS", all(f["predicted_label"] == "DoS" for f in flows),
                  {f["predicted_label"] for f in flows})
            events = call("/run/results")[1]
            check("事件帶有伺服器時間", all("time" in e for e in events if e["zone"] != "DONE"))
            check("測試記錄了 shap_reference",
                  call(f"/api/runs/{rid}")[1]["params"].get("shap_reference") == cfg["shap_reference"])
            code, body, headers = call(f"/api/runs/{rid}/export.csv", raw=True)
            disp = headers.get("content-disposition", "")
            check("中文名稱可以匯出 CSV", code == 200 and urllib.parse.quote("中文名稱") in disp, f"{code} {disp}")
            check("匯出的列數正確", body.decode().count("\n") == 101)
            exp = call(f"/explain/{flows[0]['id']}/shap")[1]
            check("SHAP 存了全部特徵", len(exp["shap_value"]) == len(cfg["feature_names"]), f"base={exp['base_value']}")
            recent = call("/api/packetRecord?limit=5")[1]
            check("流量紀錄最上面是剛跑的測試", all(f["run_id"] == rid for f in recent))

        print("3. CSV 重播（LIME 重複 2 次）")
        rid2, _ = run({"source_type": "csv", "source": "ciciot2023_cleaned_Benign.csv", "name": PREFIX + "csv benign",
                       "max_rows": 60, "lime_repeats": 2})
        if rid2:
            s = call(f"/api/runs/{rid2}")[1]
            check("60 筆、有標籤、有 LIME 穩定度",
                  s["flow_count"] == 60 and s["n_labeled"] == 60 and s["mean_lime_stability"] is not None,
                  f"正確率 {s['accuracy']}")

        print("4. 同時送出兩個啟動請求，只能成功一個")
        codes = []

        def start(i):
            code, r, _ = call("/run/start", "POST", {"source_type": "csv", "source": "ciciot2023_cleaned_Benign.csv",
                                                     "name": f"{PREFIX}race {i}", "max_rows": 5})
            codes.append(code)
            if code == 200:
                created.append(r["run_id"])
        threads = [threading.Thread(target=start, args=(i,)) for i in range(2)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        wait_done()
        check("一個 200、一個被拒絕", sorted(codes)[0] == 200 and sorted(codes)[1] in (400, 409), codes)

        print("5. 統計 API")
        charts = call(f"/api/stats/charts?k=5&run_ids={rid},{rid2}")[1]
        check("圖表資料涵蓋兩次測試", charts["n_total"] == 160, charts["n_total"])
        overall = call("/api/stats/overall?k=5")[1]
        check("完整統計可以計算", overall["n_total"] >= 160, f"n={overall['n_total']} warnings={overall['warnings']}")
    finally:
        if not args.keep:
            wait_done()
            for rid in created:
                call(f"/api/runs/{rid}", "DELETE")
            print(f"已刪除這次建立的 {len(created)} 次測試")
        elif created:
            print("保留了這次建立的測試，run_id：" + "、".join(c[:8] for c in created))

    print("\n結果：" + ("全部通過" if not failures else f"{len(failures)} 項失敗：{failures}"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
