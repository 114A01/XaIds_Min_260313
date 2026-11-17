"""
分析 pipeline：以「一次測試（run）」為單位，把 CSV / pcap / 即時擷取的每一條 flow
依序做 預測 → 解釋（SHAP + LIME）→ 一致性 → 忠實度 → 寫入資料庫 → 推送 SSE 事件。
計算的部分在獨立執行緒（_analysis_pool）跑，事件迴圈只做 DB 與 HTTP，測試中頁面不會卡住。

每一筆 flow 都算解釋，不套信心值門檻（實驗需要正確與錯誤樣本都有分數）。
警報規則不變：非 Benign 且 confidence >= CONFIDENCE_LOW 才寫 alert。

同一時間只能有一個 run。run_state 是目前（或最近一次）run 的記憶體狀態，
results 列表供 /stream 與 /run/results 用，重啟後消失；永久資料都在資料庫。
"""

import asyncio
import concurrent.futures
import datetime
import multiprocessing as mp
import traceback

import pandas as pd

from core.explainer import explain_lime, explain_shap
from core.consistency import compare_multi_k, lime_self_consistency
from core.faithfulness import ablation_drops_multi_k
from core.modelPredict import predict, predict_prob
from core.preprocessor import transform
from stream.catcher import start_capture, stop_capture, get_capture_status, extract_pcap
from db import repository as repo
from config import (class_names, category_map, CONFIDENCE_HIGH, CONFIDENCE_LOW, CONSISTENCY_KS, MODEL_NAME,
                    DEFAULT_LIME_NUM_SAMPLES, DEFAULT_LIME_REPEATS, MAX_ROWS_LIMIT, SHAP_REFERENCE)

# 啟動擷取後等多久確認沒有立即失敗（網卡不存在、BPF 語法錯誤約 0.5 秒內會回報）
CAPTURE_STARTUP_CHECK_SEC = 1.5
PROGRESS_DB_EVERY = 20     # 每處理幾筆就把進度寫回 analysis_run

run_state: dict = {
    "run_id": None,
    "name": None,
    "running": False,
    "source_type": None,   # csv | pcap | live
    "source": None,
    "total": 0,
    "processed": 0,
    "stop_event": None,
    "params": {},
    "expected_label": None,
    "results": [],
    "error": None,
}

_live: dict = {"task": None, "watcher": None, "queue": None}
_starting = False   # start_run 正在建立 run（還沒設 running）時為 True，擋掉同時進來的第二個請求


def _append_result(event):
    run_state["results"].append(event)


def _zone(confidence, label):
    if confidence < CONFIDENCE_LOW:
        return "UNCERTAIN"
    if label == "Benign":
        return "BENIGN"
    return "HIGH_CONF" if confidence >= CONFIDENCE_HIGH else "SUSPICIOUS"


def _analyze(record, params):
    """
    一筆 flow 的全部計算（預測 → SHAP / LIME → 一致性 → 忠實度），純 CPU，沒有 I/O。
    在獨立的執行緒跑（見 process），不然 LIME 一筆要跑一秒以上，事件迴圈會被卡住，
    期間所有 HTTP 請求（包含 /run/start 的回應、/run/status）都沒有回應。
    只開一個 worker：explainer 內部共用 LIME 的 RNG 狀態，不能同時解釋兩筆。
    """
    feature = transform(record)
    row = feature.values[0]
    prediction = int(predict(feature))
    prob = predict_prob(feature)[0]
    confidence = float(prob[prediction])

    shap_pairs, base_value = explain_shap(row, prediction)
    lime_pairs, lime_runs = explain_lime(row, prediction, params["lime_num_samples"], params["lime_repeats"])

    per_k = compare_multi_k(shap_pairs, lime_pairs, CONSISTENCY_KS)
    shap_drop = ablation_drops_multi_k(row, shap_pairs, prediction, CONSISTENCY_KS, confidence)
    lime_drop = ablation_drops_multi_k(row, lime_pairs, prediction, CONSISTENCY_KS, confidence)
    for k in CONSISTENCY_KS:
        per_k[k]["lime_stability"] = lime_self_consistency(lime_runs, k)
        per_k[k]["shap_ablation_drop"] = round(shap_drop[k], 4)
        per_k[k]["lime_ablation_drop"] = round(lime_drop[k], 4)
    return feature, prediction, confidence, shap_pairs, base_value, lime_pairs, per_k


_analysis_pool = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="xaids-analysis")


async def process(record, seq):
    """處理一條 flow。record 是 dict（特徵 + 可選的 metadata / label）。"""
    try:
        run_id = run_state["run_id"]
        params = run_state["params"]

        loop = asyncio.get_running_loop()
        feature, prediction, confidence, shap_pairs, base_value, lime_pairs, per_k = \
            await loop.run_in_executor(_analysis_pool, _analyze, record, params)
        label = class_names[prediction]
        zone = _zone(confidence, label)

        true_label = record.get("label")
        if true_label is None or (isinstance(true_label, float) and pd.isna(true_label)):
            true_label = run_state["expected_label"]
        true_label = str(true_label) if true_label is not None else None
        if true_label is not None and true_label not in class_names:
            true_label = category_map.get(true_label, true_label)   # 子類別 → 模型類別，例如 SqlInjection → Web-based

        async def persist():
            flow_id = await repo.insert_flow(record, feature, run_id, seq, true_label, label,
                                             round(confidence, 4), zone)
            await repo.insert_explanation(flow_id, shap_pairs, base_value, lime_pairs, params["lime_repeats"])
            await repo.insert_consistency_rows(flow_id, per_k)
            alert_id = None
            if zone in ("SUSPICIOUS", "HIGH_CONF"):
                alert_id = await repo.insert_alert(flow_id, label, round(confidence, 4), zone)
            return flow_id, alert_id

        # shield：停止即時擷取時 consumer 會被取消，不能停在四個 INSERT 中間，
        # 否則會留下有 flow 卻沒有解釋與一致性的殘缺資料。
        flow_id, alert_id = await asyncio.shield(persist())

        event = {
            "zone": zone,
            "seq": seq,
            "flow_id": flow_id,
            "alert_id": alert_id,
            "time": datetime.datetime.now().isoformat(timespec="seconds"),   # 伺服器本地時間，與資料庫的時間欄位一致
            "source_ip": record.get("source_ip"),
            "destination_ip": record.get("destination_ip"),
            "attack_type": label,
            "predicted_label": label,
            "true_label": true_label,
            "correct": (true_label == label) if true_label is not None else None,
            "confidence": round(confidence, 4),
            "shap_top3": [{"feature": n, "weight": round(w, 4)} for n, w in shap_pairs[:3]],
            "lime_top3": [{"feature": n, "weight": round(w, 4)} for n, w in lime_pairs[:3]],
            "consistency": {k: {key: (round(v, 4) if isinstance(v, float) else v)
                                for key, v in m.items() if key != "common_feature"}
                            for k, m in per_k.items()},
            "processed": run_state["processed"],
            "total": run_state["total"],
        }
        _append_result(event)
        return event

    except Exception:
        traceback.print_exc()
        return None


# --- run 生命週期 ---------------------------------------------------------

def _reset_state(run_id, name, source_type, source, expected_label, params):
    run_state.update(run_id=run_id, name=name, running=True, source_type=source_type, source=source,
                     total=0, processed=0, stop_event=asyncio.Event(), params=params,
                     expected_label=expected_label, results=[], error=None)


async def start_run(source_type, source, name=None, note=None, expected_label=None, bpf_filter=None,
                    max_rows=None, lime_num_samples=None, lime_repeats=None):
    """
    統一入口。回傳 (ok, message_or_run_id)。
    source_type: csv | pcap（source 為檔案路徑）| live（source 為網卡名稱）
    """
    global _starting
    if run_state["running"] or _starting:
        return False, "已有測試正在執行中，請先停止。"
    _starting = True
    try:
        return await _start_run(source_type, source, name, note, expected_label, bpf_filter,
                                max_rows, lime_num_samples, lime_repeats)
    finally:
        _starting = False


async def _start_run(source_type, source, name, note, expected_label, bpf_filter,
                     max_rows, lime_num_samples, lime_repeats):
    params = {
        "max_rows": max_rows if max_rows else None,
        "lime_num_samples": int(lime_num_samples or DEFAULT_LIME_NUM_SAMPLES),
        "lime_repeats": int(lime_repeats or DEFAULT_LIME_REPEATS),
        "ks": list(CONSISTENCY_KS),
        "shap_reference": SHAP_REFERENCE,
    }
    display_source = source if source_type == "live" else str(source).rsplit("/", 1)[-1]
    name = (name or "").strip() or f"{display_source} {datetime.datetime.now():%m-%d %H:%M}"
    expected_label = expected_label or None

    if source_type == "live":
        queue = asyncio.Queue()
        loop = asyncio.get_running_loop()
        ok, msg = start_capture(loop, queue, source, bpf_filter)
        if not ok:
            return False, msg
        deadline = loop.time() + CAPTURE_STARTUP_CHECK_SEC
        while loop.time() < deadline:
            status = get_capture_status()
            if not status["running"]:
                return False, status["error"] or "擷取程序意外結束"
            await asyncio.sleep(0.1)

    run_id = await repo.create_run(name, note, source_type, display_source, bpf_filter or None,
                                   expected_label, MODEL_NAME, params)
    _reset_state(run_id, name, source_type, display_source, expected_label, params)

    if source_type == "csv":
        asyncio.create_task(_run_rows(_load_csv, source))
    elif source_type == "pcap":
        asyncio.create_task(_run_rows(_load_pcap, source))
    else:
        _live["queue"] = queue
        _live["task"] = asyncio.create_task(_live_consumer(queue))
        _live["watcher"] = asyncio.create_task(_live_watcher(queue))
    return True, run_id


def _load_csv(path, max_rows):
    # max_rows 為 None（全部）時仍以 MAX_ROWS_LIMIT 為上限，避免把上千萬列的 CSV 整個讀進記憶體
    return pd.read_csv(path, nrows=max_rows or MAX_ROWS_LIMIT)


def _load_pcap(path, max_rows):
    # NFStreamer 會 fork 出 meter 行程；在 uvicorn 的執行緒裡 fork 會卡住（大 pcap 實測卡死），
    # 所以放到用 spawn 建立的獨立行程執行，和即時擷取同一個做法。
    with concurrent.futures.ProcessPoolExecutor(max_workers=1, mp_context=mp.get_context("spawn")) as pool:
        return pool.submit(extract_pcap, path, None, max_rows or MAX_ROWS_LIMIT).result()


async def _run_rows(loader, path):
    """CSV / pcap：先在執行緒載入成 DataFrame（pcap 再轉交獨立行程），再逐列處理。"""
    loop = asyncio.get_running_loop()
    try:
        df = await loop.run_in_executor(None, loader, path, run_state["params"]["max_rows"])
    except Exception as e:
        traceback.print_exc()
        await _finish("error", str(e))
        return

    run_state["total"] = len(df)
    await repo.update_run_progress(run_state["run_id"], 0, len(df))
    stop_event = run_state["stop_event"]

    for idx, row in enumerate(df.to_dict("records"), start=1):
        if stop_event.is_set():
            await _finish("stopped")
            return
        run_state["processed"] = idx
        await process(row, idx)
        if idx % PROGRESS_DB_EVERY == 0:
            await repo.update_run_progress(run_state["run_id"], idx, len(df))
    await _finish("done")


async def _live_consumer(queue):
    while True:
        record = await queue.get()
        run_state["processed"] += 1
        run_state["total"] = run_state["processed"]
        await process(record, run_state["processed"])
        if run_state["processed"] % PROGRESS_DB_EVERY == 0:
            await repo.update_run_progress(run_state["run_id"], run_state["processed"], run_state["total"])
        queue.task_done()


async def _live_watcher(queue):
    """擷取自行結束時（例如網卡消失），等已擷取的 flow 分析完再收尾。"""
    while get_capture_status()["running"]:
        await asyncio.sleep(1)
    await queue.join()
    _live["watcher"] = None   # 避免 _stop_live_tasks 取消自己
    error = get_capture_status().get("error")
    await _finish("error" if error else "stopped", error)


def _stop_live_tasks():
    for key in ("task", "watcher"):
        if _live[key]:
            _live[key].cancel()
    _live.update(task=None, watcher=None, queue=None)


async def _finish(status, error=None):
    if not run_state["running"]:
        return
    run_state["running"] = False
    run_state["error"] = error
    if run_state["source_type"] == "live":
        _stop_live_tasks()
    await repo.finish_run(run_state["run_id"], status, run_state["processed"], run_state["total"], error)
    _append_result({"zone": "DONE", "status": status, "processed": run_state["processed"],
                    "total": run_state["total"], "error": error})


async def stop_run():
    """回傳 False 表示沒有測試在執行。"""
    if not run_state["running"]:
        return False
    if run_state["source_type"] == "live":
        # stop_capture 會等待擷取子行程結束（阻塞），放到執行緒避免卡住事件迴圈
        await asyncio.get_running_loop().run_in_executor(None, stop_capture)
        await _finish("stopped")
    else:
        run_state["stop_event"].set()    # _run_rows 會在下一筆前收尾
    return True


def get_status():
    status = {key: run_state[key] for key in
              ("run_id", "name", "running", "source_type", "source", "total", "processed", "params",
               "expected_label", "error")}
    if run_state["source_type"] == "live":
        cap = get_capture_status()
        status["capture"] = {**cap, "pending": _live["queue"].qsize() if _live["queue"] else 0}
    return status
