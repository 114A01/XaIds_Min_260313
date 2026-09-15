import joblib
import os
import asyncio
import numpy as np
import pandas as pd
import traceback

from core.explainer import explain_lime, explain_shap
from core.consistency import compare_shap_lime
from core.modelPredict import predict, predict_prob
from stream.catcher import Start, start_capture, stop_capture, get_capture_status, DEFAULT_IDLE_TIMEOUT, DEFAULT_ACTIVE_TIMEOUT
from core.preprocessor import transform
from db.repository import insert_flow, init_pool, close_pool, insert_alert, insert_explain_lime, insert_explain_shap, get_packets, get_explanation_lime, insert_comparison_result
from config import feature_names, class_names, CONFIDENCE_HIGH, CONFIDENCE_LOW, REPLAY_LIMIT

# 啟動擷取後等多久確認沒有立即失敗（網卡不存在、BPF 語法錯誤約 0.5 秒內會回報）
CAPTURE_STARTUP_CHECK_SEC = 1.5

live_capture_state: dict = {
    "running": False,
    "task": None,       # 分析 flow 的 pipeline_queue
    "watcher": None,    # 偵測擷取自行結束的 _watch_live_capture
    "queue": None,
}

analysis_state: dict = {
    "running": False,
    "filename": None,
    "total": 0,
    "processed": 0,
    "stop_event": None,
    "results": []
}

def _append_result(event: dict):
    analysis_state["results"].append(event)

async def process(record):
    try:
        feature = transform(record)        #進行預處理
        prediction = predict(feature)
        prob = predict_prob(feature)[0]
        confidence = float(prob[prediction])
        flow_id = await insert_flow(record, feature)  # 將封包資料插入資料庫
        label = class_names[prediction]

        print("預測結果:", class_names[prediction])
        print("預測機率:", prob[prediction])

        if confidence < CONFIDENCE_LOW:
            event = {
                "zone": "UNCERTAIN",
                "attack_type": label,
                "confidence": round(confidence, 4),
                "flow_id": flow_id,
                "processed": analysis_state["processed"],
                "total": analysis_state["total"]
            }
            _append_result(event)
            return event
        
        conf_zone = 'HIGH_CONF' if confidence >= CONFIDENCE_HIGH else 'SUSPICIOUS'

        if class_names[prediction] == 'Benign':
            event = {
                "zone": "BENIGN",
                "attack_type": label,
                "confidence": round(confidence, 4),
                "processed": analysis_state["processed"],
                "total": analysis_state["total"]
            }
            _append_result(event)
            return event

        alert_id = await insert_alert({
            "flow_id": flow_id,
            "attack_type": label,
            "confidence": round(confidence, 4),
            "conf_zone": conf_zone,
            "status": 'unhandled',
        })  # 將警報資料插入資料庫

        shap_explanation, base_value = explain_shap(feature.values[0], prediction)
        print("shap 解釋完畢\t", end=" ")
        await insert_explain_shap(shap_explanation, f"{base_value:.6f}", alert_id)  # 將 SHAP 解釋插入資料庫

        event = {
            "zone": conf_zone,
            "alert_id": alert_id,
            "attack_type": label,
            "confidence": round(confidence, 4),
            "shap_top3": [
                {"feature": name, "weight": round(weight, 4)}
                for name, weight in shap_explanation[:3]
            ],
            "processed": analysis_state["processed"],
            "total": analysis_state["total"]
        }

        if conf_zone == 'HIGH_CONF':
            lime_explanation = explain_lime(feature.values[0])
            await insert_explain_lime(lime_explanation, alert_id)  # 將 LIME 解釋插入資料庫
            comparison_result = compare_shap_lime(shap_explanation, lime_explanation)

            await insert_comparison_result(comparison_result, alert_id)  # 將一致性比較結果插入資料庫

            event["lime_top3"] = [
                {"feature": name, "weight": round(weight, 4)}
                for name, weight in lime_explanation[:3]
            ]
            event["consistency_score"] = round(comparison_result['feature_agreement'], 4)
            print("lime解釋完畢。\t", end='')
            print("特徵一致性分數：  ", event["consistency_score"])

        _append_result(event)
        return event

    except Exception as e:
        traceback.print_exc()
        return

async def run_csv_analysis(file_path, stop_event):
    try:
        df = pd.read_csv(file_path, nrows=REPLAY_LIMIT)
    except Exception as e:
        analysis_state["running"] = False
        analysis_state["results"].append({
            "zone": "DONE",
            "processed": 0,
            "total": 0,
            "error": str(e)
        })
        return

    analysis_state["total"] = len(df)
    analysis_state["processed"] = 0
    analysis_state["results"] = []

    for idx, row in df.iterrows():
        if stop_event.is_set():
            print("分析已停止")
            break
        analysis_state["processed"] += 1
        try:
            await process(row.to_dict())
        except Exception as e:
            print(f"Error processing row {idx}: {e}")
    
    analysis_state["running"] = False
    analysis_state["results"].append({
        "zone": "DONE",
        "processed": analysis_state["processed"],
        "total": analysis_state["total"]
    })

async def pipeline_queue(queue):
    while True:
        record = await queue.get()
        await process(record)
        queue.task_done()

async def launch_pipeline():
    await init_pool()  # 初始化資料庫連接池
    queue = asyncio.Queue()
    loop = asyncio.get_event_loop()

    Start(loop, queue)  # 啟動封包捕獲器，傳入事件循環和佇列

    asyncio.create_task(pipeline_queue(queue))  # 啟動管道處理佇列

    try:
        await asyncio.Event().wait()  # 保持主線程運行
    except asyncio.CancelledError:
        pass
    finally:
        await close_pool()  # 關閉資料庫連接池

async def start_live_capture(interface=None, bpf_filter=None,
                             idle_timeout=DEFAULT_IDLE_TIMEOUT, active_timeout=DEFAULT_ACTIVE_TIMEOUT):
    # interface / bpf_filter 為 None 時使用 config 的 CAPTURE_IFACE / CAPTURE_FILTER，bpf_filter 空字串表示不過濾
    if analysis_state["running"]:
        return False, "檔案分析正在進行中，請先停止。"
    if live_capture_state["running"]:
        return False, "即時流量分析已在執行中。"

    queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    ok, msg = start_capture(loop, queue, interface, bpf_filter, idle_timeout, active_timeout)
    if not ok:
        return False, msg

    # 網卡不存在、BPF 語法錯誤等會在擷取子行程啟動後約 0.5 秒內回報，先確認沒有立即失敗
    deadline = loop.time() + CAPTURE_STARTUP_CHECK_SEC
    while loop.time() < deadline:
        status = get_capture_status()
        if not status["running"]:
            return False, status["error"] or "擷取程序意外結束"
        await asyncio.sleep(0.1)

    analysis_state["results"] = []

    live_capture_state["running"] = True
    live_capture_state["queue"] = queue
    live_capture_state["task"] = asyncio.create_task(pipeline_queue(queue))
    live_capture_state["watcher"] = asyncio.create_task(_watch_live_capture(queue))

    return True, "Started"

async def _watch_live_capture(queue):
    # 擷取自行結束時（例如執行中網卡消失），等已擷取的 flow 分析完再同步 pipeline 狀態
    while get_capture_status()["running"]:
        await asyncio.sleep(1)
    await queue.join()
    live_capture_state["watcher"] = None   # 避免 _reset_live_capture 取消自己
    _reset_live_capture()

def _reset_live_capture():
    for key in ("task", "watcher"):
        if live_capture_state[key]:
            live_capture_state[key].cancel()
    live_capture_state.update(running=False, task=None, watcher=None, queue=None)

async def stop_live_capture():
    if not live_capture_state['running']:
        return False
    # stop_capture 會等待擷取子行程結束（阻塞），放到執行緒避免卡住事件迴圈
    await asyncio.get_running_loop().run_in_executor(None, stop_capture)
    _reset_live_capture()
    return True

def get_live_capture_status():
    status = get_capture_status()
    queue = live_capture_state["queue"]
    status["capturing"] = status["running"]                # 擷取子行程是否仍在抓封包
    status["running"] = live_capture_state["running"]      # 擷取中，或擷取已結束但仍在分析剩下的 flow
    status["pending"] = queue.qsize() if queue else 0      # 已擷取、尚未分析的 flow 數
    return status