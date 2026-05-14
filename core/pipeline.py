import joblib
import os
import asyncio
import numpy as np
import pandas as pd
import traceback

from core.explainer import explain_lime, explain_shap
from core.consistency import compare_shap_lime
from core.modelPredict import predict, predict_prob
from stream.catcher import Start
from core.preprocessor import transform
from db.repository import insert_flow, init_pool, close_pool, insert_alert, insert_explain_lime, insert_explain_shap, get_packets, get_explanation_lime
from config import feature_names, class_names, CONFIDENCE_HIGH, CONFIDENCE_LOW, REPLAY_LIMIT

sse_queue: asyncio.Queue = asyncio.Queue()

analysis_state: dict = {
    "running": False,
    "filename": None,
    "total": 0,
    "processed": 0,
    "stop_event": None
}

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
            await sse_queue.put(event)  # 將事件放入 SSE 佇列
            return event
        
        conf_zone = 'HIGH_CONF' if confidence >= CONFIDENCE_HIGH else 'SUSPICIOUS'
        alert_id = await insert_alert({
            "flow_id": flow_id,
            "attack_type": label,
            "confidence": round(confidence, 4),
            "conf_zone": conf_zone,
            "status": 'unhandled',
        })  # 將警報資料插入資料庫
        
        # print("\nSHAP 解釋:")
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

            event["lime_top3"] = [
                {"feature": name, "weight": round(weight, 4)}
                for name, weight in lime_explanation[:3]
            ]
            event["consistency_score"] = round(comparison_result['consistency_score'], 4)
            print("lime解釋完畢。\t", end='')
            print("特徵一致性分數：  ", event["consistency_score"])

        await sse_queue.put(event)  # 將事件放入 SSE 佇列
        return event

    except Exception as e:
        traceback.print_exc()
        return

async def run_csv_analysis(file_path, stop_event):
    try:
        df = pd.read_csv(file_path, nrows=REPLAY_LIMIT)
    except Exception as e:
        analysis_state["running"] = False
        await sse_queue.put({
            "zone": "DONE",
            "processed": 0,
            "total": 0,
            "error": str(e)
        })
        return

    analysis_state["total"] = len(df)
    analysis_state["processed"] = 0

    for idx, row in df.iterrows():
        if stop_event.is_set():
            print("分析已停止")
            break
        try:
            await process(row.to_dict())
        except Exception as e:
            print(f"Error processing row {idx}: {e}")
        analysis_state["processed"] += 1
    
    analysis_state["running"] = False
    await sse_queue.put({
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