import joblib
import os
import asyncio
import numpy as np
import pandas as pd

from core.explainer import explain_lime, explain_shap
from core.consistency import compare_shap_lime
from core.modelPredict import predict, predict_prob
from stream.catcher import Start
from core.preprocessor import transform
from db.repository import insert_flow, init_pool, close_pool, insert_alert, insert_explain_lime, insert_explain_shap, get_packets, get_explanation_lime

bundle_data = joblib.load('./saved_models/training_data.pkl')
feature_names = bundle_data['feature_names']
class_names = bundle_data['class_names']

async def process(record):
    try:
        feature = transform(record)        #進行預處理
        prediction = predict(feature)
        prob = predict_prob(feature)

        flow_id =await insert_flow(record, feature)  # 將封包資料插入資料庫

        print("預測結果:", class_names[prediction])
        print("預測機率:", prob[prediction])

        if prob[prediction] >= 0.6:
            conf_zone = 'HIGH_CONF' if prob[prediction] > 0.9 else 'SUSPICIOUS'
            alert_data = {
                "flow_id": flow_id,
                "attack_type": class_names[prediction],
                "confidence": prob[prediction],
                "conf_zone": conf_zone,
                "status": 'unhandled',
            }
            alert_id = await insert_alert(alert_data)  # 將警報資料插入資料庫

            if conf_zone == 'SUSPICIOUS' or conf_zone == 'HIGH_CONF':

                print("\nSHAP 解釋:")
                shap_explanation, base_value = explain_shap(feature.values[0])
                print(f"Base Value: {base_value:.4f}")
                for feature_name, shap_value in shap_explanation:
                    print(f"{feature_name}: {shap_value:.4f}")  

                await insert_explain_shap(shap_explanation, base_value, alert_id)  # 將 SHAP 解釋插入資料庫
            
            if conf_zone == 'HIGH_CONF':
                print("\nLIME 解釋:")
                lime_explanation = explain_lime(feature.values[0])

                for feature_name, importance in lime_explanation:
                    print(f"{feature_name}: {importance:.4f}")

                await insert_explain_lime(lime_explanation, alert_id)  # 將 LIME 解釋插入資料庫

                comparison_result = compare_shap_lime(shap_explanation, lime_explanation)
                print("\n一致性比較結果:")
                print(f"Consistency Score: {comparison_result['consistency_score']:.4f}")
                print(f"Common Features in Top-k: {comparison_result['common_feature']}")

    except Exception as e:
        print("Error in preprocessing:", e)
        return

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
asyncio.run(launch_pipeline())