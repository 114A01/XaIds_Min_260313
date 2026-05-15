import aiomysql
from mysql.connector import Error
import json
import datetime
import uuid

async def init_pool():
    global pool
    pool = await aiomysql.create_pool(
        host="localhost",
        user="allen",
        password="allen",
        db="xaids",
        cursorclass = aiomysql.DictCursor,
        autocommit=True
    )

async def close_pool():
    global pool
    pool.close()
    await pool.wait_closed()

async def get_packets():
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT * FROM packet")
            results = await cursor.fetchall()
            return results

async def get_flows():
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT * FROM flow ORDER BY start_time DESC")
            return await cursor.fetchall()

async def get_alerts():
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT * FROM alert ORDER BY alert_time DESC")
            return await cursor.fetchall()

async def get_explanation_lime(alert_id: str):
    # 在這裡根據 packet_id 從資料庫中查詢對應的 LIME 解釋
    # 這裡使用 FAKE_EXPLANATIONS_lime 作為示例，實際應該從資料庫中獲取
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT * FROM explanationForLime WHERE alert_id = %s", (alert_id,))
            result = await cursor.fetchone()
            return result if result else {"explanations": []}

async def get_explanation_shap(alert_id: str):
    # 在這裡根據 packet_id 從資料庫中查詢對應的 LIME 解釋
    # 這裡使用 FAKE_EXPLANATIONS_lime 作為示例，實際應該從資料庫中獲取
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT * FROM explanationForShap WHERE alert_id = %s", (alert_id,))
            result = await cursor.fetchone()
            return result if result else {"explanations": []}
# print(mydb)

async def insert_flow(record, feature):
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            flow_id = str(uuid.uuid4())  # 生成唯一的 flow_id

            if hasattr(feature, 'to_dict'):
                computed_features = feature.iloc[0].to_dict()  # 將 DataFrame 行轉換為字典
            else:
                computed_features = {str(i): v for i, v in enumerate(feature)}  # 如果不是 DataFrame，直接轉換為列表

            sql = "INSERT INTO flow (id, source_ip, destination_ip, source_port, destination_port, protocol, start_time, computed_features) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            values = (flow_id, record.get('source_ip'), record.get('destination_ip'), record.get('source_port'), record.get('destination_port'), record.get('protocol'), record.get('start_time'), json.dumps(computed_features))
            await cursor.execute(sql, values)
            await conn.commit()
            return flow_id

async def insert_alert(alert_data):
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            alert_id = str(uuid.uuid4())  # 生成唯一的 alert_id
            sql = "INSERT INTO alert (alert_id, flow_id, attack_type, confidence, conf_zone, status, alert_time) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            values = (alert_id, alert_data.get('flow_id'), alert_data.get('attack_type'), alert_data.get('confidence'), alert_data.get('conf_zone'), alert_data.get('status'), datetime.datetime.now())
            await cursor.execute(sql, values)
            await conn.commit()
            return alert_id

async def insert_explain_lime(lime_explanation, alert_id):
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:

            lime_value = [{"feature": name, "weight": weight} for name, weight in lime_explanation]

            sql = "INSERT INTO explanationForLime (alert_id, lime_value) VALUES (%s, %s)"
            values = (alert_id, json.dumps(lime_value))
            await cursor.execute(sql, values)
            await conn.commit()

async def insert_explain_shap(shap_explanation, base_value, alert_id):
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:

            shap_value = [{"feature": name, "weight": round(float(weight), 4)} for name, weight in shap_explanation]

            sql = "INSERT INTO explanationForShap (alert_id, shap_value, base_value) VALUES (%s, %s, %s)"
            values = (alert_id, json.dumps(shap_value), base_value)
            await cursor.execute(sql, values)
            await conn.commit()

async def get_flow_count():
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute("select count(*) as total from flow")
            row = await cursor.fetchone()
            return row["total"]

async def get_alert_count():
    async with pool.acquire() as conn:
        async with conn.cursor() as cursor:
            await cursor.execute("select count(*) as total from alert")
            row = await cursor.fetchone()
            return row["total"]


# async def insert_comparison_result(comparison_result, alert_id):
#     async with pool.acquire() as conn:
#         async with conn.cursor() as cursor:
#             sql = "INSERT INTO comparisonResult (alert_id, consistency_score, common_features) VALUES (%s, %s, %s)"
#             values = (alert_id, comparison_result.get('consistency_score'), json.dumps(comparison_result.get('common_features')))
#             await cursor.execute(sql, values)
#             await conn.commit()