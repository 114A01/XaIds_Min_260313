import mysql.connector
import aiomysql
from mysql.connector import Error
import json
import random

mydb = mysql.connector.connect(
    host="localhost",
    user="allen",
    password="allen",
    database="xaids"
)

# FAKE_PACKETS = [
#     {"id": "001", "src_ip": "192.168.1.105", "dst_ip": "10.0.0.1",  "protocol": "TCP", "length": 1420, "label": "normal",    "status": "confirmed", "note": ""},
#     {"id": "002", "src_ip": "203.0.113.42",  "dst_ip": "10.0.0.5",  "protocol": "UDP", "length": 64,   "label": "attack",     "status": "pending",   "note": ""},
#     {"id": "003", "src_ip": "10.1.2.3",      "dst_ip": "10.0.0.1",  "protocol": "TCP", "length": 520,  "label": "normal",     "status": "confirmed", "note": "內部流量"},
#     {"id": "004", "src_ip": "198.51.100.77", "dst_ip": "10.0.0.9",  "protocol": "ICMP","length": 1024, "label": "suspicious", "status": "pending",   "note": ""},
#     {"id": "005", "src_ip": "172.16.0.88",   "dst_ip": "10.0.0.2",  "protocol": "TCP", "length": 256,  "label": "attack",     "status": "pending",   "note": ""},
# ]

# FAKE_EXPLANATIONS_lime = [
#     {"explanations": [{"rule": "2.00 < Subflow Fwd Packets <= 4.00", "weight": 0.0027143669991300553}, {"rule": "64.00 <  Fwd Header Length <= 104.00", "weight": 0.0027039148121743785}, {"rule": "64.00 <  Fwd Header Length.1 <= 104.00", "weight": 0.002620197858723672}]},
#     {"explanations": [{"rule": "64.00 <  Fwd Header Length.1 <= 104.00", "weight": 0.002795238165471092}, {"rule": "64.00 <  Fwd Header Length <= 104.00", "weight": 0.0025182891813858802}, {"rule": "2.00 <  Total Fwd Packets <= 4.00", "weight": 0.002416458033077221}]},
#     {"explanations": [{"rule": "64.00 <  Fwd Header Length.1 <= 104.00", "weight": 0.002220058679421769}, {"rule": "64.00 <  Fwd Header Length <= 104.00", "weight": 0.0021850842382679704}, {"rule": "2.00 <  Total Fwd Packets <= 4.00", "weight": 0.0021695497786990508}]},
# ]

cur = mydb.cursor()

pool = None

async def init_pool():
    global pool
    pool = await aiomysql.create_pool(
        host="localhost",
        user="allen",
        password="allen",
        db="xaids",
        cursorclass = aiomysql.DictCursor
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