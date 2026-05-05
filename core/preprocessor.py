# 取得stream/cather.py從網路中擷取到的封包，並對其進行預處理，以便後續的分析和解釋。

# 輸入：從stream/cather.py獲取的封包資料
# 輸出：經過清洗、轉換和特徵提取後的資料，準備好供模型使用

import pandas as pd

def transform(record):    #對原始的特徵資料進行清洗和轉換, 並回傳供模型使用的資料
    # 在這裡進行特徵清洗和轉換的邏輯
    record = pd.DataFrame([record]).drop(columns=[' Label'], errors='ignore')  # 將單條記錄轉換為DataFrame格式
    return record

