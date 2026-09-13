# 取得stream/cather.py從網路中擷取到的封包，並對其進行預處理，以便後續的分析和解釋。

# 輸入：從stream/cather.py獲取的封包資料
# 輸出：經過清洗、轉換和特徵提取後的資料，準備好供模型使用

import pandas as pd

from config import feature_names

def transform(record):    #對原始的特徵資料進行清洗和轉換, 並回傳供模型使用的資料
    # record 可能同時帶有 flow 的 metadata（IP、port、時間…）或 label，
    # 只取模型需要的特徵並依訓練時的順序排列；缺欄位時直接報 KeyError，避免靜默補值
    record = pd.DataFrame([record])[list(feature_names)]
    return record
