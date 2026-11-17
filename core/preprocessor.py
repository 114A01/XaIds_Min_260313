"""從一筆 record（CSV 的一列，或 stream/catcher.py 產生的 flow）取出模型特徵。"""

import pandas as pd

from config import feature_names

def transform(record):
    # record 可能同時帶有 flow 的 metadata（IP、port、時間…）或 label，
    # 只取模型需要的特徵並依訓練時的順序排列；缺欄位時直接報 KeyError，避免靜默補值
    record = pd.DataFrame([record])[list(feature_names)]
    return record
