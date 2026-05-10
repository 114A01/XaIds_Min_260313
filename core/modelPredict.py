# 接收預處理的資料，根據訓練好的模型進行預測，並將結果傳遞給解釋器進行解釋。

# 輸入：經過預處理的資料
# 輸出：模型的預測結果。

import numpy as np
import xgboost as xgb
import pandas as pd
from config import model, feature_names

def _to_df(feature):
    if isinstance(feature, pd.DataFrame):
        return feature
    # numpy array 或 list → 包成 DataFrame
    arr = np.array(feature)
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    return pd.DataFrame(
        arr,
        columns=feature_names
    )

def predict(feature):
    return model.predict(_to_df(feature))[0]

def predict_prob(feature):
    return model.predict_proba(_to_df(feature))