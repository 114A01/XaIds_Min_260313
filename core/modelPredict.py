# 接收預處理的資料，根據訓練好的模型進行預測，並將結果傳遞給解釋器進行解釋。

# 輸入：經過預處理的資料
# 輸出：模型的預測結果。

import joblib
import numpy as np
import xgboost as xgb
import pandas as pd

bundle = joblib.load('./saved_models/training_data.pkl')
model = bundle['model']
# scaler = bundle['scaler']
# label_encoder = bundle['label_encoder']

def _to_df(feature):
    if isinstance(feature, pd.DataFrame):
        return feature
    # numpy array 或 list → 包成 DataFrame
    return pd.DataFrame(
        np.array(feature).reshape(1, -1),
        columns=feature_names
    )

def predict(feature):
    # scaled_feature = scaler.transform(_to_df(feature))
    return model.predict(feature)[0]

def predict_prob(feature):
    # scaled_feature = scaler.transform(_to_df(feature))
    return model.predict_proba(feature)[0]