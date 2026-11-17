"""
模型預測。7 類模型（MODEL_CARD_7class.md）要在 log 機率上加類別偏移再取 argmax：
    pred = argmax(log(predict_proba(X)) + class_bias)
predict_prob 回傳的是加了偏移後重新正規化的機率（softmax(log p + bias)），
所以 confidence = predict_prob()[pred] 與 predict() 一致。
SHAP / LIME 解釋的是 margin（log-odds），偏移是每類的常數，不影響特徵貢獻。
"""

import numpy as np
import pandas as pd
from config import model, feature_names, class_bias


def _to_df(feature):
    if isinstance(feature, pd.DataFrame):
        return feature[feature_names].astype("float32")
    arr = np.array(feature, dtype="float32")
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    return pd.DataFrame(arr, columns=feature_names)


def predict_prob(feature):
    """加了類別偏移後的機率，shape (n, n_classes)，每列總和為 1。"""
    raw = model.predict_proba(_to_df(feature))
    logp = np.log(np.clip(raw, 1e-9, 1.0)) + class_bias
    logp -= logp.max(axis=1, keepdims=True)
    p = np.exp(logp)
    return p / p.sum(axis=1, keepdims=True)


def predict(feature):
    return int(predict_prob(feature).argmax(axis=1)[0])
