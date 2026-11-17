"""
解釋忠實度（faithfulness）：把解釋器挑出的 top-k 特徵「拿掉」，看模型對預測類別的機率掉多少。
掉得越多，代表這些特徵確實是模型做出該預測的依據。

「拿掉」= 把特徵值換成背景資料的中位數，其餘特徵不動，重新預測。
背景資料是模型檔附的驗證資料（config.X_train，名稱是歷史遺留，不是完整訓練集）。
"""

import numpy as np
import pandas as pd

from config import X_train, feature_names
from core.modelPredict import predict_prob

_BACKGROUND = X_train.median(axis=0)
_IDX = {name: i for i, name in enumerate(feature_names)}


def ablation_drop(feature_row, top_k_names, predicted_class, original_prob=None):
    """
    feature_row: 1-D array，順序同 feature_names
    top_k_names: 要移除的特徵名稱
    回傳 原機率 - 移除後機率（可為負，表示移除後反而更有把握）
    """
    row = np.array(feature_row, dtype=float).copy()
    if original_prob is None:
        original_prob = float(predict_prob(row)[0][predicted_class])
    for name in top_k_names:
        row[_IDX[name]] = float(_BACKGROUND[name])
    ablated_prob = float(predict_prob(row)[0][predicted_class])
    return original_prob - ablated_prob


def ablation_drops_multi_k(feature_row, explanation, predicted_class, ks, original_prob=None):
    """explanation: [(feature, weight), ...]，回傳 {k: drop}。"""
    ranked = [name for name, _ in sorted(explanation, key=lambda x: abs(x[1]), reverse=True)]
    return {k: ablation_drop(feature_row, ranked[:k], predicted_class, original_prob) for k in ks}
