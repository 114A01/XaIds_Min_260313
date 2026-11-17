"""
對單筆預測做 SHAP 與 LIME 解釋。

兩者解釋的是同一個東西：模型對「預測類別」輸出的 log-odds（XGBoost margin）。
  * SHAP：TreeExplainer，對樹模型是精確計算，輸出就是 margin 尺度。
  * LIME：回歸模式，被解釋的函數是 predict(output_margin=True)[:, predicted_class]。
    （LIME 分類模式解釋的是機率，和 SHAP 的 log-odds 尺度不同；而 SHAP 對多類別 softmax
      不支援 model_output="probability"，所以統一到 margin。）

兩者也用同一份參考資料（_background，從模型檔附的驗證資料抽 LIME_BACKGROUND_N 筆）：
  * LIME 的擾動樣本從它產生。
  * SHAP 以 feature_perturbation="interventional" 對它取期望，base value = 這批樣本的平均 margin。
    config.SHAP_REFERENCE 設成 "tree_path" 可以改回不給背景資料的做法（參考分布變成樹內部記錄的
    訓練分布，和 LIME 不同；140 筆試算中約四成 flow 的 top-5 一致特徵數會因此改變）。

回傳格式一律 [(feature_name, weight), ...]，依 |weight| 由大到小排序，包含全部特徵。

LIME 的可重現性：LimeTabularExplainer 的 random_state 會在每次呼叫後前進，
所以 explain_lime 每次呼叫前都重設種子；重複第 i 次用 seed + i，
讓同一筆資料每次執行得到相同結果，重複之間又彼此獨立。
"""

import numpy as np
import pandas as pd
import shap
from lime import lime_tabular

from config import (model, feature_names, X_train, LIME_BACKGROUND_N, LIME_RANDOM_STATE,
                    DEFAULT_LIME_NUM_SAMPLES, SHAP_REFERENCE)

_background = np.array(X_train.sample(n=min(LIME_BACKGROUND_N, len(X_train)), random_state=42))

explainer_lime = lime_tabular.LimeTabularExplainer(
    _background,
    feature_names=feature_names,
    mode="regression",
    random_state=LIME_RANDOM_STATE,
)

if SHAP_REFERENCE == "background":
    explainer_shap = shap.TreeExplainer(
        model,
        data=pd.DataFrame(_background.astype("float32"), columns=feature_names),
        feature_perturbation="interventional",
    )
elif SHAP_REFERENCE == "tree_path":
    explainer_shap = shap.TreeExplainer(model)
else:
    raise RuntimeError(f"config.SHAP_REFERENCE 必須是 'background' 或 'tree_path'，目前是 {SHAP_REFERENCE!r}")

_N_FEATURES = len(feature_names)


def _sorted_pairs(values):
    pairs = [(name, float(v)) for name, v in zip(feature_names, values)]
    pairs.sort(key=lambda x: abs(x[1]), reverse=True)
    return pairs


def _margin_fn(predicted_class):
    def fn(rows):
        df = pd.DataFrame(np.asarray(rows, dtype="float32"), columns=feature_names)
        return model.predict(df, output_margin=True)[:, predicted_class]
    return fn


def explain_shap(feature, predicted_class):
    """回傳 (pairs, base_value)。feature 是 1-D array，順序同 feature_names。"""
    feature = np.asarray(feature, dtype="float32").reshape(1, -1)
    # check_additivity=False：加總性已另外驗證過（誤差約 1e-6），不讓浮點誤差的檢查中斷一筆 flow
    shap_values = explainer_shap.shap_values(feature, check_additivity=False)
    values = shap_values[0, :, predicted_class]
    # expected_value 要在 shap_values() 之後讀：tree_path 模式下，呼叫前它只是 base_score 的佔位值
    base_value = float(explainer_shap.expected_value[predicted_class])
    return _sorted_pairs(values), base_value


def _explain_lime_once(feature, predicted_class, num_samples, seed):
    # LimeTabularExplainer、它的 discretizer 與 base 各自持有 RNG 物件，三個都要重設才能重現
    rng = np.random.RandomState(seed)
    explainer_lime.random_state = rng
    explainer_lime.base.random_state = rng
    if explainer_lime.discretizer is not None:
        explainer_lime.discretizer.random_state = rng
    explanation = explainer_lime.explain_instance(
        np.asarray(feature, dtype=float),
        _margin_fn(predicted_class),
        num_features=_N_FEATURES,
        num_samples=num_samples,
    )
    weights = np.zeros(_N_FEATURES)
    for idx, w in explanation.as_map()[1]:     # 回歸模式的 key 固定是 1
        weights[idx] = w
    return weights


def explain_lime(feature, predicted_class, num_samples=DEFAULT_LIME_NUM_SAMPLES, repeats=1):
    """
    回傳 (mean_pairs, runs)：
      mean_pairs  重複 repeats 次的平均權重（repeats=1 時就是那一次）
      runs        每一次的 pairs 列表，給 lime_self_consistency 用
    """
    repeats = max(1, int(repeats))
    all_weights = [_explain_lime_once(feature, predicted_class, num_samples, LIME_RANDOM_STATE + i)
                   for i in range(repeats)]
    runs = [_sorted_pairs(w) for w in all_weights]
    mean_pairs = _sorted_pairs(np.mean(all_weights, axis=0))
    return mean_pairs, runs
