import joblib
from lime import lime_tabular
import shap
import pandas as pd
import numpy as np
import xgboost as xgb

from config import model, feature_names, X_train, class_names
from core.modelPredict import predict, predict_prob
# 負責對模型的預測做出解釋，讓使用者能夠理解模型的決策過程。

# 輸入：模型的預測結果、相關的特徵資料
# 輸出：對模型預測的解釋，例如特徵重要性、決策規則等

# 視訓練資料進行更改
train_data = X_train  # 替換為實際的訓練資料

explainer_lime = lime_tabular.LimeTabularExplainer(
    np.array(train_data.sample(n=500, random_state=42)), 
    feature_names=feature_names, 
    class_names=class_names, 
    mode='classification'
)

explainer_shap_tree = shap.TreeExplainer(model)

# explainer_shap_kernel = shap.KernelExplainer(model.predict_prob, train_data)

def explain_lime(feature):    # 以 lime 解釋模型輸出
    predicted_class = int(predict(feature))
    
    explanation = explainer_lime.explain_instance(feature, predict_prob, num_features=10, num_samples=1000, labels=(predicted_class,))
    
    index_weight_pairs = explanation.as_map()[predicted_class]
    
    # 用 feature_idx 對應回 feature_names，並依絕對值排序
    result = [
        (feature_names[idx], weight)
        for idx, weight in index_weight_pairs
    ]
    result.sort(key=lambda x: abs(x[1]), reverse=True)
    return result

def explain_shap(feature, predicted_class):    # 以 shap 解釋模型輸出
    shap_values = explainer_shap_tree.shap_values(feature.reshape(1, -1))
    base_value = explainer_shap_tree.expected_value[predicted_class]
    values = shap_values[0, :,predicted_class]  # 取出對應類別的 SHAP 值
    paired = list(zip(feature_names, values))
    top10 = sorted(paired, key=lambda x: abs(x[1]), reverse=True)[:10]
    return top10, base_value

