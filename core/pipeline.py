import joblib
import os
import numpy as np
import pandas as pd
from core.explainer import explain_lime, explain_shap
from core.consistency import compare_shap_lime
from core.modelPredict import predict, predict_proba

bundle_data = joblib.load('./saved_models/training_data.joblib')
feature_names = bundle_data['feature_names']
class_names = bundle_data['class_names']

feature = np.array([33.76,6,67.82,497.069705595836,0.04,0.13,0.11,0.05,0.84,0.0,0.0,84,13,4,11,0.94,0.01,0.0,0.0,0.0,0.0,0.0,0.95,0.05,0.0,0.0,0.0,0.0,1.0,1.0,9821,60,559,98.21,109.4914133435111,98.21,0.0020117902755737,100,11988.3695959596])
feature = pd.DataFrame([feature], columns=feature_names)
print("feature: \n", feature)
prediction = predict(feature)
proba = predict_proba(feature)

print("預測結果:", class_names[prediction])
print("預測機率:", proba[prediction])

print("\nLIME 解釋:")
lime_explanation = explain_lime(feature.values[0])
for feature_name, importance in lime_explanation:
    print(f"{feature_name}: {importance:.4f}")

print("\nSHAP 解釋:")
shap_explanation = explain_shap(feature.values[0])
for feature_name, shap_value in shap_explanation:
    print(f"{feature_name}: {shap_value:.4f}")  

comparison_result = compare_shap_lime(shap_explanation, lime_explanation)
print("\n一致性比較結果:")
print(f"Consistency Score: {comparison_result['consistency_score']:.4f}")
print(f"Common Features in Top-k: {comparison_result['common_feature']}")