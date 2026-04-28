# 做到四件事
'''
1. 接收兩個 XAI 方法的特徵重要度結果, 例如:SHAP、Permutation Importance
2. 取出 top-k 特徵
3. 計算一致性指標
4. 回傳給 dashboard / database / 表格使用
'''


def compare_shap_lime(shap_exp: list[tuple[str, float]], lime_exp: list[tuple[str, float]], k: int = 10):
    # 取出 top-k 特徵
    top_shap = sorted(shap_exp, key=lambda x: abs(x[1]), reverse=True)[:k]
    top_lime = sorted(lime_exp, key=lambda x: abs(x[1]), reverse=True)[:k]

    top_shap_feats = {name for name, _ in top_shap}
    top_lime_feats = {desc for desc, _ in top_lime}
    # 計算一致性指標 (例如: Jaccard Index)
    intersection = top_shap_feats.intersection(top_lime_feats)
    union = len(top_shap_feats.union(top_lime_feats))
    
    if union == 0:
        return 0.0  # 避免除以零
    
    consistency_score = len(intersection) / union
    return { "consistency_score": consistency_score,
            "common_feature" : intersection }


