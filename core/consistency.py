# 做到四件事
'''
1. 接收兩個 XAI 方法的特徵重要度結果, 例如:SHAP、Permutation Importance
2. 取出 top-k 特徵
3. 計算一致性指標
4. 回傳給 dashboard / database / 表格使用
'''


def compare_shap_lime(shap_exp: list[tuple[str, float]], lime_exp: list[tuple[str, float]], k: int = 5):
    # 取出 top-k 特徵
    top_shap = sorted(shap_exp, key=lambda x: abs(x[1]), reverse=True)[:k]
    top_lime = sorted(lime_exp, key=lambda x: abs(x[1]), reverse=True)[:k]

    top_shap_feats = {name for name, _ in top_shap}
    top_lime_feats = {desc for desc, _ in top_lime}

    intersection = top_shap_feats.intersection(top_lime_feats)
    
    # 特徵一致性指標
    feature_agreement = len(intersection) / k

    shap_dict = dict(top_shap)
    lime_dict = dict(top_lime)
    # 正負一致性指標
    sign_agreement = sum(1 for feature in intersection 
                         if (lime_dict[feature] > 0) == (shap_dict[feature] > 0))
    sign_agreement = sign_agreement / k

    # 排名一致性指標
    rank_agreement = sum(1 for (feature_shap, _), (feature_lime, _) in zip(top_shap, top_lime) if feature_shap == feature_lime) / k

    return { "feature_agreement": feature_agreement,
            "sign_agreement": sign_agreement,
            "rank_agreement": rank_agreement,
            "common_feature" : intersection }


