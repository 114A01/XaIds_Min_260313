"""
SHAP 與 LIME 解釋的一致性指標（Krishna et al., "The Disagreement Problem"）。

輸入是兩個 [(feature_name, weight), ...] 列表（任意順序，函數內會依 |weight| 排序），
輸出三個 0 到 1 的指標：
  feature_agreement  top-k 特徵交集數 / k
  sign_agreement     交集中方向（正負）相同的特徵數 / k   ← 主指標（CONSISTENCY_PRIMARY）
  rank_agreement     名次相同的特徵數 / k
sign_agreement 必定 <= feature_agreement，因為只在交集內計算。

同時提供：
  compare_multi_k        一次算多個 k
  lime_self_consistency  LIME 重複多次的自我一致度（雜訊上限）
  random_baseline        兩個隨機 top-k 的期望值，畫基準線用
  consistency_level      分數 → high / mid / low（燈號）
"""

from itertools import combinations

from config import CONSISTENCY_KS, CONSISTENCY_HIGH, CONSISTENCY_LOW


def _top_k(exp, k):
    return sorted(exp, key=lambda x: abs(x[1]), reverse=True)[:k]


def compare_shap_lime(shap_exp, lime_exp, k=5):
    top_shap = _top_k(shap_exp, k)
    top_lime = _top_k(lime_exp, k)

    shap_dict = dict(top_shap)
    lime_dict = dict(top_lime)
    intersection = set(shap_dict) & set(lime_dict)

    feature_agreement = len(intersection) / k
    sign_agreement = sum(1 for f in intersection
                         if (lime_dict[f] > 0) == (shap_dict[f] > 0)) / k
    rank_agreement = sum(1 for (fs, _), (fl, _) in zip(top_shap, top_lime) if fs == fl) / k

    return {
        "feature_agreement": feature_agreement,
        "sign_agreement": sign_agreement,
        "rank_agreement": rank_agreement,
        "common_feature": sorted(intersection),
    }


def compare_multi_k(shap_exp, lime_exp, ks=CONSISTENCY_KS):
    return {k: compare_shap_lime(shap_exp, lime_exp, k) for k in ks}


def lime_self_consistency(lime_runs, k):
    """
    LIME 重複 n 次的自我一致度：所有兩兩組合的 sign_agreement 平均。
    n < 2 時回傳 None。用途：SHAP-LIME 一致度的雜訊上限，也是預測對錯的第三個訊號。
    """
    if len(lime_runs) < 2:
        return None
    scores = [compare_shap_lime(a, b, k)["sign_agreement"] for a, b in combinations(lime_runs, 2)]
    return sum(scores) / len(scores)


def random_baseline(k, n_features):
    """
    兩個互相獨立的隨機 top-k 排序的期望值。
      feature: 交集期望 = k^2/n，除以 k → k/n
      sign:    交集內方向隨機各半 → k/(2n)
      rank:    每個名次相同的機率 1/n，k 個名次 → k/n，除以 k → 1/n
    """
    return {
        "feature_agreement": k / n_features,
        "sign_agreement": k / (2 * n_features),
        "rank_agreement": 1 / n_features,
    }


def consistency_level(score):
    """主指標分數 → 燈號。None（沒有分數）→ 'none'。"""
    if score is None:
        return "none"
    if score >= CONSISTENCY_HIGH:
        return "high"
    if score >= CONSISTENCY_LOW:
        return "mid"
    return "low"


LEVEL_HINT = {
    "high": "可信",
    "mid": "建議人工檢查",
    "low": "解釋不一致，建議人工檢查",
    "none": "無一致性資料",
}
