"""
一次測試（或全部測試）的統計，對應交接文件的主分析：
  RQ1  各一致性指標的分布（平均、中位數、直方圖），附隨機基準線
  RQ2  2×2 表（一致 × 分類正確）、信心值三區分層、AUROC（信心值 vs 信心值 + 一致性）
  輔助 LIME 穩定度、忠實度消融

純 numpy + sklearn，可以從 notebook 直接匯入：
    from core.run_stats import compute_stats
    stats = compute_stats(rows, k=5, threshold=0.6)
rows 的格式見 db/repository.py 的 get_flows_for_stats：每列是 dict，含
    confidence、true_label、predicted_label、consistency = {k: {feature_agreement, sign_agreement,
    rank_agreement, lime_stability, shap_ablation_drop, lime_ablation_drop}}
正確性只在 true_label 非 NULL 的列上算。
"""

import numpy as np

from config import (CONSISTENCY_KS, CONSISTENCY_PRIMARY, CONSISTENCY_HIGH,
                    CONFIDENCE_LOW, CONFIDENCE_HIGH, feature_names, class_names)
from core.consistency import random_baseline

METRICS = ("feature_agreement", "sign_agreement", "rank_agreement")
HIST_BINS = 10
MIN_CELL = 5


def _f(v):
    return None if v is None else float(v)


def _metric(row, k, name):
    return _f(row.get("consistency", {}).get(k, {}).get(name))


def _summary(values):
    arr = np.array([v for v in values if v is not None], dtype=float)
    if arr.size == 0:
        return {"n": 0, "mean": None, "median": None, "q1": None, "q3": None, "std": None}
    return {
        "n": int(arr.size),
        "mean": float(arr.mean()),
        "median": float(np.median(arr)),
        "q1": float(np.percentile(arr, 25)),
        "q3": float(np.percentile(arr, 75)),
        "std": float(arr.std()),
    }


def _hist(values):
    arr = np.array([v for v in values if v is not None], dtype=float)
    counts, edges = np.histogram(arr, bins=HIST_BINS, range=(0.0, 1.0))
    return {"counts": counts.tolist(), "edges": [float(e) for e in edges]}


def _auroc(scores, labels):
    """labels: 1 = 分類正確。兩類都要有才算。"""
    from sklearn.metrics import roc_auc_score
    y = np.asarray(labels)
    if len(y) == 0 or y.min() == y.max():
        return None
    return float(roc_auc_score(y, np.asarray(scores, dtype=float)))


def _logit_auroc(X, y):
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler
    y = np.asarray(y)
    if len(y) < 2 * MIN_CELL or y.min() == y.max():
        return None
    X = StandardScaler().fit_transform(np.asarray(X, dtype=float))
    clf = LogisticRegression(max_iter=1000).fit(X, y)
    return _auroc(clf.predict_proba(X)[:, 1], y)


def _point_biserial(scores, labels):
    s = np.asarray(scores, dtype=float)
    y = np.asarray(labels, dtype=float)
    if len(s) < 3 or s.std() == 0 or y.std() == 0:
        return None
    return float(np.corrcoef(s, y)[0, 1])


def _conf_stratum(conf):
    if conf < CONFIDENCE_LOW:
        return "low"
    if conf < CONFIDENCE_HIGH:
        return "mid"
    return "high"


def compute_stats(rows, k=None, threshold=None, primary=CONSISTENCY_PRIMARY, ks=CONSISTENCY_KS):
    k = int(k or ks[len(ks) // 2])
    threshold = CONSISTENCY_HIGH if threshold is None else float(threshold)
    warnings = []
    n_features = len(feature_names)

    rows = [r for r in rows if r.get("consistency")]
    labeled = [r for r in rows if r.get("true_label") is not None]
    for r in labeled:
        r["correct"] = r["true_label"] == r["predicted_label"]

    result = {
        "k": k,
        "threshold": threshold,
        "primary": primary,
        "n_total": len(rows),
        "n_labeled": len(labeled),
        "n_correct": sum(1 for r in labeled if r["correct"]),
        "accuracy": (sum(1 for r in labeled if r["correct"]) / len(labeled)) if labeled else None,
        "zones": {},
        "per_k": {},
        "two_by_two": None,
        "confidence_strata": None,
        "auroc": None,
        "correct_vs_incorrect": None,
        "warnings": warnings,
    }

    for r in rows:
        z = r.get("conf_zone") or "UNKNOWN"
        result["zones"][z] = result["zones"].get(z, 0) + 1

    # --- RQ1：每個 k 的指標分布 ------------------------------------------
    for kk in ks:
        entry = {"baseline": random_baseline(kk, n_features), "metrics": {}}
        for m in METRICS:
            vals = [_metric(r, kk, m) for r in rows]
            entry["metrics"][m] = {
                **_summary(vals),
                "hist": _hist(vals),
                "hist_correct": _hist([_metric(r, kk, m) for r in labeled if r["correct"]]),
                "hist_incorrect": _hist([_metric(r, kk, m) for r in labeled if not r["correct"]]),
            }
        entry["lime_stability"] = _summary([_metric(r, kk, "lime_stability") for r in rows])
        entry["faithfulness"] = {
            "shap_ablation_drop": _summary([_metric(r, kk, "shap_ablation_drop") for r in rows]),
            "lime_ablation_drop": _summary([_metric(r, kk, "lime_ablation_drop") for r in rows]),
        }
        result["per_k"][kk] = entry

    if not labeled:
        warnings.append("沒有真實標籤，無法計算正確性相關分析")
        return result
    if all(r["correct"] for r in labeled):
        warnings.append("全部分類正確，沒有錯誤樣本可比較")
    elif not any(r["correct"] for r in labeled):
        warnings.append("全部分類錯誤，沒有正確樣本可比較")

    scored = [r for r in labeled if _metric(r, k, primary) is not None]
    score = np.array([_metric(r, k, primary) for r in scored])
    conf = np.array([float(r["confidence"]) for r in scored])
    correct = np.array([1 if r["correct"] else 0 for r in scored])
    consistent = score >= threshold

    # --- 2×2 ---------------------------------------------------------------
    def cell(mask):
        n = int(mask.sum())
        return {"n": n, "error_rate": (float(1 - correct[mask].mean()) if n else None)}

    tbl = {
        "consistent_correct": int((consistent & (correct == 1)).sum()),
        "consistent_incorrect": int((consistent & (correct == 0)).sum()),
        "inconsistent_correct": int((~consistent & (correct == 1)).sum()),
        "inconsistent_incorrect": int((~consistent & (correct == 0)).sum()),
        "consistent": cell(consistent),
        "inconsistent": cell(~consistent),
    }
    if min(tbl["consistent"]["n"], tbl["inconsistent"]["n"]) < MIN_CELL:
        warnings.append(f"2×2 表有格子樣本數少於 {MIN_CELL}")
    result["two_by_two"] = tbl

    # --- 信心值三區分層 ------------------------------------------------------
    strata = {}
    for name in ("low", "mid", "high"):
        mask = np.array([_conf_stratum(c) == name for c in conf])
        strata[name] = {
            "n": int(mask.sum()),
            "error_rate": (float(1 - correct[mask].mean()) if mask.any() else None),
            "consistent": cell(mask & consistent),
            "inconsistent": cell(mask & ~consistent),
        }
    result["confidence_strata"] = strata

    # --- AUROC：一致性有沒有在信心值之外的額外價值 ------------------------
    stability = np.array([_metric(r, k, "lime_stability") for r in scored], dtype=object)
    has_stab = all(s is not None for s in stability) and len(stability) > 0
    auroc = {
        "confidence": _auroc(conf, correct),
        "consistency": _auroc(score, correct),
        "lime_stability": _auroc(stability.astype(float), correct) if has_stab else None,
        "confidence_plus_consistency": _logit_auroc(np.column_stack([conf, score]), correct),
        "confidence_plus_consistency_plus_stability": (
            _logit_auroc(np.column_stack([conf, score, stability.astype(float)]), correct) if has_stab else None),
    }
    result["auroc"] = auroc

    # --- 正確組 vs 錯誤組 ---------------------------------------------------
    result["correct_vs_incorrect"] = {
        "correct": _summary(score[correct == 1]),
        "incorrect": _summary(score[correct == 0]),
        "point_biserial": _point_biserial(score, correct),
    }
    return result


# --- 歷史頁 / 單次測試頁的五張圖 ----------------------------------------
# 一致性橫軸用「方向一致的特徵數」0..k（= round(sign_agreement × k)），不用小數。
# 信心值橫軸切成固定寬度的區間。正確率只在有真實標籤的列上算。
# 「一致組」= 一致特徵數 ≥ ceil(threshold × k)，對應燈號的綠燈門檻。

import math

CONF_BINS = 20


def _count_bucket(rows_in, n_buckets, index_of):
    n = [0] * n_buckets
    labeled = [0] * n_buckets
    correct = [0] * n_buckets
    for r in rows_in:
        i = index_of(r)
        if i is None:
            continue
        n[i] += 1
        if r.get("correct") is not None:
            labeled[i] += 1
            if r["correct"]:
                correct[i] += 1
    return {
        "n": n,
        "n_labeled": labeled,
        "n_correct": correct,
        "accuracy": [(c / l) if l else None for c, l in zip(correct, labeled)],
    }


def _confusion(rows, k, primary):
    """
    混淆矩陣：列 = 真實類別（只列出資料裡出現過的），欄 = 預測類別（模型全部類別，固定順序）。
    多次測試合併時仍是同一張二維表，只是列變多。沒有真實標籤的 flow 不算，另回傳筆數。
    每格附該格 flow 的平均一致特徵數（primary 指標 × k），用來看錯誤的格子一致性是否較低。
    類別順序以模型的 class_names 為準；舊模型留下、不在 class_names 裡的標籤排在最後。
    """
    labeled = [r for r in rows if r.get("true_label") is not None]
    order = list(class_names)
    true_set = {r["true_label"] for r in labeled}
    pred_set = {r["predicted_label"] for r in labeled}
    order += sorted((true_set | pred_set) - set(order))
    true_labels = [c for c in order if c in true_set]
    pred_labels = [c for c in order if c in class_names or c in pred_set]
    ti = {c: i for i, c in enumerate(true_labels)}
    pi = {c: i for i, c in enumerate(pred_labels)}
    counts = [[0] * len(pred_labels) for _ in true_labels]
    sums = [[0.0] * len(pred_labels) for _ in true_labels]
    for r in labeled:
        i, j = ti[r["true_label"]], pi[r["predicted_label"]]
        counts[i][j] += 1
        sums[i][j] += _metric(r, k, primary) * k
    mean_level = [[(s / n) if n else None for s, n in zip(sr, nr)] for sr, nr in zip(sums, counts)]
    return {"true_labels": true_labels, "pred_labels": pred_labels, "counts": counts,
            "mean_level": mean_level, "n_unlabeled": len(rows) - len(labeled)}


def chart_data(rows, k=None, threshold=None, primary=CONSISTENCY_PRIMARY, conf_bins=CONF_BINS, ks=CONSISTENCY_KS):
    """
    回傳：
      consistency: 橫軸 0..k 的筆數與正確率
      confidence:  橫軸 conf_bins 個信心值區間的筆數與正確率（edges 長度 = bins + 1），
                   另附 consistent / inconsistent 兩組各自的筆數與正確率（RQ2：同信心值下一致性有沒有額外價值）
      points:      每筆 flow 的 (一致性整數, 信心值, 正確與否)，給頁尾的散佈圖
      confusion:   混淆矩陣（真實 × 預測），每格附平均一致特徵數，見 _confusion
      summary:     筆數、正確率、平均一致性、隨機基準、兩組錯誤率、AUROC、LIME 穩定度、消融忠實度
    """
    k = int(k or ks[len(ks) // 2])
    threshold = CONSISTENCY_HIGH if threshold is None else float(threshold)
    level_threshold = min(k, max(0, math.ceil(threshold * k - 1e-9)))
    rows = [r for r in rows if _metric(r, k, primary) is not None]
    for r in rows:
        r["correct"] = ((r["true_label"] == r["predicted_label"])
                        if r.get("true_label") is not None else None)
        r["_level"] = int(round(_metric(r, k, primary) * k))
        r["_conf"] = float(r["confidence"])
        r["_consistent"] = r["_level"] >= level_threshold

    def conf_index(r):
        i = int(r["_conf"] * conf_bins)
        return min(max(i, 0), conf_bins - 1)

    labeled = [r for r in rows if r["correct"] is not None]
    n_correct = sum(1 for r in labeled if r["correct"])
    levels = np.array([r["_level"] for r in rows], dtype=float)
    baseline = random_baseline(k, len(feature_names))[primary]

    def group(mask_rows):
        n = len(mask_rows)
        lab = [r for r in mask_rows if r["correct"] is not None]
        return {"n": n, "n_labeled": len(lab),
                "error_rate": (sum(1 for r in lab if not r["correct"]) / len(lab)) if lab else None}

    summary = {
        "n_total": len(rows),
        "n_labeled": len(labeled),
        "n_correct": n_correct,
        "accuracy": (n_correct / len(labeled)) if labeled else None,
        "mean_level": float(levels.mean()) if len(levels) else None,
        "mean_score": float(levels.mean() / k) if len(levels) else None,
        "baseline_score": baseline,
        "baseline_level": baseline * k,
        "level_threshold": level_threshold,
        "threshold": threshold,
        "consistent": group([r for r in rows if r["_consistent"]]),
        "inconsistent": group([r for r in rows if not r["_consistent"]]),
        "auroc": None,
        "point_biserial": None,
        "lime_stability": _summary([_metric(r, k, "lime_stability") for r in rows]),
        "shap_ablation_drop": _summary([_metric(r, k, "shap_ablation_drop") for r in rows]),
        "lime_ablation_drop": _summary([_metric(r, k, "lime_ablation_drop") for r in rows]),
    }
    if labeled:
        score = np.array([_metric(r, k, primary) for r in labeled])
        conf = np.array([r["_conf"] for r in labeled])
        correct = np.array([1 if r["correct"] else 0 for r in labeled])
        summary["auroc"] = {
            "confidence": _auroc(conf, correct),
            "consistency": _auroc(score, correct),
            "confidence_plus_consistency": _logit_auroc(np.column_stack([conf, score]), correct),
        }
        summary["point_biserial"] = _point_biserial(score, correct)

    return {
        "k": k,
        "primary": primary,
        "n_total": len(rows),
        "n_labeled": len(labeled),
        "consistency": {"levels": list(range(k + 1)),
                        **_count_bucket(rows, k + 1, lambda r: r["_level"])},
        "confidence": {"edges": [i / conf_bins for i in range(conf_bins + 1)],
                       **_count_bucket(rows, conf_bins, conf_index),
                       "consistent": _count_bucket([r for r in rows if r["_consistent"]], conf_bins, conf_index),
                       "inconsistent": _count_bucket([r for r in rows if not r["_consistent"]], conf_bins, conf_index)},
        "confusion": _confusion(rows, k, primary),
        "points": [{"x": r["_level"], "y": round(r["_conf"], 4), "correct": r["correct"]} for r in rows],
        "summary": summary,
    }
