#import const from this file

import os
import joblib
import numpy as np
from pathlib import Path

from stream.flow_features import FEATURES, NFSTREAM_PARAMS

BASE_DIR = Path(__file__).parent
DATA_ROOT = BASE_DIR / "data"
# 測試用 CSV 的目錄（預設 data/csv）；可用環境變數 XAIDS_DATA_DIR 覆寫（例如指到 output/dataset）
DATA_DIR = Path(os.environ.get("XAIDS_DATA_DIR", DATA_ROOT / "csv"))
PCAP_DIR = DATA_ROOT / "pcap"
MODEL_DIR = "./saved_models/"

# Network capture settings
CAPTURE_IFACE = "eth0"        # network interface to sniff on
CAPTURE_FILTER = ""

CONFIDENCE_LOW  = 0.6    # < 0.6  → UNCERTAIN
CONFIDENCE_HIGH = 0.85   # ≥ 0.85 → HIGH_CONF，否則 SUSPICIOUS

# 解釋一致性
CONSISTENCY_KS = (3, 5, 7)          # 每筆 flow 都算這幾個 k
CONSISTENCY_K_DEFAULT = 5
CONSISTENCY_PRIMARY = "sign_agreement"   # 主指標：top-k 重疊且方向一致 / k
CONSISTENCY_HIGH = 0.6   # ≥ 0.6 → 綠燈「可信」；主實驗後依結論調整
CONSISTENCY_LOW  = 0.3   # ≥ 0.3 → 黃燈「建議人工檢查」，低於為紅燈

# 每次測試的預設參數（可在 /run/start 覆寫）
DEFAULT_MAX_ROWS = 1000
# CSV / pcap 的「最多處理筆數」留空（None）表示全部，但仍以這個值為上限：
# DoS-SYN_Flood.csv 有 2,000 萬列，整檔讀入會把記憶體用光，而且以每秒幾筆的速度也跑不完。
MAX_ROWS_LIMIT = 200_000
DEFAULT_LIME_NUM_SAMPLES = 2000
DEFAULT_LIME_REPEATS = 1
LIME_BACKGROUND_N = 500   # LimeTabularExplainer 的背景樣本數
LIME_RANDOM_STATE = 42

# SHAP 的參考分布（解釋是「相對於什麼」算出來的）：
#   "background"  和 LIME 用同一份背景樣本（interventional TreeSHAP）。兩個解釋器只差在方法，預設。
#   "tree_path"   不給背景資料，用樹內部記錄的訓練分布（hessian 加權的 cover）。2026-11-17 以前的做法。
# 這個值會記在每次測試的 params.shap_reference，不同設定的測試不應該合併分析。
SHAP_REFERENCE = "background"

# CICIoT2023 七類模型（說明見 MODEL_CARD_7class.md）：XGBoost + 類別偏移，22 個 nfstream 特徵。
# 預測方式：argmax(log(predict_proba) + class_bias)，見 core/modelPredict.py。
# 舊的 5 類測試模型：saved_models/test_models/nfstream_xgb_20261109.joblib（12 特徵，換回去要一併改 FEATURES）。
MODEL_PATH = BASE_DIR / "saved_models" / "nfstream_xgb_refined7_ftop10_20261116.joblib"
MODEL_NAME = MODEL_PATH.name

pack = joblib.load(MODEL_PATH)
model = pack['model']
label_encoder = pack['label_encoder']
feature_names = list(pack['feature_names'])
X_train = pack['validation_data']['X']          # LIME 背景樣本與消融用的中位數
class_names = list(pack['class_names'])
class_bias = np.asarray(pack.get('class_bias', np.zeros(len(class_names))), dtype=float)
# CICIoT2023 子類別 → 模型類別（例如 SqlInjection → Web-based），CSV 的 label 欄用它對應
category_map = dict(pack.get('category_map', {}))

# 模型必須用和即時擷取相同的 nfstream 參數與特徵訓練，否則預測沒有意義。
if feature_names != FEATURES:
    raise RuntimeError(f"模型的特徵和 stream/flow_features.py 的 FEATURES 不同：\n"
                       f"  模型: {feature_names}\n  程式: {FEATURES}")
if pack.get('nfstream_params') != NFSTREAM_PARAMS:
    raise RuntimeError(f"模型的 nfstream 參數和 stream/flow_features.py 的 NFSTREAM_PARAMS 不同：\n"
                       f"  模型: {pack.get('nfstream_params')}\n  程式: {NFSTREAM_PARAMS}")
