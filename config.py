#import const from this file

import joblib
from pathlib import Path

from stream.flow_features import FEATURES, NFSTREAM_PARAMS

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = "./saved_models/"

REPLAY_LIMIT = None

# Network capture settings
CAPTURE_IFACE = "eth0"        # network interface to sniff on
CAPTURE_FILTER = ""

CONFIDENCE_LOW  = 0.6    # < 0.6  → UNCERTAIN
CONFIDENCE_HIGH = 0.85   # ≥ 0.85 → HIGH_CONF，否則 SUSPICIOUS

# 暫時使用 nfstream 特徵訓練的測試模型。
# 舊模型（CICIoT2023 官方 CSV 的 46 個特徵）：
#   /mnt/c/Users/pccu1/Desktop/project-model/randomforest/models/complete_model_20260512_131827.joblib
# 換回舊模型前，stream/catcher.py 也要換回舊版特徵算法，否則特徵對不上。
MODEL_PATH = BASE_DIR / "saved_models" / "test_models" / "nfstream_xgb_20261109.joblib"

pack = joblib.load(MODEL_PATH)
model = pack['model']
label_encoder = pack['label_encoder']
feature_names = pack['feature_names']
X_train = pack['validation_data']['X']
class_names = list(pack['label_encoder'].classes_)

# 模型必須用和即時擷取相同的 nfstream 參數與特徵訓練，否則預測沒有意義。
if list(feature_names) != FEATURES:
    raise RuntimeError(f"模型的特徵和 stream/flow_features.py 的 FEATURES 不同：\n"
                       f"  模型: {list(feature_names)}\n  程式: {FEATURES}")
if pack.get('nfstream_params') != NFSTREAM_PARAMS:
    raise RuntimeError(f"模型的 nfstream 參數和 stream/flow_features.py 的 NFSTREAM_PARAMS 不同：\n"
                       f"  模型: {pack.get('nfstream_params')}\n  程式: {NFSTREAM_PARAMS}")
