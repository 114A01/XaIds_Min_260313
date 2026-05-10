#import const from this file

import joblib
from pathlib import Path

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
MODEL_DIR = "./saved_models/"

REPLAY_LIMIT = 100

CONFIDENCE_LOW  = 0.6    # < 0.6  → UNCERTAIN
CONFIDENCE_HIGH = 0.85   # ≥ 0.85 → HIGH_CONF，否則 SUSPICIOUS

pack = joblib.load('/mnt/c/Users/pccu1/Desktop/randomforest/models/complete_model_20260508_210127.joblib')
model = pack['model']
label_encoder = pack['label_encoder']
feature_names = pack['feature_names']
X_train = pack['validation_data']['X']
class_names = pack['label_encoder'].classes_