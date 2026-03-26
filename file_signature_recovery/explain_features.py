import sys
import os
import json
import numpy as np

PROJECT_ROOT = r"c:\Users\siddh\OneDrive\Desktop\FY_Project\file_signature_recovery"
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from models.xgboost_pipeline import FileSignatureXGBoost
from utils.feature_engineering import FeatureEngineer, _SIG_ENTRIES

# 1. Load model
xgb_model = FileSignatureXGBoost()
xgb_model.load(os.path.join(PROJECT_ROOT, "saved_models"))

# 2. Re-create feature names list
CNN_FEATURE_COUNT = 128
feature_names = [f"CNN_feature_{i}" for i in range(CNN_FEATURE_COUNT)]
feature_names.append("shannon_entropy")
feature_names.extend([f"histogram_byte_{i}" for i in range(256)])
feature_names.append("null_byte_ratio")
feature_names.append("printable_ascii_ratio")
feature_names.extend([f"raw_byte_{i}" for i in range(16)])
feature_names.extend([f"sig_match_{name}" for name, _, _, _, _ in _SIG_ENTRIES])

# 3. Get importance
importances = xgb_model.xgb_type.feature_importances_
indices = np.argsort(importances)[::-1]

print(f"Total features: {len(importances)}")
print("\nTop 20 Most Important Features:")
print("-" * 50)
for i in range(20):
    idx = indices[i]
    if idx < len(feature_names):
        name = feature_names[idx]
    else:
        name = f"Unknown_Index_{idx}"
    print(f"{i+1:2d}. {name:<40} {importances[idx]:.4f}")
