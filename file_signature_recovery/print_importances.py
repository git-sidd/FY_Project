import sys
import os
import pickle

PROJECT_ROOT = r"c:\Users\siddh\OneDrive\Desktop\FY_Project\file_signature_recovery"
sys.path.append(PROJECT_ROOT)

from models.xgboost_pipeline import FileSignatureXGBoost

xgb_model = FileSignatureXGBoost()
xgb_model.load(os.path.join(PROJECT_ROOT, "saved_models"))

features = xgb_model.xgb_type.feature_importances_
print("Top 10 Feature Importances:")
indices = features.argsort()[::-1]
# We don't have the exact names easily accessible here, but let's just see indices
for i in range(20):
    print(f"Feature Index {indices[i]}: {features[indices[i]]:.4f}")
