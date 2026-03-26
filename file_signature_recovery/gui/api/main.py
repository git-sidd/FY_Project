import os
import sys
import time
import pickle
import numpy as np
from typing import List, Dict, Any
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add project root to sys.path to allow importing from models/ utils/
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(PROJECT_ROOT)

from models.cnn_model import FileSignatureCNN
from models.xgboost_pipeline import FileSignatureXGBoost
from utils.feature_engineering import FeatureEngineer

app = FastAPI(title="File Signature Analysis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AppState:
    cnn_model = None
    xgb_model = None
    feature_engineer = None
    label_decoder = None
    feature_names = []

class ByteRequest(BaseModel):
    bytes: List[int]
    filename: str

def generate_feature_names() -> List[str]:
    """Generate exact feature names matching the full feature vector order."""
    from dataset.signatures import SIGNATURES as _SIGS

    # 256 CNN features (matches feature_layer in models/cnn_model.py)
    names = [f"cnn_feature_{i}" for i in range(256)]
    
    # 275 base handcrafted features
    names.append("entropy")
    names.extend([f"byte_histogram_{i}" for i in range(256)])
    names.append("null_byte_ratio")
    names.append("printable_ascii_ratio")
    names.extend([f"magic_byte_{i}" for i in range(16)])
    
    # N_SIGNATURES signature match scores
    names.extend([f"sig_match_{n}" for n in sorted(_SIGS.keys())])
    
    # 6 new engineered features (matches utils/feature_engineering.py)
    names.extend([
        "byte_freq_variance",
        "byte_value_range",
        "byte_value_mean",
        "byte_value_std",
        "control_char_ratio",
        "high_entropy_ratio"
    ])
    
    return names

@app.on_event("startup")
async def startup_event():
    AppState.feature_names = generate_feature_names()
    
    # Load CNN
    AppState.cnn_model = FileSignatureCNN()
    AppState.cnn_model.load(os.path.join(PROJECT_ROOT, "saved_models", "cnn_model.keras"))
    
    # Load XGBoost Process
    AppState.xgb_model = FileSignatureXGBoost()
    AppState.xgb_model.load(os.path.join(PROJECT_ROOT, "saved_models"))
    
    # Feature Engineer
    AppState.feature_engineer = FeatureEngineer()
    
    # Load Label Encoder
    le_path = os.path.join(PROJECT_ROOT, "saved_models", "label_encoder.pkl")
    if os.path.exists(le_path):
        with open(le_path, "rb") as f:
            le = pickle.load(f)
            AppState.label_decoder = le.classes_
    else:
        # Fallback
        AppState.label_decoder = [f"Type_{i}" for i in range(100)]
        
    print("Models loaded successfully")

def process_file_bytes(file_bytes: bytes, filename: str, file_size_bytes: int):
    t0 = time.time()
    
    arr = list(file_bytes)
    # Pad to 512 bytes with zeros if shorter
    if len(arr) < 512:
        arr.extend([0] * (512 - len(arr)))
    arr = arr[:512]
    
    # 1. Feature Extraction (CNN)
    X_cnn_input = np.array([arr], dtype=np.float32)
    cnn_features = AppState.cnn_model.extract_features(X_cnn_input)
    
    # 2. Feature Extraction (Handcrafted)
    fe_features = AppState.feature_engineer.extract_all(bytes(arr))
    X_handcrafted = np.array([fe_features], dtype=np.float32)
    
    # 3. XGBoost Predict
    predict_res = AppState.xgb_model.predict(cnn_features, X_handcrafted, AppState.label_decoder)
    
    # 4. XGBoost Explanations (SHAP)
    # Ensure feature names match the current feature vector length. If they don't,
    # try to regenerate them or fall back to generated placeholder names.
    try:
        expected_len = int(cnn_features.shape[1] + X_handcrafted.shape[1])
    except Exception:
        expected_len = None

    if expected_len is not None and len(AppState.feature_names) != expected_len:
        try:
            AppState.feature_names = generate_feature_names()
        except Exception:
            # Fallback: create placeholder feature names to avoid index errors
            AppState.feature_names = [f"feature_{i}" for i in range(expected_len)]

    top_shap_features = []
    try:
        shap_res = AppState.xgb_model.explain(cnn_features, X_handcrafted, AppState.feature_names)
        top_shap_features = [{"feature": f, "value": v} for f, v in shap_res.get("top_features", [])]
    except Exception as e:
        # Don't let SHAP failures break the analysis API. Log and continue with empty SHAP output.
        print(f"Warning: SHAP explanation failed: {e}")
    
    # 5. Probabilities & Histogram
    X_full = np.concatenate([cnn_features, X_handcrafted], axis=1)
    # predict_proba returns matrix -> [0] for single sample
    type_probs = AppState.xgb_model.xgb_type.predict_proba(X_full)[0] 
    
    confidence_per_type = {
        AppState.label_decoder[i]: float(type_probs[i]) 
        for i in range(len(AppState.label_decoder)) 
        if i < len(type_probs)
    }
    
    label_idx = int(np.argmax(type_probs))
    hist = AppState.feature_engineer.byte_histogram(bytes(arr)).tolist()
    declared_ext = os.path.splitext(filename)[1].lower() if filename else ""
    
    t1 = time.time()
    
    return {
        "filename": filename,
        "file_size_bytes": file_size_bytes,
        "declared_extension": declared_ext,
        "predicted_file_type": predict_res["file_type"],
        "file_type_confidence": predict_res["file_type_confidence"],
        "malware_risk_score": predict_res["malware_risk_score"],
        "risk_level": predict_res["risk_level"],
        "signature_tampered": predict_res["signature_tampered"],
        "label": label_idx,
        "label_name": predict_res["file_type"],
        "top_shap_features": top_shap_features,
        "byte_histogram": hist,
        "confidence_per_type": confidence_per_type,
        "analysis_time_ms": int((t1 - t0) * 1000)
    }

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    # Read up to the required 512 bytes for extraction
    content = await file.read(512)
    
    # Determine full original file size
    file.file.seek(0, 2) # Move to EOF
    file_size_bytes = file.file.tell()
    
    return process_file_bytes(content, file.filename, file_size_bytes)

@app.post("/analyze-bytes")
async def analyze_bytes(req: ByteRequest):
    return process_file_bytes(bytes(req.bytes[:512]), req.filename, len(req.bytes))

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "models_loaded": AppState.cnn_model is not None,
        "version": "1.0.0"
    }

@app.get("/supported-types")
async def supported_types():
    return list(AppState.label_decoder) if AppState.label_decoder is not None else []
