"""
predict.py
==========

Inference module for file type identification, anomaly analysis, and malware detection.
"""

import sys
import os
import json
import argparse
import numpy as np

from models.xgboost_pipeline import XGBoostPipeline
from models.cnn_model import FileSignatureCNN

# Load label mappings
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAPPING_FILE = os.path.join(SCRIPT_DIR, "saved_models", "file_types_mapping.json")
XGB_MODEL_PATH = os.path.join(SCRIPT_DIR, "saved_models", "xgboost_pipeline.pkl")
CNN_MODEL_PATH = os.path.join(SCRIPT_DIR, "saved_models", "cnn_model.keras")

def load_file_bytes(filepath: str, sample_size: int = 512) -> np.ndarray:
    try:
        with open(filepath, 'rb') as f:
            data = f.read(sample_size)
        
        # Pad with zeros if shorter than 512 bytes
        if len(data) < sample_size:
            data += b"\x00" * (sample_size - len(data))
            
        return np.array([list(data)], dtype=np.uint8) # (1, 512) array of bytes
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Analyze file signature and detect anomalies/malware")
    parser.add_argument("file", type=str, help="Path to the file to analyze")
    args = parser.parse_args()

    filepath = args.file
    if not os.path.isfile(filepath):
        print(f"Error: File '{filepath}' does not exist.")
        sys.exit(1)
        
    print(f"\nAnalyzing file: {filepath}")
    
    # ── 1. Load Byte Array ─────────────────────────────────────
    X_bytes = load_file_bytes(filepath, 512)
    
    # ── 2. Run XGBoost Anomaly Classifier ──────────────────────
    print("  * Running Structural Anomaly Detection (XGBoost)...")
    xgb_pipeline = XGBoostPipeline()
    try:
        xgb_pipeline.load(XGB_MODEL_PATH)
        xgb_preds = xgb_pipeline.predict(X_bytes)
        # 0=valid, 1=corrupt, 2=mismatch
        anomaly_map = {0: "VALID", 1: "CORRUPTED", 2: "MISMATCH/DISGUISED"}
        
        pred_label_idx = xgb_preds[0]
        print(f"    Anomaly Status : {anomaly_map.get(pred_label_idx, 'UNKNOWN')}")
    except Exception as e:
        print(f"    [XGBoost Skipped] {e}")

    # ── 3. Run CNN File Type & Malware Detection ───────────────
    print("  * Running CNN File Type & Malware Detection...")
    cnn = FileSignatureCNN()
    try:
        # Load label mapping
        with open(MAPPING_FILE, 'r') as f:
            mapping = json.load(f)
            
        cnn.load(CNN_MODEL_PATH)
        preds = cnn.model.predict(X_bytes, verbose=0)
        
        type_probs = preds[0][0]
        malware_prob = preds[1][0][0]
        
        pred_class_idx = np.argmax(type_probs)
        pred_type = mapping.get(str(pred_class_idx), "UNKNOWN")
        confidence = type_probs[pred_class_idx] * 100
        
        print(f"    File Type      : {pred_type} (Confidence: {confidence:.2f}%)")
        print(f"    Malware Risk   : {'HIGH' if malware_prob >= 0.5 else 'LOW'} (Score: {malware_prob:.4f})")
    except Exception as e:
        print(f"    [CNN Skipped] {e}")

    print("\nAnalysis Complete!\n")

if __name__ == "__main__":
    # Ensure TF doesn't grab all VRAM if running locally with GPU
    os.environ["TF_FORCE_GPU_ALLOW_GROWTH"] = "true"
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
    main()
