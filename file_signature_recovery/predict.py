"""
predict.py
==========

Inference module for file type identification, anomaly analysis, and malware detection.
"""

import sys
import os
import pickle
import argparse
import numpy as np

from models.xgboost_pipeline import FileSignatureXGBoost
from models.cnn_model import FileSignatureCNN
from utils.feature_engineering import FeatureEngineer

# Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(SCRIPT_DIR, "saved_models")
CNN_MODEL_PATH = os.path.join(MODELS_DIR, "cnn_model.keras")
XGB_DIR = MODELS_DIR
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")

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
    
    # ── 2. Initialize Components ──────────────────────────────
    print("  * Initializing Models...")
    cnn = FileSignatureCNN()
    xgb_model = FileSignatureXGBoost()
    fe = FeatureEngineer()
    
    try:
        cnn.load(CNN_MODEL_PATH)
        xgb_model.load(XGB_DIR)
        
        # Load Label Decoder
        label_decoder = None
        if os.path.exists(LABEL_ENCODER_PATH):
            with open(LABEL_ENCODER_PATH, "rb") as f:
                le = pickle.load(f)
                label_decoder = le.classes_
        
        # ── 3. Feature Extraction ───────────────────────────────
        print("  * Extracting Features...")
        # CNN Features
        X_cnn_input = X_bytes.astype(np.float32)
        cnn_features = cnn.extract_features(X_cnn_input)
        
        # Handcrafted Features
        fe_features = fe.extract_all(X_bytes[0])
        X_handcrafted = np.array([fe_features], dtype=np.float32)
        
        # ── 4. Hybrid Prediction ───────────────────────────────
        print("  * Running Hybrid Analysis...")
        results = xgb_model.predict(cnn_features, X_handcrafted, label_decoder)
        
        # Display Results
        print("\n" + "="*40)
        print(f" ANALYSIS RESULTS: {os.path.basename(filepath)}")
        print("="*40)
        print(f"    Predicted File Type : {results['file_type']}")
        print(f"    Confidence Score    : {results['file_type_confidence']*100:.2f}%")
        print(f"    Malware Risk Score  : {results['malware_risk_score']:.4f}")
        print(f"    Risk Level          : {results['risk_level']}")
        
        if results['signature_tampered']:
            print("    [!] WARNING: Signature Tampering Detected (Corrupted/Mismatch)!")
        else:
            print("    [+] Signature appears valid/consistent.")
        print("="*40)

    except Exception as e:
        print(f"    Error during analysis: {e}")
        import traceback
        traceback.print_exc()

    print("\nAnalysis Complete!\n")

if __name__ == "__main__":
    # Ensure TF doesn't grab all VRAM if running locally with GPU
    os.environ["TF_FORCE_GPU_ALLOW_GROWTH"] = "true"
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
    main()
