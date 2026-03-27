import os
import sys
import time
import pickle
import json
import asyncio
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.append(PROJECT_ROOT)

from models.hybrid_recovery_model import HybridRecoveryModel
from models.cnn_model import FileSignatureCNN
from models.xgboost_pipeline import FileSignatureXGBoost
from utils.feature_engineering import FeatureEngineer
from recovery.scanner import FolderScanner
from recovery.disk_scanner import DiskScanner, RecycleBinScanner
from recovery.yara_scanner import YARAScanner
from recovery.reconstructor import FileReconstructor
from recovery.integrity import IntegrityVerifier

app = FastAPI(title="File Signature Recovery & Analysis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve web frontend
WEB_DIR = os.path.join(os.path.dirname(__file__), '..', 'web')
if os.path.exists(WEB_DIR):
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


# ════════════════════════════════════════════════════════
# Application State
# ════════════════════════════════════════════════════════

class AppState:
    hybrid_model = None
    cnn_model = None
    xgb_model = None
    feature_engineer = None
    label_decoder = None
    yara_scanner = None
    # Recovery state
    recovery_status = {"running": False, "progress": 0, "total": 0, "message": "", "results": []}


class RecoverRequest(BaseModel):
    path: str
    recursive: bool = True


# ════════════════════════════════════════════════════════
# Startup — Load Models
# ════════════════════════════════════════════════════════

@app.on_event("startup")
async def startup_event():
    models_dir = os.path.join(PROJECT_ROOT, "saved_models")

    # Load Hybrid Recovery Model
    hybrid_path = os.path.join(models_dir, "hybrid_recovery_model.keras")
    if os.path.exists(hybrid_path):
        AppState.hybrid_model = HybridRecoveryModel()
        AppState.hybrid_model.load(hybrid_path)

    # Load CNN Model
    cnn_path = os.path.join(models_dir, "cnn_model.keras")
    if os.path.exists(cnn_path):
        AppState.cnn_model = FileSignatureCNN()
        AppState.cnn_model.load(cnn_path)

    # Load XGBoost
    xgb_type_path = os.path.join(models_dir, "xgb_type_model.json")
    if os.path.exists(xgb_type_path):
        AppState.xgb_model = FileSignatureXGBoost()
        AppState.xgb_model.load(models_dir)

    # Feature Engineer
    AppState.feature_engineer = FeatureEngineer()

    # Label Decoder
    le_path = os.path.join(models_dir, "label_encoder.pkl")
    if os.path.exists(le_path):
        with open(le_path, "rb") as f:
            le = pickle.load(f)
            AppState.label_decoder = le.classes_
    else:
        AppState.label_decoder = [f"Type_{i}" for i in range(100)]

    # YARA Scanner
    AppState.yara_scanner = YARAScanner()

    print("=" * 50)
    print("  Models loaded successfully!")
    print(f"  Hybrid: {'✓' if AppState.hybrid_model else '✗'}")
    print(f"  CNN:    {'✓' if AppState.cnn_model else '✗'}")
    print(f"  XGB:    {'✓' if AppState.xgb_model else '✗'}")
    print(f"  YARA:   {'✓' if AppState.yara_scanner else '✗'}")
    print("=" * 50)


# ════════════════════════════════════════════════════════
# Web Frontend Route
# ════════════════════════════════════════════════════════

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    index_path = os.path.join(WEB_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Web frontend not found. Place index.html in gui/web/</h1>")


# ════════════════════════════════════════════════════════
# Single File Analysis
# ════════════════════════════════════════════════════════

@app.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    t0 = time.time()
    content = await file.read()
    file_size = len(content)

    # Pad/trim to 512 bytes
    header = content[:512]
    if len(header) < 512:
        header = header + b"\x00" * (512 - len(header))

    byte_array = np.frombuffer(header, dtype=np.uint8).copy()
    X = byte_array.astype(np.float32).reshape(1, -1)

    result = {"filename": file.filename, "file_size": file_size}

    # Hybrid model prediction
    if AppState.hybrid_model:
        pred = AppState.hybrid_model.predict_single(byte_array)
        pred_idx = pred["predicted_class_idx"]
        pred_type = AppState.label_decoder[pred_idx] if pred_idx < len(AppState.label_decoder) else f"Type_{pred_idx}"
        result.update({
            "predicted_type": pred_type,
            "confidence": round(pred["confidence"] * 100, 2),
            "malware_score": round(pred["malware_score"], 4),
            "risk_level": pred["risk_level"],
        })
    elif AppState.cnn_model and AppState.xgb_model:
        # Fallback to CNN+XGBoost
        cnn_feats = AppState.cnn_model.extract_features(X)
        hc_feats = np.array([AppState.feature_engineer.extract_all(byte_array)], dtype=np.float32)
        xgb_result = AppState.xgb_model.predict(cnn_feats, hc_feats, AppState.label_decoder)
        result.update({
            "predicted_type": xgb_result["file_type"],
            "confidence": round(xgb_result["file_type_confidence"] * 100, 2),
            "malware_score": round(xgb_result["malware_risk_score"], 4),
            "risk_level": xgb_result["risk_level"],
        })

    # YARA scan
    if AppState.yara_scanner:
        yara_result = AppState.yara_scanner.scan_bytes(content, file.filename)
        result["yara_threats"] = yara_result["threats"]
        result["yara_action"] = yara_result["action"]

    # Byte histogram
    result["byte_histogram"] = AppState.feature_engineer.byte_histogram(byte_array).tolist()

    result["analysis_time_ms"] = int((time.time() - t0) * 1000)
    return result


# ════════════════════════════════════════════════════════
# Folder Recovery
# ════════════════════════════════════════════════════════

@app.post("/recover")
async def start_recovery(req: RecoverRequest):
    if AppState.recovery_status["running"]:
        return {"error": "Recovery already in progress"}

    if not os.path.exists(req.path):
        return {"error": f"Path does not exist: {req.path}"}

    # Run recovery in background
    asyncio.create_task(_run_recovery(req.path, req.recursive))
    return {"status": "started", "path": req.path}


async def _run_recovery(path: str, recursive: bool):
    AppState.recovery_status = {"running": True, "progress": 0, "total": 0, "message": "Starting scan...", "results": []}

    try:
        scanner = FolderScanner(path, recursive=recursive)
        total = scanner.count_files()
        AppState.recovery_status["total"] = total

        yara_scanner = AppState.yara_scanner
        reconstructor = FileReconstructor(
            output_dir=os.path.join(PROJECT_ROOT, "recovered_files"),
            quarantine_dir=os.path.join(PROJECT_ROOT, "quarantine"),
        )

        results = []
        for i, candidate in enumerate(scanner.scan_generator(), 1):
            AppState.recovery_status["progress"] = i
            AppState.recovery_status["message"] = f"Analyzing {candidate['filename']}..."

            if candidate.get("error"):
                candidate["action"] = "error"
                candidate["predicted_type"] = "ERROR"
                candidate["confidence"] = 0
                candidate["malware_score"] = 0
                candidate["risk_level"] = "UNKNOWN"
                candidate.pop("byte_array", None)
                results.append(candidate)
                continue

            # AI Classification
            byte_array = candidate["byte_array"].astype(np.float32)
            if AppState.hybrid_model:
                pred = AppState.hybrid_model.predict_single(byte_array)
            else:
                pred = {"predicted_class_idx": 0, "confidence": 0.5, "malware_score": 0.1, "risk_level": "LOW"}

            pred_idx = pred["predicted_class_idx"]
            pred_type = AppState.label_decoder[pred_idx] if pred_idx < len(AppState.label_decoder) else f"Type_{pred_idx}"

            # YARA scan
            is_malicious = False
            yara_threats = []
            if yara_scanner:
                with open(candidate["filepath"], "rb") as f:
                    file_data = f.read()
                yara_result = yara_scanner.scan_bytes(file_data, candidate["filename"])
                is_malicious = yara_result["threat_detected"]
                yara_threats = yara_result["threats"]

            if pred["malware_score"] >= 0.7:
                is_malicious = True

            # Reconstruct
            recon = reconstructor.reconstruct(
                filepath=candidate["filepath"],
                predicted_type=pred_type,
                header_intact=not candidate["header_empty"],
                is_malicious=is_malicious,
                confidence=pred["confidence"],
            )

            entry = {
                "filename": candidate["filename"],
                "filepath": candidate["filepath"],
                "file_size": candidate["file_size"],
                "sha256": candidate["sha256"],
                "predicted_type": pred_type,
                "confidence": round(pred["confidence"] * 100, 2),
                "malware_score": round(pred["malware_score"], 4),
                "risk_level": pred["risk_level"],
                "yara_threats": yara_threats,
                "action": recon["action"],
                "repairs": recon.get("repairs", []),
                "output_path": recon.get("output_path", ""),
            }
            results.append(entry)

            AppState.recovery_status["results"] = results
            await asyncio.sleep(0.01)  # yield control

        # Generate report
        verifier = IntegrityVerifier(output_dir=os.path.join(PROJECT_ROOT, "outputs"))
        scan_summary = scanner.get_summary()
        recon_summary = reconstructor.get_summary()
        report = verifier.generate_report(results, scan_summary, recon_summary)
        verifier.save_report(report)

        AppState.recovery_status["message"] = "Recovery complete!"
        AppState.recovery_status["running"] = False
        AppState.recovery_status["report"] = report

    except Exception as e:
        AppState.recovery_status["message"] = f"Error: {str(e)}"
        AppState.recovery_status["running"] = False


@app.get("/recover/status")
async def recovery_status():
    return AppState.recovery_status


@app.get("/recover/results")
async def recovery_results():
    return {
        "results": AppState.recovery_status.get("results", []),
        "running": AppState.recovery_status.get("running", False),
    }


# ════════════════════════════════════════════════════════
# Utilities
# ════════════════════════════════════════════════════════

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "models": {
            "hybrid": AppState.hybrid_model is not None,
            "cnn": AppState.cnn_model is not None,
            "xgboost": AppState.xgb_model is not None,
            "yara": AppState.yara_scanner is not None,
        },
        "version": "2.0.0",
    }


@app.get("/supported-types")
async def supported_types():
    return list(AppState.label_decoder) if AppState.label_decoder is not None else []


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=7999, reload=False)
