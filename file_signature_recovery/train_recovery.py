"""
train_recovery.py — Train the CNN+LSTM Hybrid Recovery Model
==============================================================

Usage:
    python train_recovery.py
"""

import os
import sys
import json
import numpy as np
import pickle

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.metrics import accuracy_score, f1_score

from models.hybrid_recovery_model import HybridRecoveryModel
from models.lstm_model import FileSignatureLSTM


def main():
    os.makedirs("saved_models", exist_ok=True)
    os.makedirs("outputs", exist_ok=True)

    print("=" * 65)
    print("  File Recovery System — CNN+LSTM Hybrid Training")
    print("=" * 65)

    # ── 1. Load Dataset ──
    print("\n[1] Loading dataset...")
    X = np.load("dataset/dataset.npy")  # (N, 512)
    with open("dataset/dataset_meta.json", "r") as f:
        meta = json.load(f)

    y_type = [m["true_file_type"] for m in meta]
    y_malware = [int(m["is_malicious"]) for m in meta]
    y_label = np.load("dataset/dataset_labels.npy")

    print(f"    Loaded {X.shape[0]} samples, shape {X.shape[1]}")

    # ── 2. Encode Labels ──
    print("\n[2] Encoding labels...")
    le = LabelEncoder()
    y_type_enc = le.fit_transform(y_type)
    num_types = len(le.classes_)
    print(f"    {num_types} file types: {list(le.classes_[:10])}...")

    with open("saved_models/label_encoder.pkl", "wb") as f:
        pickle.dump(le, f)

    y_type_onehot = OneHotEncoder(sparse_output=False).fit_transform(y_type_enc.reshape(-1, 1))
    y_malware_np = np.array(y_malware, dtype=np.float32)

    # ── 3. Split ──
    print("\n[3] Splitting dataset (70/15/15)...")
    X_train, X_temp, y_oh_tr, y_oh_tmp, y_mal_tr, y_mal_tmp, y_enc_tr, y_enc_tmp = train_test_split(
        X, y_type_onehot, y_malware_np, y_type_enc,
        test_size=0.3, stratify=y_label, random_state=42,
    )
    X_val, X_test, y_oh_va, y_oh_te, y_mal_va, y_mal_te, y_enc_va, y_enc_te = train_test_split(
        X_temp, y_oh_tmp, y_mal_tmp, y_enc_tmp,
        test_size=0.5, random_state=42,
    )
    print(f"    Train: {len(X_train)} | Val: {len(X_val)} | Test: {len(X_test)}")

    # ── 4. Train LSTM alone ──
    print("\n[4] Training LSTM model (3 epochs fast mode)...")
    lstm = FileSignatureLSTM()
    lstm.build(num_file_types=num_types)

    X_train_f = X_train.astype(np.float32)
    X_val_f = X_val.astype(np.float32)
    X_test_f = X_test.astype(np.float32)

    lstm.train(X_train_f, y_oh_tr, y_mal_tr, X_val_f, y_oh_va, y_mal_va, epochs=3, batch_size=64)
    lstm.save("saved_models/lstm_model.keras")

    lstm_eval = lstm.evaluate(X_test_f, y_oh_te, y_mal_te)
    lstm_acc = lstm_eval["file_type_accuracy"] * 100
    lstm_f1 = lstm_eval["file_type_f1"]
    print(f"    LSTM alone: {lstm_acc:.2f}% accuracy, F1={lstm_f1:.3f}")

    # ── 5. Train Hybrid CNN+LSTM ──
    print("\n[5] Training Hybrid CNN+LSTM model (3 epochs fast mode)...")
    hybrid = HybridRecoveryModel()
    hybrid.build(num_file_types=num_types)

    hybrid.train(X_train_f, y_oh_tr, y_mal_tr, X_val_f, y_oh_va, y_mal_va, epochs=3, batch_size=64)
    hybrid.save("saved_models/hybrid_recovery_model.keras")

    hybrid_eval = hybrid.evaluate(X_test_f, y_oh_te, y_mal_te)
    hybrid_acc = hybrid_eval["file_type_accuracy"] * 100
    hybrid_f1 = hybrid_eval["file_type_f1"]
    print(f"    Hybrid CNN+LSTM: {hybrid_acc:.2f}% accuracy, F1={hybrid_f1:.3f}")

    # ── 6. Print Results Table ──
    print("\n" + "+" + "-" * 34 + "+" + "-" * 12 + "+" + "-" * 10 + "+")
    print("| {:^32} | {:^10} | {:^8} |".format("Model", "Accuracy", "F1"))
    print("+" + "-" * 34 + "+" + "-" * 12 + "+" + "-" * 10 + "+")
    print("| {:^32} | {:>9.2f}% | {:>8.3f} |".format("LSTM alone", lstm_acc, lstm_f1))
    print("| {:^32} | {:>9.2f}% | {:>8.3f} |".format("CNN+LSTM Hybrid (Recovery)", hybrid_acc, hybrid_f1))
    print("+" + "-" * 34 + "+" + "-" * 12 + "+" + "-" * 10 + "+")

    # ── 7. Save results ──
    import datetime
    results = {
        "lstm_accuracy": float(lstm_acc),
        "lstm_f1": float(lstm_f1),
        "hybrid_accuracy": float(hybrid_acc),
        "hybrid_f1": float(hybrid_f1),
        "num_file_types": int(num_types),
        "total_samples": int(X.shape[0]),
        "trained_at": datetime.datetime.now().isoformat(),
    }
    with open("outputs/recovery_training_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print("\n[OK] Models saved to saved_models/")
    print("[OK] Results saved to outputs/recovery_training_results.json")
    print("\nTraining complete! You can now run:")
    print("  python recover.py \"path/to/folder\"")


if __name__ == "__main__":
    main()
