import os
import json
import numpy as np
import pickle
import matplotlib.pyplot as plt
import seaborn as sns
import seaborn as sns
def tqdm(iterable, *args, **kwargs):
    return iterable
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.metrics import accuracy_score, f1_score, roc_curve, auc, confusion_matrix
import shap
import xgboost as xgb

from models.cnn_model import FileSignatureCNN
from models.xgboost_pipeline import FileSignatureXGBoost
from utils.feature_engineering import FeatureEngineer, N_SIGNATURES

def save_confusion_matrix(y_true, y_pred, labels, filename):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix - Hybrid Model (File Type)')
    plt.ylabel('True Class')
    plt.xlabel('Predicted Class')
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def save_roc_curve(y_true, y_probs, filename):
    fpr, tpr, _ = roc_curve(y_true, y_probs)
    roc_auc = auc(fpr, tpr)
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC = {roc_auc:.3f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('Receiver Operating Characteristic - Malware Detection')
    plt.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def save_training_curve(history, filename):
    plt.figure(figsize=(12, 4))
    
    # Accuracy plot
    plt.subplot(1, 2, 1)
    if 'file_type_output_accuracy' in history.history:
        acc_key = 'file_type_output_accuracy'
        val_acc_key = 'val_file_type_output_accuracy'
    else:
        acc_key = 'accuracy'
        val_acc_key = 'val_accuracy'
        
    plt.plot(history.history[acc_key], label='Train Acc')
    if val_acc_key in history.history:
        plt.plot(history.history[val_acc_key], label='Val Acc')
    plt.title('Model Accuracy')
    plt.ylabel('Accuracy')
    plt.xlabel('Epoch')
    plt.legend()
    
    # Loss plot
    plt.subplot(1, 2, 2)
    plt.plot(history.history['loss'], label='Train Loss')
    if 'val_loss' in history.history:
        plt.plot(history.history['val_loss'], label='Val Loss')
    plt.title('Model Total Loss')
    plt.ylabel('Loss')
    plt.xlabel('Epoch')
    plt.legend()
    
    plt.tight_layout()
    plt.savefig(filename)
    plt.close()

def save_shap_summary(xgb_model, X, feature_names, filename):
    try:
        # Select subset for shap so it doesn't take forever
        X_sample = X[:min(500, len(X))]
        explainer = shap.TreeExplainer(xgb_model)
        shap_values = explainer.shap_values(X_sample)
        
        plt.figure(figsize=(10, 8))
        # SHAP summary plot for multi-class generates a layered bar plot automatically.
        shap.summary_plot(shap_values, X_sample, feature_names=feature_names, show=False, plot_type="bar")
        plt.tight_layout()
        plt.savefig(filename)
        plt.close()
        print(f"    [OK] SHAP summary saved to {filename}")
    except Exception as e:
        print(f"    [!] Skipping SHAP summary: Interpretation library error ({e})")
        plt.close()

def main():
    os.makedirs('saved_models', exist_ok=True)
    os.makedirs('outputs', exist_ok=True)
    
    print("="*60)
    print("  File Signature Recovery & Analysis - ML Training Orchestration")
    print("="*60)
    
    # ── 1. Load Dataset ──────────────────────────────────────────
    print("\n[1] Loading dataset...")
    X = np.load('dataset/dataset.npy') # (N, 512)
    with open('dataset/dataset_meta.json', 'r') as f:
        meta = json.load(f)
    
    y_type = [m['true_file_type'] for m in meta]
    y_malware = [int(m['is_malicious']) for m in meta]
    y_label = np.load('dataset/dataset_labels.npy') # (N,) array
    
    print(f"    Loaded {X.shape[0]} samples of shape {X.shape[1]}")

    # ── 2. Encode Labels ─────────────────────────────────────────
    print("\n[2] Encoding labels...")
    le = LabelEncoder()
    y_type_enc = le.fit_transform(y_type)
    num_file_types = len(le.classes_)
    
    with open('saved_models/label_encoder.pkl', 'wb') as f:
        pickle.dump(le, f)
        
    y_type_onehot = OneHotEncoder(sparse_output=False).fit_transform(y_type_enc.reshape(-1, 1))
    y_malware_np = np.array(y_malware, dtype=np.float32)

    # ── 3. Stratified Split ──────────────────────────────────────
    print("\n[3] Splitting dataset...")
    # 70% train, 30% temp
    X_train, X_temp, y_type_enc_tr, y_type_enc_tmp, y_type_oh_tr, y_type_oh_tmp, y_malware_tr, y_malware_tmp, y_label_tr, y_label_tmp = train_test_split(
        X, y_type_enc, y_type_onehot, y_malware_np, y_label, 
        test_size=0.3, stratify=y_label, random_state=42
    )
    # 15% val, 15% test (which is 50% of 30%)
    X_val, X_test, y_type_enc_va, y_type_enc_te, y_type_oh_va, y_type_oh_te, y_malware_va, y_malware_te, _, _ = train_test_split(
        X_temp, y_type_enc_tmp, y_type_oh_tmp, y_malware_tmp, y_label_tmp,
        test_size=0.5, stratify=y_label_tmp, random_state=42
    )

    print(f"    Train: {len(X_train)}  |  Val: {len(X_val)}  |  Test: {len(X_test)}")

    # ── 4. Train CNN ─────────────────────────────────────────────
    print("\n[4] Training Dual-Head CNN (Fast Mode)...")
    cnn = FileSignatureCNN()
    cnn.build(num_file_types=num_file_types)
    history = cnn.train(
        X_train, y_type_oh_tr, y_malware_tr,
        X_val,   y_type_oh_va, y_malware_va,
        epochs=3,    # reduced for rapid execution
        batch_size=64
    )
    cnn.save('saved_models/cnn_model.keras')

    # Evaluate CNN alone for table
    cnn_eval = cnn.evaluate(X_test, y_type_oh_te, y_malware_te)
    cnn_acc = cnn_eval['file_type_accuracy'] * 100
    cnn_f1  = cnn_eval['file_type_f1']

    # ── 5. Extract CNN features ──────────────────────────────────
    print("\n[5] Extracting CNN Features...")
    cnn_train_feats = cnn.extract_features(X_train)
    cnn_val_feats   = cnn.extract_features(X_val)
    cnn_test_feats  = cnn.extract_features(X_test)
    print(f"    CNN Feature shape: {cnn_train_feats.shape[1]}")

    # ── 6. Extract Handcrafted features ──────────────────────────
    print("\n[6] Extracting Handcrafted Features...")
    fe = FeatureEngineer()
    
    def extract_hc(data, desc):
        # We can't easily process array loop with fast numpy operations so we iterate
        feats = []
        for x in tqdm(data, desc=desc):
            feats.append(fe.extract_all(x))
        return np.array(feats, dtype=np.float32)

    hc_train = extract_hc(X_train, "Train")
    hc_val   = extract_hc(X_val, "  Val")
    hc_test  = extract_hc(X_test, " Test")
    print(f"    Handcrafted Feature shape: {hc_train.shape[1]}")

    # XGBoost alone evaluation (train standalone XGBoost on hc_features)
    print("\n[.] Training XGBoost alone for comparison...")
    xgb_alone = xgb.XGBClassifier(n_estimators=100, max_depth=6, learning_rate=0.1, n_jobs=-1, random_state=42)
    xgb_alone.fit(hc_train, y_type_enc_tr)
    y_pred_alone = xgb_alone.predict(hc_test)
    xgb_alone_acc = accuracy_score(y_type_enc_te, y_pred_alone) * 100
    xgb_alone_f1 = f1_score(y_type_enc_te, y_pred_alone, average='weighted', zero_division=0)

    # ── 7. Train Hybrid XGBoost ──────────────────────────────────
    print("\n[7] Training Hybrid XGBoost (CNN + Handcrafted)...")
    xgb_hybrid = FileSignatureXGBoost()
    xgb_hybrid.build(num_file_types)
    xgb_hybrid.train(cnn_train_feats, hc_train, y_type_enc_tr, y_malware_tr)
    xgb_hybrid.save('saved_models/')

    # Evaluate Hybrid
    # We predict manually on test to get metrics
    X_hybrid_test = np.concatenate([cnn_test_feats, hc_test], axis=1)
    
    hybrid_type_preds = xgb_hybrid.xgb_type.predict(X_hybrid_test)
    hybrid_acc = accuracy_score(y_type_enc_te, hybrid_type_preds) * 100
    hybrid_f1 = f1_score(y_type_enc_te, hybrid_type_preds, average='weighted', zero_division=0)
    
    malware_probs = xgb_hybrid.xgb_malware.predict_proba(X_hybrid_test)[:, 1]

    # Calculate AUC
    fpr, tpr, _ = roc_curve(y_malware_te, malware_probs)
    malware_auc = auc(fpr, tpr)

    # ── 8. Generate and Save Plots ───────────────────────────────
    print("\n[8] Generating evaluation plots to outputs/ folder...")
    
    save_confusion_matrix(y_type_enc_te, hybrid_type_preds, le.classes_, 'outputs/confusion_matrix.png')
    save_roc_curve(y_malware_te, malware_probs, 'outputs/roc_curve.png')
    save_training_curve(history, 'outputs/cnn_training_history.png')
    
    # Generate feature names for SHAP
    cnn_names = [f"cnn_feature_{i}" for i in range(256)]  # Updated to match new CNN output
    hc_base_names = (
        ["entropy"]
        + [f"byte_hist_{i}" for i in range(256)]
        + ["null_ratio", "printable_ratio"]
        + [f"magic_b_{i}" for i in range(16)]
    )
    from dataset.signatures import SIGNATURES as _SIGS
    sig_names = [f"sig_match_{name}" for name in sorted(_SIGS.keys())]
    # Add the 6 new engineered features
    engineered_names = [
        "byte_freq_variance",
        "byte_value_range",
        "byte_value_mean",
        "byte_value_std",
        "control_char_ratio",
        "high_entropy_ratio"
    ]
    hc_names = hc_base_names + sig_names + engineered_names
    feature_names = cnn_names + hc_names
    
    print("    Running SHAP explainer (this may take a few seconds)...")
    X_hybrid_train = np.concatenate([cnn_train_feats, hc_train], axis=1)
    
    # Verify feature names match actual features
    if len(feature_names) == X_hybrid_train.shape[1]:
        save_shap_summary(xgb_hybrid.xgb_type, X_hybrid_train, feature_names, 'outputs/shap_summary.png')
    else:
        print(f"    WARNING: Feature names mismatch! Expected {X_hybrid_train.shape[1]}, got {len(feature_names)}")
        print(f"    Skipping SHAP summary plot...")

    # ── 9. Print Final Table ─────────────────────────────────────
    print("\n" + "+" + "-"*29 + "+" + "-"*10 + "+" + "-"*10 + "+" + "-"*10 + "+")
    print("| {:<27} | {:^8} | {:^8} | {:^8} |".format("Model", "Accuracy", "F1 Score", "AUC"))
    print("+" + "-"*29 + "+" + "-"*10 + "+" + "-"*10 + "+" + "-"*10 + "+")
    print("| {:<27} | {:>7.2f}% | {:>8.3f} | {:^8} |".format("CNN alone (file type)", cnn_acc, cnn_f1, "N/A"))
    print("| {:<27} | {:>7.2f}% | {:>8.3f} | {:^8} |".format("XGBoost alone (file type)", xgb_alone_acc, xgb_alone_f1, "N/A"))
    print("| {:<27} | {:>7.2f}% | {:>8.3f} | {:^8} |".format("CNN + XGBoost hybrid", hybrid_acc, hybrid_f1, "N/A"))
    print("| {:<27} | {:^8} | {:^8} | {:>8.3f} |".format("Malware detection (AUC)", "N/A", "N/A", malware_auc))
    print("+" + "-"*29 + "+" + "-"*10 + "+" + "-"*10 + "+" + "-"*10 + "+")

    import datetime
    results = {
        "cnn_accuracy": float(cnn_acc),
        "cnn_f1": float(cnn_f1),
        "xgb_accuracy": float(xgb_alone_acc),
        "xgb_f1": float(xgb_alone_f1),
        "hybrid_accuracy": float(hybrid_acc),
        "hybrid_f1": float(hybrid_f1),
        "malware_auc": float(malware_auc),
        "trained_at": datetime.datetime.now().isoformat(),
        "total_samples": int(X.shape[0]),
        "num_file_types": int(num_file_types)
    }
    with open('outputs/evaluation_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("\n[OK] Saved evaluation results to outputs/evaluation_results.json")

if __name__ == "__main__":
    os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2" # silence TF compilation warnings
    main()
