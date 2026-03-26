import os
import numpy as np
import xgboost as xgb
import shap

class FileSignatureXGBoost:
    """Hybrid XGBoost model utilizing CNN and handcrafted representations."""
    
    def __init__(self):
        self.xgb_type = None
        self.xgb_malware = None

    def build(self, num_file_types):
        """Creates TWO XGBoost models with optimized hyperparameters."""
        self.xgb_type = xgb.XGBClassifier(
            n_estimators=600,
            max_depth=8,
            learning_rate=0.03,
            subsample=0.8,
            colsample_bytree=0.8,
            colsample_bylevel=0.85,
            min_child_weight=2,
            gamma=1.0,
            reg_alpha=0.1,
            reg_lambda=1.0,
            objective="multi:softprob",
            num_class=num_file_types,
            use_label_encoder=False,
            eval_metric="mlogloss",
            n_jobs=-1,
            random_state=42,
            tree_method="hist",
            predictor="auto"
        )
        
        self.xgb_malware = xgb.XGBClassifier(
            n_estimators=500,
            max_depth=7,
            learning_rate=0.03,
            subsample=0.8,
            colsample_bytree=0.8,
            colsample_bylevel=0.85,
            min_child_weight=2,
            gamma=0.5,
            reg_alpha=0.1,
            reg_lambda=1.0,
            objective="binary:logistic",
            scale_pos_weight=1,  # Updated dynamically in train()
            eval_metric="logloss",
            n_jobs=-1,
            random_state=42,
            tree_method="hist",
            predictor="auto"
        )

    def train(self, cnn_features, handcrafted_features, y_type, y_malware):
        """Trains models on concatenated (CNN + handcrafted) features."""
        from sklearn.utils.class_weight import compute_sample_weight

        # Concatenate features (N, 128+) + (N, 275+) -> (N, combined)
        X = np.concatenate([cnn_features, handcrafted_features], axis=1)

        # ── Balanced sample weights for file-type classifier ──────
        # Prevents high-sample-count classes (or distinctive ones like SQLITE)
        # from dominating tree splits.
        type_sample_weights = compute_sample_weight(class_weight="balanced", y=y_type)

        # ── Class imbalance weight for malware head ───────────────
        num_neg = np.sum(y_malware == 0)
        num_pos = np.sum(y_malware == 1)
        scale_pos_weight = num_neg / num_pos if num_pos > 0 else 1.0
        self.xgb_malware.set_params(scale_pos_weight=scale_pos_weight)

        print(f"    Fit xgb_type on shape {X.shape}...")
        self.xgb_type.fit(X, y_type, sample_weight=type_sample_weights)

        print(f"    Fit xgb_malware on shape {X.shape}...")
        self.xgb_malware.fit(X, y_malware)

        return self.xgb_type, self.xgb_malware

    def predict(self, cnn_features, handcrafted_features, label_decoder=None):
        """Predicts file type and malware risk score."""
        X = np.concatenate([cnn_features, handcrafted_features], axis=1)
        type_probs = self.xgb_type.predict_proba(X)
        malware_probs = self.xgb_malware.predict_proba(X)[:, 1]
        
        pred_type_idx = np.argmax(type_probs, axis=1)
        pred_type_conf = np.max(type_probs, axis=1)
        
        results = []
        for i in range(len(X)):
            label_str = str(pred_type_idx[i]) if label_decoder is None else label_decoder[pred_type_idx[i]]
            score = float(malware_probs[i])
            
            if score >= 0.7:
                risk = "HIGH"
            elif score >= 0.3:
                risk = "MEDIUM"
            else:
                risk = "LOW"
                
            results.append({
                "file_type": label_str,
                "file_type_confidence": float(pred_type_conf[i]),
                "malware_risk_score": score,
                "risk_level": risk,
                "signature_tampered": bool(pred_type_idx[i] == 2) # True if label==2 predicted
            })
            
        if len(results) == 1:
            return results[0]
        return results

    def explain(self, cnn_features, handcrafted_features, feature_names):
        """SHAP explanations for the file type XGBoost model."""
        X = np.concatenate([cnn_features, handcrafted_features], axis=1)
        explainer = shap.TreeExplainer(self.xgb_type)
        shap_values = explainer.shap_values(X)
        
        if isinstance(shap_values, list):
            # Multiclass SHAP values (legacy)
            mean_shap = np.mean([np.abs(sv).mean(0) for sv in shap_values], axis=0) # (num_features,)
        else:
            if len(shap_values.shape) == 3:
                # Modern SHAP: (samples, features, classes)
                mean_shap = np.abs(shap_values).mean(axis=(0, 2))
            else:
                mean_shap = np.abs(shap_values).mean(0) # (num_features,)
            
        top_indices = np.argsort(mean_shap)[::-1][:10]
        
        # Robustly map indices to feature names
        top_features = []
        for i in top_indices:
            idx = int(i)
            if idx < len(feature_names):
                name = feature_names[idx]
            else:
                name = f"unknown_feature_{idx}"
            top_features.append((name, float(mean_shap[idx])))
        
        summary = f"The top predicting feature is '{top_features[0][0]}' which effectively routes the file decision trees."
        return {
            "shap_values": shap_values, 
            "top_features": top_features,
            "summary": summary
        }

    def save(self, path='saved_models/'):
        os.makedirs(path, exist_ok=True)
        self.xgb_type.save_model(os.path.join(path, "xgb_type_model.json"))
        self.xgb_malware.save_model(os.path.join(path, "xgb_malware_model.json"))

    def load(self, path='saved_models/'):
        # Empty xgb models to load into
        self.xgb_type = xgb.XGBClassifier()
        self.xgb_type.load_model(os.path.join(path, "xgb_type_model.json"))
        
        self.xgb_malware = xgb.XGBClassifier()
        self.xgb_malware.load_model(os.path.join(path, "xgb_malware_model.json"))
