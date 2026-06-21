"""
Hybrid CNN+LSTM Recovery Model
================================

Combines CNN (local byte patterns) with LSTM (sequential context)
and an Attention mechanism for file type classification and malware detection.
This is the primary model for the file recovery system.
"""

import os
import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model, callbacks
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import accuracy_score, f1_score


class HybridRecoveryModel:
    """CNN+LSTM hybrid with Attention for file recovery classification."""

    def __init__(self):
        self.model: Model | None = None
        self.feature_extractor: Model | None = None
        self._num_file_types: int = 0

    def build(self, num_file_types: int, seq_length: int = 512) -> Model:
        self._num_file_types = num_file_types

        inp = layers.Input(shape=(seq_length,), name="byte_input")

        # ════════════════════════════════════════════════════════
        # CNN BRANCH — Detects local byte patterns (magic bytes)
        # ════════════════════════════════════════════════════════
        cnn_x = layers.Reshape((seq_length, 1))(inp)
        cnn_x = layers.Lambda(lambda t: t / 255.0, name="cnn_normalize")(cnn_x)

        cnn_x = layers.Conv1D(64, kernel_size=7, padding="same", activation="relu")(cnn_x)
        cnn_x = layers.BatchNormalization()(cnn_x)
        cnn_x = layers.MaxPooling1D(pool_size=2)(cnn_x)

        cnn_x = layers.Conv1D(128, kernel_size=5, padding="same", activation="relu")(cnn_x)
        cnn_x = layers.BatchNormalization()(cnn_x)
        cnn_x = layers.Conv1D(128, kernel_size=3, dilation_rate=2, padding="same", activation="relu")(cnn_x)
        cnn_x = layers.BatchNormalization()(cnn_x)
        cnn_x = layers.MaxPooling1D(pool_size=2)(cnn_x)

        cnn_x = layers.Conv1D(256, kernel_size=3, padding="same", activation="relu")(cnn_x)
        cnn_x = layers.BatchNormalization()(cnn_x)
        cnn_x = layers.GlobalMaxPooling1D()(cnn_x)

        cnn_features = layers.Dense(128, activation="relu", name="cnn_feature_branch")(cnn_x)

        # ════════════════════════════════════════════════════════
        # LSTM BRANCH — Captures sequential byte dependencies
        # ════════════════════════════════════════════════════════
        lstm_x = layers.Embedding(input_dim=256, output_dim=32, input_length=seq_length, name="lstm_embedding")(inp)

        lstm_x = layers.Bidirectional(
            layers.LSTM(64, return_sequences=True, dropout=0.2),
            name="bilstm_seq"
        )(lstm_x)

        # ── Attention Layer ──
        # Learn which byte positions are most important
        attn_score = layers.Dense(1, activation="tanh", name="attn_dense")(lstm_x)
        attn_score = layers.Flatten()(attn_score)
        attn_weights = layers.Activation("softmax", name="attention_weights")(attn_score)
        attn_weights_expanded = layers.RepeatVector(128)(attn_weights)  # 64*2
        attn_weights_expanded = layers.Permute([2, 1])(attn_weights_expanded)
        lstm_attended = layers.Multiply(name="attended_output")([lstm_x, attn_weights_expanded])

        lstm_x = layers.Bidirectional(
            layers.LSTM(32, return_sequences=False, dropout=0.2),
            name="bilstm_final"
        )(lstm_attended)

        lstm_features = layers.Dense(128, activation="relu", name="lstm_feature_branch")(lstm_x)

        # ════════════════════════════════════════════════════════
        # MERGE — Combine CNN + LSTM features
        # ════════════════════════════════════════════════════════
        merged = layers.Concatenate(name="feature_merge")([cnn_features, lstm_features])
        merged = layers.Dense(256, activation="relu", name="hybrid_feature_layer")(merged)
        merged = layers.Dropout(0.5)(merged)

        # ── File type classification head ──
        ft = layers.Dense(128, activation="relu", name="ft_hidden1")(merged)
        ft = layers.Dropout(0.3)(ft)
        ft = layers.Dense(64, activation="relu", name="ft_hidden2")(ft)
        file_type_output = layers.Dense(num_file_types, activation="softmax", name="file_type_output")(ft)

        # ── Malware detection head ──
        mw = layers.Dense(64, activation="relu", name="mw_hidden1")(merged)
        mw = layers.Dropout(0.3)(mw)
        mw = layers.Dense(32, activation="relu", name="mw_hidden2")(mw)
        malware_output = layers.Dense(1, activation="sigmoid", name="malware_output")(mw)

        # ── Assemble ──
        self.model = Model(inputs=inp, outputs=[file_type_output, malware_output], name="HybridRecoveryModel")

        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss=["categorical_crossentropy", "binary_crossentropy"],
            loss_weights=[1.0, 0.5],
            metrics=[["accuracy"], ["accuracy"]],
        )

        # Feature extractor (256-dim hybrid features)
        self.feature_extractor = Model(
            inputs=self.model.input,
            outputs=self.model.get_layer("hybrid_feature_layer").output,
            name="HybridFeatureExtractor",
        )

        return self.model

    def extract_features(self, X: np.ndarray) -> np.ndarray:
        if self.feature_extractor is None:
            raise RuntimeError("Model not built.")
        return self.feature_extractor.predict(X, verbose=0)

    def train(self, X_train, y_type_train, y_malware_train,
              X_val, y_type_val, y_malware_val,
              epochs=50, batch_size=64):
        if self.model is None:
            raise RuntimeError("Model not built.")

        type_labels = np.argmax(y_type_train, axis=1)
        unique_classes = np.unique(type_labels)
        weights = compute_class_weight("balanced", classes=unique_classes, y=type_labels)
        class_weight_dict = dict(zip(unique_classes, weights))
        sample_weights = np.array([class_weight_dict[l] for l in type_labels])

        cb = [
            callbacks.EarlyStopping(monitor="val_loss", patience=8, restore_best_weights=True, verbose=1),
            callbacks.ReduceLROnPlateau(monitor="val_loss", patience=4, factor=0.5, min_lr=1e-7, verbose=1),
        ]

        return self.model.fit(
            X_train, [y_type_train, y_malware_train],
            validation_data=(X_val, [y_type_val, y_malware_val]),
            epochs=epochs, batch_size=batch_size,
            sample_weight=[sample_weights, np.ones(len(y_malware_train))],
            callbacks=cb, verbose=2,
        )

    def evaluate(self, X_test, y_type_test, y_malware_test) -> dict:
        preds = self.model.predict(X_test, verbose=0)
        y_type_pred = np.argmax(preds[0], axis=1)
        y_type_true = np.argmax(y_type_test, axis=1)
        y_mal_pred = (preds[1].flatten() >= 0.5).astype(int)
        y_mal_true = y_malware_test.flatten()

        return {
            "file_type_accuracy": float(accuracy_score(y_type_true, y_type_pred)),
            "file_type_f1": float(f1_score(y_type_true, y_type_pred, average="weighted", zero_division=0)),
            "malware_accuracy": float(accuracy_score(y_mal_true, y_mal_pred)),
            "malware_f1": float(f1_score(y_mal_true, y_mal_pred, zero_division=0)),
        }

    def predict_single(self, X_bytes: np.ndarray) -> dict:
        """Predict file type and malware risk for a single sample."""
        if self.model is None:
            raise RuntimeError("Model not loaded.")
        X = X_bytes.astype(np.float32).reshape(1, -1)
        preds = self.model.predict(X, verbose=0)
        type_probs = preds[0][0]
        malware_prob = float(preds[1][0][0])
        pred_idx = int(np.argmax(type_probs))
        confidence = float(type_probs[pred_idx])

        return {
            "predicted_class_idx": pred_idx,
            "confidence": confidence,
            "malware_score": malware_prob,
            "risk_level": "HIGH" if malware_prob >= 0.7 else ("MEDIUM" if malware_prob >= 0.3 else "LOW"),
            "type_probabilities": type_probs.tolist(),
        }

    def save(self, path: str = "saved_models/hybrid_recovery_model.keras"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.model.save(path)
        print(f"[OK] Hybrid model saved to {path}")

    def load(self, path: str = "saved_models/hybrid_recovery_model.keras"):
        self.model = keras.models.load_model(path, safe_mode=False)
        self._num_file_types = self.model.output_shape[0][-1]
        self.feature_extractor = Model(
            inputs=self.model.input,
            outputs=self.model.get_layer("hybrid_feature_layer").output,
            name="HybridFeatureExtractor",
        )
        print(f"[OK] Hybrid model loaded from {path}")
        return self.model


if __name__ == "__main__":
    model = HybridRecoveryModel()
    m = model.build(num_file_types=35)
    m.summary()

    dummy = np.random.randint(0, 256, size=(4, 512)).astype(np.float32)
    type_out, mal_out = m.predict(dummy, verbose=0)
    features = model.extract_features(dummy)

    print(f"\n  file_type shape : {type_out.shape}")
    print(f"  malware shape   : {mal_out.shape}")
    print(f"  features shape  : {features.shape}")

    result = model.predict_single(dummy[0])
    print(f"  Single prediction: class={result['predicted_class_idx']}, conf={result['confidence']:.3f}, malware={result['malware_score']:.4f}")
    print("✅ Hybrid Recovery Model OK")
