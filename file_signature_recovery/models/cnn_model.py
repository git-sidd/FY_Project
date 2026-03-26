"""
FileSignatureCNN — Dual-head 1D-CNN for File Type & Malware Detection
=====================================================================

Architecture:
    Input (512,) → Reshape (512,1) → Normalize 0-1
    → Conv1D(64,7) → BN → MaxPool
    → Conv1D(128,5) → BN → MaxPool
    → Conv1D(256,3) → BN → GlobalMaxPool
    → Dense(128) 'feature_layer'
    → Dropout(0.4)
    ├─ Head 1: Dense(64) → Dense(num_types, softmax)  'file_type_output'
    └─ Head 2: Dense(32) → Dense(1, sigmoid)           'malware_output'
"""

import os
import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"  # suppress TF info logs

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model, callbacks
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


class FileSignatureCNN:
    """Dual-head CNN for simultaneous file-type classification and malware detection."""

    def __init__(self):
        self.model: Model | None = None
        self.feature_extractor: Model | None = None
        self._num_file_types: int = 0

    # ──────────────────────────────────────────────────────────────
    # Build
    # ──────────────────────────────────────────────────────────────

    def build(self, num_file_types: int) -> Model:
        """
        Build and compile the dual-head CNN.

        Parameters
        ----------
        num_file_types : int
            Number of file-type classes for the softmax head.

        Returns
        -------
        keras.Model
        """
        self._num_file_types = num_file_types

        # ── Input ────────────────────────────────────────────────
        inp = layers.Input(shape=(512,), name="byte_input")

        # Reshape to (512, 1) for Conv1D
        x = layers.Reshape((512, 1))(inp)

        # Normalize byte values 0-255 → 0.0-1.0
        x = layers.Lambda(lambda t: t / 255.0, name="normalize")(x)

        # ── Enhanced Convolutional backbone with dilated convolutions ───────────
        # Use dilated convolutions to capture patterns at multiple scales
        x = layers.Conv1D(64, kernel_size=7, padding="same", activation="relu")(x)
        x = layers.BatchNormalization()(x)
        x = layers.Conv1D(64, kernel_size=5, dilation_rate=2, padding="same", activation="relu")(x)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling1D(pool_size=2)(x)

        x = layers.Conv1D(128, kernel_size=5, padding="same", activation="relu")(x)
        x = layers.BatchNormalization()(x)
        x = layers.Conv1D(128, kernel_size=3, dilation_rate=2, padding="same", activation="relu")(x)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling1D(pool_size=2)(x)

        x = layers.Conv1D(256, kernel_size=3, padding="same", activation="relu")(x)
        x = layers.BatchNormalization()(x)
        x = layers.Conv1D(256, kernel_size=3, dilation_rate=2, padding="same", activation="relu")(x)
        x = layers.BatchNormalization()(x)
        x = layers.MaxPooling1D(pool_size=2)(x)
        
        # Additional high-level feature capture
        x = layers.Conv1D(512, kernel_size=3, padding="same", activation="relu")(x)
        x = layers.BatchNormalization()(x)
        x = layers.GlobalMaxPooling1D()(x)

        # ── Feature layer with increased capacity ────────────────
        feature_layer = layers.Dense(256, activation="relu", name="feature_layer")(x)
        x = layers.Dropout(0.5)(feature_layer)

        # ── Head 1: File-type classification with deeper architecture ─────────────
        ft = layers.Dense(128, activation="relu", name="file_type_hidden1")(x)
        ft = layers.Dropout(0.3)(ft)
        ft = layers.Dense(64, activation="relu", name="file_type_hidden2")(ft)
        file_type_output = layers.Dense(
            num_file_types, activation="softmax", name="file_type_output"
        )(ft)

        # ── Head 2: Malware detection with improved architecture ────────────────
        mw = layers.Dense(64, activation="relu", name="malware_hidden1")(x)
        mw = layers.Dropout(0.3)(mw)
        mw = layers.Dense(32, activation="relu", name="malware_hidden2")(mw)
        malware_output = layers.Dense(
            1, activation="sigmoid", name="malware_output"
        )(mw)

        # ── Assemble model ───────────────────────────────────────
        self.model = Model(
            inputs=inp,
            outputs=[file_type_output, malware_output],
            name="FileSignatureCNN",
        )

        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss=["categorical_crossentropy", "binary_crossentropy"],
            loss_weights=[1.0, 0.5],
            metrics=[["accuracy"], ["accuracy"]],
        )

        # ── Feature extractor (for extract_features) ─────────────
        feature_layer_output = self.model.get_layer("feature_layer").output
        self.feature_extractor = Model(
            inputs=self.model.input,
            outputs=feature_layer_output,
            name="FeatureExtractor",
        )

        return self.model

    # ──────────────────────────────────────────────────────────────
    # Feature extraction
    # ──────────────────────────────────────────────────────────────

    def extract_features(self, X: np.ndarray) -> np.ndarray:
        """
        Extract the 256-dim feature vector from the 'feature_layer'.

        Parameters
        ----------
        X : np.ndarray, shape (N, 512)

        Returns
        -------
        np.ndarray, shape (N, 256)
        """
        if self.feature_extractor is None:
            raise RuntimeError("Model not built yet. Call build() first.")
        return self.feature_extractor.predict(X, verbose=0)

    # ──────────────────────────────────────────────────────────────
    # Training
    # ──────────────────────────────────────────────────────────────

    def train(
        self,
        X_train: np.ndarray,
        y_type_train: np.ndarray,
        y_malware_train: np.ndarray,
        X_val: np.ndarray,
        y_type_val: np.ndarray,
        y_malware_val: np.ndarray,
        epochs: int = 100,
        batch_size: int = 32,
    ):
        """
        Train the dual-head model with early stopping & LR scheduling.

        Parameters
        ----------
        X_train, X_val       : shape (N, 512) — raw byte values 0-255
        y_type_train/val     : shape (N, num_file_types) — one-hot encoded
        y_malware_train/val  : shape (N,) or (N,1) — binary 0/1
        epochs               : max epochs (default 100)
        batch_size           : batch size (default 32)

        Returns
        -------
        keras.callbacks.History
        """
        if self.model is None:
            raise RuntimeError("Model not built yet. Call build() first.")

        # ── Compute class weights for file-type head ─────────────
        type_labels = np.argmax(y_type_train, axis=1)
        unique_classes = np.unique(type_labels)
        weights = compute_class_weight(
            class_weight="balanced",
            classes=unique_classes,
            y=type_labels,
        )
        class_weight_dict = dict(zip(unique_classes, weights))
        
        # Convert to sample weights for multi-output model
        sample_weights_array = np.array([class_weight_dict[label] for label in type_labels])
        malware_weights_array = np.ones(len(y_malware_train))

        # ── Callbacks with improved strategy ────────────────────────
        cb = [
            callbacks.EarlyStopping(
                monitor="val_loss",
                patience=8,
                restore_best_weights=True,
                verbose=1,
            ),
            callbacks.ReduceLROnPlateau(
                monitor="val_loss",
                patience=4,
                factor=0.5,
                min_lr=1e-7,
                verbose=1,
            ),
        ]

        # ── Fit ──────────────────────────────────────────────────
        history = self.model.fit(
            X_train,
            [y_type_train, y_malware_train],
            validation_data=(
                X_val,
                [y_type_val, y_malware_val],
            ),
            epochs=epochs,
            batch_size=batch_size,
            sample_weight=[sample_weights_array, malware_weights_array],
            callbacks=cb,
            verbose=2,
        )
        return history

    # ──────────────────────────────────────────────────────────────
    # Evaluation
    # ──────────────────────────────────────────────────────────────

    def evaluate(
        self,
        X_test: np.ndarray,
        y_type_test: np.ndarray,
        y_malware_test: np.ndarray,
    ) -> dict:
        """
        Evaluate both heads and return detailed metrics.

        Returns
        -------
        dict with keys:
            file_type_accuracy, file_type_f1, file_type_precision, file_type_recall,
            malware_accuracy, malware_f1, malware_precision, malware_recall
        """
        if self.model is None:
            raise RuntimeError("Model not built yet. Call build() first.")

        preds = self.model.predict(X_test, verbose=0)
        type_preds = preds[0]
        malware_preds = preds[1]

        # File-type metrics (multi-class)
        y_type_true = np.argmax(y_type_test, axis=1)
        y_type_pred = np.argmax(type_preds, axis=1)

        # Malware metrics (binary)
        y_mal_true = y_malware_test.flatten()
        y_mal_pred = (malware_preds.flatten() >= 0.5).astype(int)

        results = {
            # ── File-type head ───────────────────────────────────
            "file_type_accuracy":  float(accuracy_score(y_type_true, y_type_pred)),
            "file_type_f1":        float(f1_score(y_type_true, y_type_pred, average="weighted", zero_division=0)),
            "file_type_precision": float(precision_score(y_type_true, y_type_pred, average="weighted", zero_division=0)),
            "file_type_recall":    float(recall_score(y_type_true, y_type_pred, average="weighted", zero_division=0)),
            # ── Malware head ─────────────────────────────────────
            "malware_accuracy":    float(accuracy_score(y_mal_true, y_mal_pred)),
            "malware_f1":          float(f1_score(y_mal_true, y_mal_pred, zero_division=0)),
            "malware_precision":   float(precision_score(y_mal_true, y_mal_pred, zero_division=0)),
            "malware_recall":      float(recall_score(y_mal_true, y_mal_pred, zero_division=0)),
        }
        return results

    # ──────────────────────────────────────────────────────────────
    # Save / Load
    # ──────────────────────────────────────────────────────────────

    def save(self, path: str = "saved_models/cnn_model.keras") -> None:
        """Save the full model to disk."""
        if self.model is None:
            raise RuntimeError("No model to save.")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.model.save(path)
        print(f"[OK] Model saved to {path}")

    def load(self, path: str = "saved_models/cnn_model.keras") -> Model:
        """Load a previously saved model and rebuild the feature extractor."""
        self.model = keras.models.load_model(path, safe_mode=False)
        self._num_file_types = self.model.output_shape[0][-1]

        # Rebuild feature extractor
        feature_layer_output = self.model.get_layer("feature_layer").output
        self.feature_extractor = Model(
            inputs=self.model.input,
            outputs=feature_layer_output,
            name="FeatureExtractor",
        )
        print(f"[OK] Model loaded from {path}")
        return self.model


# ─── Self-test: build and print summary ──────────────────────────────
if __name__ == "__main__":
    cnn = FileSignatureCNN()
    model = cnn.build(num_file_types=35)
    model.summary()

    # Quick shape sanity check
    dummy = np.random.randint(0, 256, size=(4, 512)).astype(np.float32)
    type_out, mal_out = model.predict(dummy, verbose=0)
    features = cnn.extract_features(dummy)

    print(f"\nDummy batch of 4 samples:")
    print(f"  file_type_output shape : {type_out.shape}")   # (4, 35)
    print(f"  malware_output shape   : {mal_out.shape}")     # (4, 1)
    print(f"  feature_layer shape    : {features.shape}")    # (4, 128)
    print("\n✅ CNN model builds and runs correctly.")
