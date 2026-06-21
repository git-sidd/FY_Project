"""
LSTM Model for File Fragment Classification
=============================================

A Bidirectional LSTM that reads raw bytes as a sequence
to capture sequential patterns in file data. Combined with
CNN features for hybrid file type identification.
"""

import os
import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, Model, callbacks
from sklearn.utils.class_weight import compute_class_weight
from sklearn.metrics import accuracy_score, f1_score


class FileSignatureLSTM:
    """Bidirectional LSTM for sequential byte pattern recognition."""

    def __init__(self):
        self.model: Model | None = None
        self.feature_extractor: Model | None = None
        self._num_file_types: int = 0

    def build(self, num_file_types: int, seq_length: int = 512) -> Model:
        self._num_file_types = num_file_types

        # ── Input ──
        inp = layers.Input(shape=(seq_length,), name="byte_input")

        # Embedding: each byte value (0-255) → 32-dim vector
        x = layers.Embedding(input_dim=256, output_dim=32, input_length=seq_length, name="byte_embedding")(inp)

        # ── Bidirectional LSTM layers ──
        x = layers.Bidirectional(
            layers.LSTM(64, return_sequences=True, dropout=0.2, recurrent_dropout=0.1),
            name="bilstm_1"
        )(x)

        # Attention mechanism: learn which byte positions matter most
        attention = layers.Dense(1, activation="tanh")(x)
        attention = layers.Flatten()(attention)
        attention = layers.Activation("softmax", name="attention_weights")(attention)
        attention = layers.RepeatVector(128)(attention)  # 128 = 64*2 (bidirectional)
        attention = layers.Permute([2, 1])(attention)

        x = layers.Multiply()([x, attention])

        x = layers.Bidirectional(
            layers.LSTM(32, return_sequences=False, dropout=0.2, recurrent_dropout=0.1),
            name="bilstm_2"
        )(x)

        # ── Feature layer ──
        feature_layer = layers.Dense(128, activation="relu", name="lstm_feature_layer")(x)
        x = layers.Dropout(0.4)(feature_layer)

        # ── File type head ──
        ft = layers.Dense(64, activation="relu")(x)
        ft = layers.Dropout(0.3)(ft)
        file_type_output = layers.Dense(num_file_types, activation="softmax", name="file_type_output")(ft)

        # ── Malware head ──
        mw = layers.Dense(32, activation="relu")(x)
        mw = layers.Dropout(0.3)(mw)
        malware_output = layers.Dense(1, activation="sigmoid", name="malware_output")(mw)

        # ── Assemble ──
        self.model = Model(inputs=inp, outputs=[file_type_output, malware_output], name="FileSignatureLSTM")

        self.model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss=["categorical_crossentropy", "binary_crossentropy"],
            loss_weights=[1.0, 0.5],
            metrics=[["accuracy"], ["accuracy"]],
        )

        # Feature extractor
        self.feature_extractor = Model(
            inputs=self.model.input,
            outputs=self.model.get_layer("lstm_feature_layer").output,
            name="LSTMFeatureExtractor",
        )

        return self.model

    def extract_features(self, X: np.ndarray) -> np.ndarray:
        if self.feature_extractor is None:
            raise RuntimeError("Model not built yet.")
        return self.feature_extractor.predict(X, verbose=0)

    def train(self, X_train, y_type_train, y_malware_train,
              X_val, y_type_val, y_malware_val,
              epochs=50, batch_size=64):
        if self.model is None:
            raise RuntimeError("Model not built yet.")

        type_labels = np.argmax(y_type_train, axis=1)
        unique_classes = np.unique(type_labels)
        weights = compute_class_weight("balanced", classes=unique_classes, y=type_labels)
        class_weight_dict = dict(zip(unique_classes, weights))
        sample_weights = np.array([class_weight_dict[l] for l in type_labels])

        cb = [
            callbacks.EarlyStopping(monitor="val_loss", patience=6, restore_best_weights=True, verbose=1),
            callbacks.ReduceLROnPlateau(monitor="val_loss", patience=3, factor=0.5, min_lr=1e-6, verbose=1),
        ]

        history = self.model.fit(
            X_train, [y_type_train, y_malware_train],
            validation_data=(X_val, [y_type_val, y_malware_val]),
            epochs=epochs, batch_size=batch_size,
            sample_weight=[sample_weights, np.ones(len(y_malware_train))],
            callbacks=cb, verbose=2,
        )
        return history

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

    def save(self, path: str = "saved_models/lstm_model.keras"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.model.save(path)
        print(f"[OK] LSTM model saved to {path}")

    def load(self, path: str = "saved_models/lstm_model.keras"):
        self.model = keras.models.load_model(path, safe_mode=False)
        self._num_file_types = self.model.output_shape[0][-1]
        self.feature_extractor = Model(
            inputs=self.model.input,
            outputs=self.model.get_layer("lstm_feature_layer").output,
            name="LSTMFeatureExtractor",
        )
        print(f"[OK] LSTM model loaded from {path}")
        return self.model


if __name__ == "__main__":
    lstm = FileSignatureLSTM()
    model = lstm.build(num_file_types=35)
    model.summary()

    dummy = np.random.randint(0, 256, size=(4, 512)).astype(np.float32)
    type_out, mal_out = model.predict(dummy, verbose=0)
    features = lstm.extract_features(dummy)

    print(f"\nDummy batch of 4:")
    print(f"  file_type shape : {type_out.shape}")
    print(f"  malware shape   : {mal_out.shape}")
    print(f"  features shape  : {features.shape}")
    print("✅ LSTM model OK")
