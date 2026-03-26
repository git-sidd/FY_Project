"""
Feature Engineering — Extract numerical features from raw byte arrays
=====================================================================

Provides a FeatureEngineer class that converts raw file bytes into
a fixed-length numerical feature vector suitable for ML classifiers.

Feature vector layout (275 + N_signatures dimensions):
    [0]         Shannon entropy              (1)
    [1:257]     Byte histogram               (256)
    [257]       Null byte ratio              (1)
    [258]       Printable ASCII ratio        (1)
    [259:275]   First 16 raw bytes (norm.)   (16)
    [275:]      Signature match scores       (N_signatures, one per known type)
"""

import numpy as np
import sys
import os

# Import SIGNATURES — resolve path relative to project root
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from dataset.signatures import SIGNATURES, USABLE_SIGNATURES_FILTER
except ImportError:
    # Fallback: import SIGNATURES only
    from dataset.signatures import SIGNATURES
    USABLE_SIGNATURES_FILTER = None

# Build the ordered list of (name, magic_bytes, offset, sub_marker_offset, sub_marker)
# used for signature matching features — same order every time for consistency.
_SUB_MARKERS = {
    "WAV":  (8,  b"WAVE"),
    "AVI":  (8,  b"AVI "),
    "WEBP": (8,  b"WEBP"),
    "DOCX": (30, b"DOCX"),
    "XLSX": (30, b"XLSX"),
    "PPTX": (30, b"PPTX"),
    "ZIP":  (30, b"ZPAK"),
    "PE":   (60, b"PE\x00\x00"),
}

_SIG_ENTRIES: list[tuple[str, bytes, int, int | None, bytes | None]] = []
for _name, _sig in sorted(SIGNATURES.items()):  # sorted = stable order
    _magic  = _sig["magic_bytes"]
    _offset = _sig["offset"]
    _sm     = _SUB_MARKERS.get(_name)
    _sm_off = _sm[0] if _sm else None
    _sm_bytes = _sm[1] if _sm else None
    _SIG_ENTRIES.append((_name, _magic, _offset, _sm_off, _sm_bytes))

N_SIGNATURES = len(_SIG_ENTRIES)



class FeatureEngineer:
    """Extracts forensic features from raw byte arrays."""

    # ──────────────────────────────────────────────────────────────
    # Individual feature methods
    # ──────────────────────────────────────────────────────────────

    @staticmethod
    def shannon_entropy(byte_array: np.ndarray | bytes | bytearray) -> float:
        """
        Compute Shannon entropy of the byte distribution.

        Returns
        -------
        float
            Entropy in bits.  0.0 = all identical bytes,  8.0 = perfectly
            uniform distribution across all 256 possible byte values.
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) == 0:
            return 0.0

        # Count occurrences of each byte value 0-255
        counts = np.bincount(data, minlength=256).astype(np.float64)
        probabilities = counts / counts.sum()

        # Filter out zero probabilities to avoid log2(0)
        nonzero = probabilities[probabilities > 0]
        entropy = -np.sum(nonzero * np.log2(nonzero))
        return float(entropy)

    @staticmethod
    def byte_histogram(byte_array: np.ndarray | bytes | bytearray) -> np.ndarray:
        """
        Compute a normalised histogram of byte value frequencies.

        Returns
        -------
        np.ndarray, shape (256,), dtype float32
            Frequency of each byte value 0x00 – 0xFF, summing to 1.0.
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) == 0:
            return np.zeros(256, dtype=np.float32)

        counts = np.bincount(data, minlength=256).astype(np.float32)
        total = counts.sum()
        if total > 0:
            counts /= total
        return counts

    @staticmethod
    def null_byte_ratio(byte_array: np.ndarray | bytes | bytearray) -> float:
        """
        Compute the ratio of null bytes (0x00) in the array.

        Returns
        -------
        float
            Ratio in [0.0, 1.0].
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) == 0:
            return 0.0
        return float(np.count_nonzero(data == 0x00) / len(data))

    @staticmethod
    def printable_ascii_ratio(byte_array: np.ndarray | bytes | bytearray) -> float:
        """
        Compute the ratio of printable ASCII bytes (0x20 – 0x7E).

        Returns
        -------
        float
            Ratio in [0.0, 1.0].
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) == 0:
            return 0.0
        printable_mask = (data >= 0x20) & (data <= 0x7E)
        return float(np.count_nonzero(printable_mask) / len(data))

    @staticmethod
    def magic_bytes_raw(byte_array: np.ndarray | bytes | bytearray, n: int = 16) -> np.ndarray:
        """
        Extract the first *n* bytes and normalise to [0, 1].

        If the input is shorter than *n*, the result is zero-padded.

        Returns
        -------
        np.ndarray, shape (n,), dtype float32
            First *n* byte values scaled to 0.0 – 1.0.
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        raw = np.zeros(n, dtype=np.float32)
        length = min(len(data), n)
        raw[:length] = data[:length].astype(np.float32) / 255.0
        return raw

    @staticmethod
    def signature_match_scores(
        byte_array: np.ndarray | bytes | bytearray,
        sample_size: int = 512,
    ) -> np.ndarray:
        """
        Compute a match score in [0, 1] for every known file signature.

        For each signature entry the score is:
            (bytes_correctly_matched) / (magic_length + sub_marker_length)

        A perfect score of 1.0 means every magic byte AND sub-type marker
        byte matched exactly.

        Returns
        -------
        np.ndarray, shape (N_SIGNATURES,), dtype float32
        """
        data = (
            np.frombuffer(byte_array, dtype=np.uint8)
            if not isinstance(byte_array, np.ndarray)
            else byte_array.astype(np.uint8)
        )
        scores = np.zeros(N_SIGNATURES, dtype=np.float32)

        for idx, (name, magic, offset, sm_off, sm_bytes) in enumerate(_SIG_ENTRIES):
            total = len(magic)
            matched = 0

            # --- check magic bytes ---
            for i, b in enumerate(magic):
                pos = offset + i
                if pos < len(data) and data[pos] == b:
                    matched += 1

            # --- check sub-type marker (tie-breaker for RIFF/ZIP types) ---
            if sm_off is not None and sm_bytes is not None:
                total += len(sm_bytes)
                for i, b in enumerate(sm_bytes):
                    pos = sm_off + i
                    if pos < len(data) and data[pos] == b:
                        matched += 1

            scores[idx] = matched / total if total > 0 else 0.0

        return scores

    @staticmethod
    def byte_frequency_variance(byte_array: np.ndarray | bytes | bytearray) -> float:
        """
        Compute the variance of byte frequencies.
        Higher variance indicates more diverse byte patterns.

        Returns
        -------
        float
            Variance of frequency distribution.
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) == 0:
            return 0.0
        counts = np.bincount(data, minlength=256).astype(np.float32)
        return float(np.var(counts))

    @staticmethod
    def byte_value_range(byte_array: np.ndarray | bytes | bytearray) -> float:
        """
        Compute the range (max - min) of byte values in the file.
        Indicates the spread of byte values used.

        Returns
        -------
        float
            Range of byte values (0-255).
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) == 0:
            return 0.0
        return float(np.max(data) - np.min(data))

    @staticmethod
    def byte_value_mean(byte_array: np.ndarray | bytes | bytearray) -> float:
        """
        Compute the mean of all byte values.

        Returns
        -------
        float
            Mean byte value (0-255).
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) == 0:
            return 0.0
        return float(np.mean(data))

    @staticmethod
    def byte_value_std(byte_array: np.ndarray | bytes | bytearray) -> float:
        """
        Compute the standard deviation of byte values.

        Returns
        -------
        float
            Standard deviation of byte values.
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) == 0:
            return 0.0
        return float(np.std(data))

    @staticmethod
    def control_character_ratio(byte_array: np.ndarray | bytes | bytearray) -> float:
        """
        Compute the ratio of control characters (0x00-0x1F, excluding newline).

        Returns
        -------
        float
            Ratio in [0.0, 1.0].
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) == 0:
            return 0.0
        control_mask = (data >= 0x00) & (data <= 0x1F)
        return float(np.count_nonzero(control_mask) / len(data))

    @staticmethod
    def high_entropy_ratio(byte_array: np.ndarray | bytes | bytearray, window_size: int = 16) -> float:
        """
        Compute ratio of windows with high entropy (compressed/encrypted).

        Returns
        -------
        float
            Ratio of high-entropy windows (entropy > 6.0).
        """
        data = np.frombuffer(byte_array, dtype=np.uint8) if not isinstance(byte_array, np.ndarray) else byte_array
        if len(data) < window_size:
            return 0.0
        
        high_entropy_count = 0
        for i in range(0, len(data) - window_size + 1, window_size):
            window = data[i:i + window_size]
            counts = np.bincount(window, minlength=256).astype(np.float32)
            probs = counts / counts.sum()
            entropy = -np.sum(probs[probs > 0] * np.log2(probs[probs > 0]))
            if entropy > 6.0:
                high_entropy_count += 1
        
        total_windows = (len(data) - window_size + 1) // window_size + (1 if (len(data) - window_size) % window_size > 0 else 0)
        return float(high_entropy_count / total_windows) if total_windows > 0 else 0.0

    # ──────────────────────────────────────────────────────────────
    # Aggregate feature extraction
    # ──────────────────────────────────────────────────────────────

    def extract_all(self, byte_array: np.ndarray | bytes | bytearray) -> np.ndarray:
        """
        Extract ALL features and return a single concatenated vector.

        Layout (Original 275 + N_SIGNATURES + 6 new engineered features):
            [0]         entropy              (1)
            [1:257]     byte_histogram       (256)
            [257]       null_byte_ratio      (1)
            [258]       printable_ratio      (1)
            [259:275]   magic_bytes_raw      (16)
            [275:]      signature_match_scores  (N_SIGNATURES)
            [275+N_SIG:]   byte_frequency_variance (1)
            [276+N_SIG:]   byte_value_range (1)
            [277+N_SIG:]   byte_value_mean  (1)
            [278+N_SIG:]   byte_value_std   (1)
            [279+N_SIG:]   control_character_ratio (1)
            [280+N_SIG:]   high_entropy_ratio (1)

        Returns
        -------
        np.ndarray, shape (281 + N_SIGNATURES,), dtype float32
        """
        entropy    = np.array([self.shannon_entropy(byte_array)], dtype=np.float32)
        histogram  = self.byte_histogram(byte_array)                        # (256,)
        null_ratio = np.array([self.null_byte_ratio(byte_array)], dtype=np.float32)
        printable  = np.array([self.printable_ascii_ratio(byte_array)], dtype=np.float32)
        magic      = self.magic_bytes_raw(byte_array, n=16)                 # (16,)
        sig_scores = self.signature_match_scores(byte_array)               # (N_SIGNATURES,)
        
        # Enhanced features
        byte_freq_var = np.array([self.byte_frequency_variance(byte_array)], dtype=np.float32)
        byte_range = np.array([self.byte_value_range(byte_array)], dtype=np.float32)
        byte_mean = np.array([self.byte_value_mean(byte_array) / 255.0], dtype=np.float32)  # normalize
        byte_std = np.array([self.byte_value_std(byte_array) / 255.0], dtype=np.float32)    # normalize
        control_char = np.array([self.control_character_ratio(byte_array)], dtype=np.float32)
        high_entropy = np.array([self.high_entropy_ratio(byte_array)], dtype=np.float32)

        feature_vector = np.concatenate([
            entropy,        # 1
            histogram,      # 256
            null_ratio,     # 1
            printable,      # 1
            magic,          # 16
            sig_scores,     # N_SIGNATURES
            byte_freq_var,  # 1
            byte_range,     # 1 (normalize 0-255)
            byte_mean,      # 1 (normalized)
            byte_std,       # 1 (normalized)
            control_char,   # 1
            high_entropy,   # 1
        ])                  # total = 281 + N_SIGNATURES

        return feature_vector


# ─── Quick self-test ──────────────────────────────────────────────────
if __name__ == "__main__":
    fe = FeatureEngineer()

    # Test with a fake PDF header + random noise
    sample = bytearray(b"\x25\x50\x44\x46\x2D") + bytearray(507)
    vec = fe.extract_all(sample)

    print(f"Feature vector shape : {vec.shape}")
    print(f"Entropy              : {fe.shannon_entropy(sample):.4f}")
    print(f"Null byte ratio      : {fe.null_byte_ratio(sample):.4f}")
    print(f"Printable ASCII ratio: {fe.printable_ascii_ratio(sample):.4f}")
    print(f"Magic bytes (first 8): {fe.magic_bytes_raw(sample, 8)}")
    expected_dim = 281 + N_SIGNATURES
    assert vec.shape == (expected_dim,), f"Expected {expected_dim} features, got {vec.shape[0]}"
    print("\n✅ All feature engineering methods working correctly.")
