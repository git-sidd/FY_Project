"""
Synthetic Forensic Dataset Generator
=====================================

Generates a labelled dataset of 512-byte file headers for training
file-signature classification models.

Labels
------
0  valid      — correct magic bytes + matching extension
1  corrupted  — damaged / incomplete headers
2  mismatch   — extension does not match magic bytes (disguised files)

Usage
-----
    python -m dataset.generate_dataset          # from project root
    python dataset/generate_dataset.py          # direct run
"""

import json
import os
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import pandas as pd
# Disable tqdm for headless environments that might hang
def tqdm(iterable, *args, **kwargs):
    return iterable

# ─── Ensure project root is importable ────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from dataset.signatures import SIGNATURES  # noqa: E402

# ══════════════════════════════════════════════════════════════════════
# Constants
# ══════════════════════════════════════════════════════════════════════
SAMPLE_SIZE = 512           # bytes per sample
SEED = 42
RNG = np.random.default_rng(SEED)

LABEL_MAP = {0: "valid", 1: "corrupted", 2: "mismatch"}

# Filter out signatures whose offset is beyond the sample window
# (e.g. ISO at 0x8001 = 32769 — cannot fit in 512 bytes)
USABLE_SIGNATURES: dict[str, dict] = {
    name: sig
    for name, sig in SIGNATURES.items()
    if sig["offset"] + len(sig["magic_bytes"]) <= SAMPLE_SIZE
}

# ── RIFF/ZIP sub-type disambiguation bytes at fixed offsets ───────────
# These bytes are placed AFTER the magic to distinguish colliding types.
# RIFF offset 8 = sub-type identifier; ZIP types get a comment at offset 30+
SUB_TYPE_MARKERS: dict[str, tuple[int, bytes]] = {
    "WAV":  (8,  b"WAVE"),
    "AVI":  (8,  b"AVI "),
    "WEBP": (8,  b"WEBP"),
    # ZIP-based: put a distinct 4-byte marker at offset 30 (local file header extra)
    "DOCX": (30, b"DOCX"),
    "XLSX": (30, b"XLSX"),
    "PPTX": (30, b"PPTX"),
    "ZIP":  (30, b"ZPAK"),
    # PE vs EXE: EXE gets 'PE\x00\x00' at offset 60 (simplified e_lfanew target)
    "PE":   (60, b"PE\x00\x00"),
}

# ── Category-specific body byte generators ────────────────────────────
# Each function returns a bytes-like body (appended after magic + offset region).
# The goal: teach the model that real files have characteristic byte distributions
# beyond just the magic header.

def _body_image(length: int) -> np.ndarray:
    """Images: high entropy compressed pixel data, mostly values 0-255 uniformly."""
    return RNG.integers(0, 256, size=length, dtype=np.uint8)

def _body_document(length: int) -> np.ndarray:
    """Documents (PDF, DOCX): mix of printable ASCII and binary sections."""
    # ~60% printable ASCII text (0x20–0x7E), ~40% binary
    out = np.empty(length, dtype=np.uint8)
    n_text = int(length * 0.6)
    out[:n_text] = RNG.integers(0x20, 0x7F, size=n_text, dtype=np.uint8)
    out[n_text:] = RNG.integers(0, 256, size=length - n_text, dtype=np.uint8)
    RNG.shuffle(out)
    return out

def _body_archive(length: int) -> np.ndarray:
    """Archives: high entropy (compressed), zero null bytes."""
    return RNG.integers(1, 256, size=length, dtype=np.uint8)  # no nulls

def _body_executable(length: int) -> np.ndarray:
    """Executables: structured sections — header region with low values, then code."""
    out = np.empty(length, dtype=np.uint8)
    # First quarter: structured header bytes (PE section table pattern)
    out[:length//4] = RNG.integers(0, 64, size=length//4, dtype=np.uint8)
    # Rest: high-entropy code bytes
    out[length//4:] = RNG.integers(0, 256, size=length - length//4, dtype=np.uint8)
    return out

def _body_database(length: int) -> np.ndarray:
    """Databases: large blocks of null bytes (sparse pages) + some data bytes."""
    out = np.zeros(length, dtype=np.uint8)
    # ~30% non-null data scattered around
    n_data = int(length * 0.3)
    idxs = RNG.choice(length, size=n_data, replace=False)
    out[idxs] = RNG.integers(1, 256, size=n_data, dtype=np.uint8)
    return out

def _body_audio(length: int) -> np.ndarray:
    """Audio: medium entropy PCM-like data with small variations."""
    # Simulate PCM: values clustered near midpoint (128) with Gaussian spread
    vals = np.clip(
        RNG.normal(loc=128, scale=40, size=length), 0, 255
    ).astype(np.uint8)
    return vals

def _body_video(length: int) -> np.ndarray:
    """Video: very high entropy (compressed frames), uniform distribution."""
    return RNG.integers(0, 256, size=length, dtype=np.uint8)

def _body_web(length: int) -> np.ndarray:
    """Web files (HTML/XML): almost entirely printable ASCII text."""
    # 90% printable ASCII
    n_text = int(length * 0.9)
    out = np.empty(length, dtype=np.uint8)
    out[:n_text] = RNG.integers(0x20, 0x7F, size=n_text, dtype=np.uint8)
    out[n_text:] = RNG.integers(0, 0x20, size=length - n_text, dtype=np.uint8)
    RNG.shuffle(out)
    return out

_CATEGORY_BODY_FN = {
    # We leave this intentionally empty so `.get()` in `_make_base_sample` 
    # falls back to `_random_noise`. This forces the CNN and XGBoost to 
    # ignore background statistical patterns and solely learn the signatures!
}

_SKIPPED = set(SIGNATURES) - set(USABLE_SIGNATURES)
if _SKIPPED:
    print(f"  [!] Skipping {_SKIPPED} -- offset exceeds {SAMPLE_SIZE}-byte window")

# ── Real Dataset Augmentation ─────────────────────────────────────────
REAL_SAMPLES = {}
try:
    _user_path = r"C:\Users\siddh\OneDrive\Desktop\malware_pattern_test_files\malware_test_files"
    if os.path.exists(_user_path):
        import glob
        print(f"\n  [+] Loading real files from: {_user_path}")
        for fpath in glob.glob(os.path.join(_user_path, "*.*")):
            ext = os.path.splitext(fpath)[1].lower()
            with open(fpath, "rb") as f:
                data = f.read(SAMPLE_SIZE)
                if len(data) < SAMPLE_SIZE:
                    data = data + b"\x00" * (SAMPLE_SIZE - len(data))
                buf = np.frombuffer(data, dtype=np.uint8)
            # Find matching type
            for name, sig in USABLE_SIGNATURES.items():
                if ext in [e.lower() for e in sig["extension"]]:
                    if name not in REAL_SAMPLES:
                        REAL_SAMPLES[name] = []
                    REAL_SAMPLES[name].append(buf)
                    break
        print(f"  [+] Loaded real samples for {len(REAL_SAMPLES)} file categories.")
except Exception as e:
    print(f"  [!] Failed to load real dataset: {e}")

# Output paths
DATASET_DIR = _PROJECT_ROOT / "dataset"
OUTPUT_CSV        = DATASET_DIR / "dataset.csv"
OUTPUT_BYTES_NPY  = DATASET_DIR / "dataset.npy"
OUTPUT_LABELS_NPY = DATASET_DIR / "dataset_labels.npy"
OUTPUT_META_JSON  = DATASET_DIR / "dataset_meta.json"


# ══════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════

def _random_noise(length: int) -> np.ndarray:
    """Generate random byte noise (uint8)."""
    return RNG.integers(0, 256, size=length, dtype=np.uint8)


def _embed_magic(buffer: np.ndarray, magic: bytes, offset: int) -> np.ndarray:
    """Write *magic* bytes into *buffer* starting at *offset*."""
    buf = buffer.copy()
    for i, b in enumerate(magic):
        pos = offset + i
        if pos < SAMPLE_SIZE:
            buf[pos] = b
    return buf


def _embed_sub_marker(buf: np.ndarray, name: str) -> np.ndarray:
    """Embed RIFF/ZIP sub-type disambiguation bytes if defined for this type."""
    if name in SUB_TYPE_MARKERS:
        off, marker = SUB_TYPE_MARKERS[name]
        buf = buf.copy()
        for i, b in enumerate(marker):
            pos = off + i
            if pos < SAMPLE_SIZE:
                buf[pos] = b
    return buf


def _make_base_sample(sig: dict, name: str = "") -> np.ndarray:
    """
    Create a 512-byte sample with:
      0. REAL bytes if a real file for this type was loaded!
      1. Category-appropriate body byte distribution (NOT pure noise)
      2. Correct magic bytes at the right offset
      3. Sub-type disambiguation bytes for RIFF/ZIP collisions
    """
    if name in REAL_SAMPLES and len(REAL_SAMPLES[name]) > 0:
        idx = int(RNG.integers(0, len(REAL_SAMPLES[name])))
        return REAL_SAMPLES[name][idx].copy()

    category = sig.get("category", "image")
    body_fn = _CATEGORY_BODY_FN.get(category, _random_noise)
    buf = body_fn(SAMPLE_SIZE)
    # Embed magic at correct offset
    buf = _embed_magic(buf, sig["magic_bytes"], sig["offset"])
    # Embed sub-type marker (for RIFF/ZIP collisions)
    buf = _embed_sub_marker(buf, name)
    return buf


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 0 — Valid / Clean Signatures
# ══════════════════════════════════════════════════════════════════════

def generate_valid_samples(samples_per_type: int = 150) -> list[dict]:
    """
    Generate clean samples with correct magic bytes + correct extension.

    At least *samples_per_type* samples per file-type entry in USABLE_SIGNATURES.
    """
    samples: list[dict] = []

    for name, sig in tqdm(USABLE_SIGNATURES.items(), desc="Cat-0  valid    "):
        ext = sig["extension"][0]
        for _ in range(samples_per_type):
            buf = _make_base_sample(sig, name)
            samples.append({
                "file_bytes":          buf,
                "true_file_type":      name,
                "declared_extension":  ext,
                "label":               0,
                "label_name":          "valid",
                "is_malicious":        False,
                "category":            sig["category"],
                "corruption_type":     "none",
            })

    return samples


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 1 — Corrupted / Incomplete Signatures
# ══════════════════════════════════════════════════════════════════════

def _corrupt_truncated(
    buf: np.ndarray, magic: bytes, offset: int
) -> tuple[np.ndarray, str]:
    """Keep only first 1 or 2 bytes of the magic header; zero the rest."""
    keep = int(RNG.integers(1, min(3, len(magic) + 1)))
    b = buf.copy()
    for i in range(keep, len(magic)):
        pos = offset + i
        if pos < SAMPLE_SIZE:
            b[pos] = 0x00
    return b, f"truncated_header_keep_{keep}"


def _corrupt_byte_flip(
    buf: np.ndarray, magic: bytes, offset: int
) -> tuple[np.ndarray, str]:
    """Flip one random byte inside the magic region to 0x00."""
    b = buf.copy()
    idx = int(RNG.integers(0, len(magic)))
    b[offset + idx] = 0x00
    return b, f"byte_flip_pos_{idx}"


def _corrupt_partial_overwrite(
    buf: np.ndarray, magic: bytes, offset: int
) -> tuple[np.ndarray, str]:
    """Replace first 4 bytes at the magic offset with null bytes."""
    b = buf.copy()
    for i in range(min(4, SAMPLE_SIZE - offset)):
        b[offset + i] = 0x00
    return b, "partial_overwrite_4_null"


def _corrupt_wrong_offset(
    buf: np.ndarray, magic: bytes, offset: int
) -> tuple[np.ndarray, str]:
    """Place magic bytes at offset 4 instead of the correct offset."""
    b = _random_noise(SAMPLE_SIZE)
    wrong_off = 4 if offset != 4 else 0
    b = _embed_magic(b, magic, wrong_off)
    return b, f"wrong_offset_{wrong_off}_instead_of_{offset}"


_CORRUPTION_FNS = [
    _corrupt_truncated,
    _corrupt_byte_flip,
    _corrupt_partial_overwrite,
    _corrupt_wrong_offset,
]


def generate_corrupted_samples(samples_per_variant_per_type: int = 38) -> list[dict]:
    """
    Generate corrupted samples for every (file_type × corruption_variant).

    Total ≈ len(USABLE_SIGNATURES) × 4 variants × samples_per_variant_per_type.
    """
    samples: list[dict] = []

    for name, sig in tqdm(USABLE_SIGNATURES.items(), desc="Cat-1  corrupted"):
        magic  = sig["magic_bytes"]
        offset = sig["offset"]
        ext    = sig["extension"][0]

        for corrupt_fn in _CORRUPTION_FNS:
            for _ in range(samples_per_variant_per_type):
                base = _make_base_sample(sig, name)
                corrupted_buf, desc = corrupt_fn(base, magic, offset)
                samples.append({
                    "file_bytes":          corrupted_buf,
                    "true_file_type":      name,
                    "declared_extension":  ext,
                    "label":               1,
                    "label_name":          "corrupted",
                    "is_malicious":        False,
                    "category":            sig["category"],
                    "corruption_type":     desc,
                })

    return samples


# ══════════════════════════════════════════════════════════════════════
# CATEGORY 2 — Extension Mismatch / Disguised Files
# ══════════════════════════════════════════════════════════════════════

# (actual_type, fake_extension, is_malicious, scenario_description)
_MISMATCH_SCENARIOS: list[tuple[str | None, str | None, bool, str]] = [
    ("EXE",  ".pdf",  True,  "exe_disguised_as_pdf"),
    ("EXE",  ".jpg",  True,  "exe_disguised_as_jpg"),
    ("ELF",  ".mp3",  True,  "elf_disguised_as_mp3"),
    ("ZIP",  ".docx", False, "zip_repackaged_as_docx"),
    ("PNG",  ".exe",  False, "png_mislabeled_as_exe"),
    (None,   None,    False, "random_bytes_unknown"),      # no valid signature
]

_RANDOM_EXTS = [".pdf", ".jpg", ".png", ".exe", ".mp3", ".docx", ".zip", ".wav"]


def generate_mismatch_samples(samples_per_scenario: int = 875) -> list[dict]:
    """
    Generate extension-mismatch / disguised-file samples.

    Includes both malicious (disguised executables) and benign mismatches.
    """
    samples: list[dict] = []

    for actual_type, fake_ext, is_mal, desc in tqdm(
        _MISMATCH_SCENARIOS, desc="Cat-2  mismatch "
    ):
        for _ in range(samples_per_scenario):
            if actual_type is None:
                # Completely random bytes — no valid signature at all
                buf = _random_noise(SAMPLE_SIZE)
                chosen_ext = str(RNG.choice(_RANDOM_EXTS))
                samples.append({
                    "file_bytes":          buf,
                    "true_file_type":      "UNKNOWN",
                    "declared_extension":  chosen_ext,
                    "label":               2,
                    "label_name":          "mismatch",
                    "is_malicious":        is_mal,
                    "category":            "unknown",
                    "corruption_type":     desc,
                })
            else:
                sig = USABLE_SIGNATURES[actual_type]
                buf = _make_base_sample(sig, actual_type)
                samples.append({
                    "file_bytes":          buf,
                    "true_file_type":      actual_type,
                    "declared_extension":  fake_ext,
                    "label":               2,
                    "label_name":          "mismatch",
                    "is_malicious":        is_mal,
                    "category":            sig["category"],
                    "corruption_type":     desc,
                })

    return samples


# ══════════════════════════════════════════════════════════════════════
# Dataset Summary
# ══════════════════════════════════════════════════════════════════════

def print_summary(samples: list[dict]) -> None:
    """Print a comprehensive, human-readable dataset summary."""
    total      = len(samples)
    labels     = [s["label"]          for s in samples]
    types      = [s["true_file_type"] for s in samples]
    malicious  = [s["is_malicious"]   for s in samples]

    label_counts = Counter(labels)
    type_counts  = Counter(types)
    mal_counts   = Counter(malicious)

    print("\n" + "=" * 65)
    print("  DATASET SUMMARY")
    print("=" * 65)
    print(f"  Total samples : {total:,}")

    # ── Per label ────────────────────────────────────────────────
    print("\n  -- Samples per label --")
    for lbl in sorted(label_counts):
        cnt = label_counts[lbl]
        pct = cnt / total * 100
        print(f"    [{lbl}] {LABEL_MAP[lbl]:>10s}  : {cnt:>6,d}  ({pct:5.1f}%)")

    # ── Per file type ────────────────────────────────────────────
    print("\n  -- Samples per file type --")
    for ft, cnt in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(f"    {ft:<12s}: {cnt:>5,d}")

    # ── Malicious vs clean ───────────────────────────────────────
    print("\n  -- Malicious vs Clean --")
    mal_true  = mal_counts.get(True, 0)
    mal_false = mal_counts.get(False, 0)
    print(f"    Malicious : {mal_true:>6,d}  ({mal_true / total * 100:5.1f}%)")
    print(f"    Clean     : {mal_false:>6,d}  ({mal_false / total * 100:5.1f}%)")

    # ── Class balance ────────────────────────────────────────────
    print("\n  -- Class balance --")
    for lbl in sorted(label_counts):
        cnt = label_counts[lbl]
        print(f"    {LABEL_MAP[lbl]:>10s} : {cnt / total * 100:5.1f}%")

    print("=" * 65 + "\n")


# ══════════════════════════════════════════════════════════════════════
# Save to disk
# ══════════════════════════════════════════════════════════════════════

def save_dataset(samples: list[dict]) -> None:
    """Persist the dataset in CSV, NPY, and JSON formats."""
    DATASET_DIR.mkdir(parents=True, exist_ok=True)

    # 1 — dataset.npy  (byte arrays only)
    bytes_array = np.array(
        [s["file_bytes"] for s in samples], dtype=np.uint8
    )
    np.save(OUTPUT_BYTES_NPY, bytes_array)
    print(f"  [OK] {OUTPUT_BYTES_NPY.name:<25s}  shape={bytes_array.shape}")

    # 2 — dataset_labels.npy
    labels_array = np.array([s["label"] for s in samples], dtype=np.int32)
    np.save(OUTPUT_LABELS_NPY, labels_array)
    print(f"  [OK] {OUTPUT_LABELS_NPY.name:<25s}  shape={labels_array.shape}")

    # 3 — dataset_meta.json  (everything except raw bytes)
    meta: list[dict] = []
    for s in samples:
        m = {k: v for k, v in s.items() if k != "file_bytes"}
        m["is_malicious"] = bool(m["is_malicious"])   # numpy bool → native
        meta.append(m)

    with open(OUTPUT_META_JSON, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2, ensure_ascii=False)
    print(f"  [OK] {OUTPUT_META_JSON.name:<25s}  {len(meta):,} records")

    # 4 — dataset.csv  (human readable, no file_bytes)
    df = pd.DataFrame(meta)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"  [OK] {OUTPUT_CSV.name:<25s}  {len(df):,} rows × {len(df.columns)} cols")


# ══════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════

def main() -> None:
    n_types = len(USABLE_SIGNATURES)

    print("\nFile Signature Dataset Generator")
    print("-" * 50)
    print(f"    Usable file types : {n_types}")
    print(f"    Sample size       : {SAMPLE_SIZE} bytes")
    print(f"    Random seed       : {SEED}")
    print()

    # ── Generate ─────────────────────────────────────────────────
    valid     = generate_valid_samples(samples_per_type=300)          # 2× more valid samples
    corrupted = generate_corrupted_samples(samples_per_variant_per_type=75)  # more corrupted
    mismatch  = generate_mismatch_samples(samples_per_scenario=875)

    # ── Combine & shuffle ────────────────────────────────────────
    all_samples = valid + corrupted + mismatch

    indices = np.arange(len(all_samples))
    RNG.shuffle(indices)
    all_samples = [all_samples[i] for i in indices]

    # ── Summary ──────────────────────────────────────────────────
    print_summary(all_samples)

    # ── Save ─────────────────────────────────────────────────────
    print("  Saving dataset files ...")
    save_dataset(all_samples)

    print("\n  [OK] Dataset generation complete.\n")


if __name__ == "__main__":
    main()
