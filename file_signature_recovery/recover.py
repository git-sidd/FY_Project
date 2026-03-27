"""
recover.py — Full File Recovery Tool with Disk Scanning
=========================================================

3 Recovery modes:
  1. Folder scan        — Analyze existing files in a folder
  2. Recycle Bin scan    — Find recently deleted files in Windows Recycle Bin
  3. Raw Disk scan       — Scan physical disk sectors for permanently deleted files (Admin required)

SECURITY MODEL:
  ► is_malicious is determined STRICTLY by YARA rule matches.
  ► AI malware_score is logged for reference but does NOT affect quarantine.
  ► If YARA flags a file → QUARANTINE.
  ► If YARA clears a file → RECOVER.

Usage:
    python recover.py "C:\\Users\\Dell\\Desktop\\Test_folder"
    python recover.py "C:\\Users\\Dell\\Desktop\\Test_folder" --deep
    python recover.py --disk C --sectors 100000
"""

import os
import sys
import pickle
import shutil
import argparse
import numpy as np

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

from recovery.scanner import FolderScanner
from recovery.disk_scanner import DiskScanner, RecycleBinScanner
from recovery.yara_scanner import YARAScanner
from recovery.reconstructor import FileReconstructor
from recovery.integrity import IntegrityVerifier
from models.hybrid_recovery_model import HybridRecoveryModel

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(SCRIPT_DIR, "saved_models")
HYBRID_MODEL_PATH = os.path.join(MODELS_DIR, "hybrid_recovery_model.keras")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")


def load_model():
    """Load the AI model and label decoder."""
    model = HybridRecoveryModel()
    try:
        model.load(HYBRID_MODEL_PATH)
    except Exception as e:
        print(f"[!] Could not load hybrid model: {e}")
        print("    Run: python train_recovery.py")
        sys.exit(1)

    label_decoder = None
    if os.path.exists(LABEL_ENCODER_PATH):
        with open(LABEL_ENCODER_PATH, "rb") as f:
            le = pickle.load(f)
            label_decoder = le.classes_

    return model, label_decoder


def classify_candidate(candidate: dict, model, label_decoder, yara_scanner) -> dict:
    """
    Run AI classification and YARA scan on a file candidate.

    SECURITY: is_malicious is set ONLY by YARA results.
    The AI malware_score is stored for reporting but does NOT
    influence the quarantine decision.
    """
    byte_array = candidate["byte_array"].astype(np.float32)
    prediction = model.predict_single(byte_array)

    pred_idx = prediction["predicted_class_idx"]
    pred_type = label_decoder[pred_idx] if label_decoder is not None and pred_idx < len(label_decoder) else f"Type_{pred_idx}"
    confidence = prediction["confidence"]
    malware_score = prediction["malware_score"]
    risk_level = prediction["risk_level"]

    # ── STRICT YARA-ONLY malware decision ──
    is_malicious = False
    yara_threats = []
    if yara_scanner:
        try:
            with open(candidate["filepath"], "rb") as f:
                file_data = f.read()
            yara_result = yara_scanner.scan_bytes(file_data, candidate.get("filename", ""))
            is_malicious = yara_result["threat_detected"]   # ONLY YARA decides
            yara_threats = yara_result["threats"]
        except Exception:
            pass

    # NOTE: malware_score >= 0.7 check REMOVED — YARA is the sole authority

    candidate.update({
        "predicted_type": pred_type,
        "confidence": confidence,
        "malware_score": malware_score,
        "risk_level": risk_level,
        "yara_threats": yara_threats,
        "is_malicious": is_malicious,
    })
    return candidate


def main():
    parser = argparse.ArgumentParser(
        description="File Recovery System — Recover deleted, corrupted, and disguised files"
    )
    parser.add_argument("path", nargs="?", type=str, help="Folder path to scan")
    parser.add_argument("--deep", action="store_true",
                        help="Enable deep recovery: scan Recycle Bin + Raw Disk for deleted files")
    parser.add_argument("--disk", type=str, default=None,
                        help="Drive letter for raw disk scan (e.g., C). Requires Admin.")
    parser.add_argument("--sectors", type=int, default=200000,
                        help="Number of disk sectors to scan (default: 200000 ≈ 100MB)")
    parser.add_argument("--output", type=str, default="recovered_files",
                        help="Output directory for recovered files")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA malware scanning")
    args = parser.parse_args()

    if not args.path and not args.disk:
        parser.print_help()
        print("\nExample:")
        print('  python recover.py "C:\\Users\\Dell\\Desktop\\Test_folder"')
        print('  python recover.py "C:\\Users\\Dell\\Desktop\\Test_folder" --deep')
        print('  python recover.py --disk C --sectors 50000')
        sys.exit(1)

    print("\n" + "=" * 65)
    print("  FILE SIGNATURE RECOVERY & ANALYSIS SYSTEM v2.0")
    print("  AI-Powered Forensic File Recovery")
    print("=" * 65)

    # ── 1. Load AI Model ──
    print("\n[1] Loading AI models...")
    model, label_decoder = load_model()

    # ── 2. Initialize Components ──
    print("[2] Initializing components...")
    yara_scanner = YARAScanner() if not args.no_yara else None
    reconstructor = FileReconstructor(output_dir=args.output)
    verifier = IntegrityVerifier()
    all_results = []

    # ══════════════════════════════════════════════════════
    # MODE A: Scan existing files in a folder
    # ══════════════════════════════════════════════════════
    if args.path:
        target_path = args.path
        if not os.path.exists(target_path):
            print(f"[!] Path does not exist: {target_path}")
            sys.exit(1)

        print(f"\n{'─' * 65}")
        print(f"  MODE A: Folder Scan — {target_path}")
        print(f"{'─' * 65}")

        scanner = FolderScanner(target_path)
        total_files = scanner.count_files()
        print(f"  Found {total_files} existing file(s)")

        for i, candidate in enumerate(scanner.scan_generator(), 1):
            if candidate.get("error"):
                print(f"  [{i}/{total_files}] ✗ {candidate['filename']} — Error")
                candidate["action"] = "error"
                all_results.append(candidate)
                continue

            candidate = classify_candidate(candidate, model, label_decoder, yara_scanner)
            recon = reconstructor.reconstruct(
                filepath=candidate["filepath"],
                predicted_type=candidate["predicted_type"],
                header_intact=not candidate["header_empty"],
                is_malicious=candidate["is_malicious"],
                confidence=candidate["confidence"],
            )

            action = recon["action"]
            status_icon = "✓" if action == "recovered" else "⚠" if action == "quarantined" else "✗"
            print(f"  [{i}/{total_files}] {status_icon} {candidate['filename']} → "
                  f"{candidate['predicted_type']} ({candidate['confidence']*100:.0f}%) "
                  f"[{candidate['risk_level']}] → {action.upper()}")

            candidate["action"] = action
            candidate["repairs"] = recon.get("repairs", [])
            candidate["output_path"] = recon.get("output_path", "")
            candidate.pop("byte_array", None)
            all_results.append(candidate)

    # ══════════════════════════════════════════════════════
    # MODE B: Scan Recycle Bin (always if --deep)
    # ══════════════════════════════════════════════════════
    if args.deep or args.disk:
        print(f"\n{'─' * 65}")
        print(f"  MODE B: Recycle Bin Recovery")
        print(f"{'─' * 65}")

        rb_scanner = RecycleBinScanner(output_dir=args.output)
        rb_files = rb_scanner.scan()

        if rb_files:
            print(f"  Found {len(rb_files)} deleted file(s) in Recycle Bin")
            for i, candidate in enumerate(rb_files, 1):
                candidate = classify_candidate(candidate, model, label_decoder, yara_scanner)

                # Copy the deleted file to recovery folder
                recon = reconstructor.reconstruct(
                    filepath=candidate["filepath"],
                    predicted_type=candidate["predicted_type"],
                    header_intact=not candidate["header_empty"],
                    is_malicious=candidate["is_malicious"],
                    confidence=candidate["confidence"],
                )

                action = recon["action"]
                original = candidate.get("original_path", candidate["filename"])
                deleted_time = candidate.get("deleted_time", "?")
                status_icon = "✓" if action == "recovered" else "⚠"
                print(f"  [{i}] {status_icon} {os.path.basename(original)} "
                      f"(deleted: {deleted_time}) → {candidate['predicted_type']} → {action.upper()}")

                candidate["action"] = action
                candidate["repairs"] = recon.get("repairs", [])
                candidate["output_path"] = recon.get("output_path", "")
                candidate.pop("byte_array", None)
                all_results.append(candidate)
        else:
            print("  No deleted files found in Recycle Bin")

    # ══════════════════════════════════════════════════════
    # MODE C: Raw Disk Sector Scan (requires Admin)
    # ══════════════════════════════════════════════════════
    if args.disk:
        print(f"\n{'─' * 65}")
        print(f"  MODE C: Raw Disk Scan — {args.disk}: drive")
        print(f"{'─' * 65}")

        disk_scanner = DiskScanner(drive_letter=args.disk, output_dir=args.output)

        if not disk_scanner.is_admin:
            print("  [!] SKIPPED: Requires Administrator privileges.")
            print("      Right-click PowerShell → 'Run as Administrator'")
        else:
            found = disk_scanner.scan_for_deleted_files(
                max_sectors=args.sectors,
                progress_callback=lambda cur, total, found: (
                    print(f"\r  Scanning... {cur:,}/{total:,} sectors, {found} found", end="")
                    if cur % 10000 == 0 else None
                ),
            )

            print()
            for candidate in found:
                candidate = classify_candidate(candidate, model, label_decoder, yara_scanner)

                if candidate["is_malicious"]:
                    # Quarantine the carved file
                    quarantine_path = os.path.join("quarantine", f"QUARANTINE_{candidate['filename']}")
                    os.makedirs("quarantine", exist_ok=True)
                    shutil.move(candidate["filepath"], quarantine_path)
                    candidate["action"] = "quarantined"
                    print(f"  ⚠ {candidate['filename']} → QUARANTINED (malware)")
                else:
                    candidate["action"] = "recovered"
                    print(f"  ✓ {candidate['filename']} → {candidate['predicted_type']} "
                          f"(sector {candidate['disk_sector']:,})")

                candidate.pop("byte_array", None)
                all_results.append(candidate)

    # ══════════════════════════════════════════════════════
    # REPORT
    # ══════════════════════════════════════════════════════
    print(f"\n{'═' * 65}")
    print(f"  GENERATING FORENSIC REPORT")
    print(f"{'═' * 65}")

    scan_summary = {"target": args.path or f"{args.disk}: drive", "modes": []}
    if args.path:
        scan_summary["modes"].append("folder_scan")
    if args.deep or args.disk:
        scan_summary["modes"].append("recycle_bin")
    if args.disk:
        scan_summary["modes"].append("raw_disk")

    recon_summary = reconstructor.get_summary()
    report = verifier.generate_report(all_results, scan_summary, recon_summary)
    verifier.save_report(report)
    verifier.save_report_txt(report)

    # Final Summary
    totals = report["totals"]
    recovered = totals.get("recovered", 0)
    quarantined = totals.get("quarantined", 0)
    errors = totals.get("errors", 0)

    print(f"\n{'═' * 65}")
    print(f"  RECOVERY COMPLETE")
    print(f"{'─' * 65}")
    print(f"  Total Scanned     : {totals['total_files_scanned']}")
    print(f"  ✓ Recovered       : {recovered}")
    print(f"  ⚠ Quarantined     : {quarantined}")
    print(f"  ✗ Errors          : {errors}")
    print(f"  Output Folder     : {args.output}/")
    print(f"  Report            : outputs/")
    print(f"{'═' * 65}\n")


if __name__ == "__main__":
    main()
