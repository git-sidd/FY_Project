"""
test_recovery.py — End-to-End Recovery System Test
====================================================

Tests:
  1. Folder scan (finds f1, f3 — NOT f2 since it was deleted)
  2. Recycle Bin scan (finds f2 IF it's still in Recycle Bin)
  3. Raw disk scan (finds f2 even if Recycle Bin was emptied)
  4. Full combined report
"""

import os
import sys
import ctypes

# Add project root
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"


def check_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def main():
    import pickle
    import numpy as np

    from recovery.scanner import FolderScanner
    from recovery.disk_scanner import DiskScanner, RecycleBinScanner
    from recovery.yara_scanner import YARAScanner
    from recovery.reconstructor import FileReconstructor
    from recovery.integrity import IntegrityVerifier
    from models.hybrid_recovery_model import HybridRecoveryModel

    is_admin = check_admin()

    print("=" * 65)
    print("  FILE RECOVERY SYSTEM — COMPLETE TEST")
    print("=" * 65)
    print(f"  Admin mode: {'YES ✓ (raw disk scanning enabled)' if is_admin else 'NO (Recycle Bin only)'}")
    print()

    # ── Load Model ──
    print("[1] Loading AI Model...")
    model = HybridRecoveryModel()
    model_path = os.path.join(SCRIPT_DIR, "saved_models", "hybrid_recovery_model.keras")
    le_path = os.path.join(SCRIPT_DIR, "saved_models", "label_encoder.pkl")

    if not os.path.exists(model_path):
        print("    [!] No hybrid model found. Run: python train_recovery.py first")
        sys.exit(1)

    model.load(model_path)

    label_decoder = None
    if os.path.exists(le_path):
        with open(le_path, "rb") as f:
            le = pickle.load(f)
            label_decoder = le.classes_
        print(f"    Label decoder loaded: {len(label_decoder)} file types")
    print()

    # ── Components ──
    yara = YARAScanner()
    reconstructor = FileReconstructor(
        output_dir=os.path.join(SCRIPT_DIR, "recovered_files"),
        quarantine_dir=os.path.join(SCRIPT_DIR, "quarantine"),
    )
    verifier = IntegrityVerifier(output_dir=os.path.join(SCRIPT_DIR, "outputs"))
    all_results = []

    def classify_and_recover(candidate):
        """Helper: classify a candidate file and attempt recovery."""
        if candidate.get("error"):
            candidate["action"] = "error"
            candidate.pop("byte_array", None)
            all_results.append(candidate)
            return

        byte_array = candidate["byte_array"].astype(np.float32)
        pred = model.predict_single(byte_array)

        pred_idx = pred["predicted_class_idx"]
        pred_type = label_decoder[pred_idx] if label_decoder is not None and pred_idx < len(label_decoder) else f"Type_{pred_idx}"

        # YARA scan
        is_malicious = pred["malware_score"] >= 0.7
        yara_threats = []
        try:
            with open(candidate["filepath"], "rb") as f:
                file_data = f.read()
            yr = yara.scan_bytes(file_data, candidate.get("filename", ""))
            is_malicious = is_malicious or yr["threat_detected"]
            yara_threats = yr["threats"]
        except Exception:
            pass

        recon = reconstructor.reconstruct(
            filepath=candidate["filepath"],
            predicted_type=pred_type,
            header_intact=not candidate["header_empty"],
            is_malicious=is_malicious,
            confidence=pred["confidence"],
        )

        action = recon["action"]
        icon = "✓" if action == "recovered" else "⚠"
        src = candidate.get("source", "folder")

        print(f"    {icon} [{src}] {candidate['filename']}")
        print(f"       Type: {pred_type} ({pred['confidence']*100:.1f}%) | Risk: {pred['risk_level']} | → {action.upper()}")
        if recon.get("repairs"):
            for r in recon["repairs"]:
                print(f"       Repair: {r}")
        if yara_threats:
            for t in yara_threats:
                print(f"       ⚠ YARA: {t['rule']}")

        candidate.update({
            "predicted_type": pred_type,
            "confidence": pred["confidence"],
            "malware_score": pred["malware_score"],
            "risk_level": pred["risk_level"],
            "yara_threats": yara_threats,
            "action": action,
            "repairs": recon.get("repairs", []),
            "output_path": recon.get("output_path", ""),
        })
        candidate.pop("byte_array", None)
        all_results.append(candidate)

    # ══════════════════════════════════════════════════════
    # TEST 1: Folder Scan (finds existing files only)
    # ══════════════════════════════════════════════════════
    test_folder = os.path.join(os.path.expanduser("~"), "Desktop", "Test_folder")

    if os.path.exists(test_folder):
        print(f"[2] FOLDER SCAN — {test_folder}")
        print("─" * 65)
        print("    (Note: deleted f2 will NOT appear here — that's expected)\n")

        scanner = FolderScanner(test_folder)
        total = scanner.count_files()
        print(f"    Visible files: {total}")
        print()

        for candidate in scanner.scan_generator():
            classify_and_recover(candidate)

        print()
    else:
        print(f"[2] FOLDER SCAN — Test_folder not found at {test_folder}")
        print("    Create it first: New folder → Desktop → Test_folder")
        print("    Add files f1.txt, f2.txt, f3.txt, then delete f2.txt")
        print()

    # ══════════════════════════════════════════════════════
    # TEST 2: Recycle Bin Scan
    # ══════════════════════════════════════════════════════
    print("[3] RECYCLE BIN SCAN")
    print("─" * 65)
    print("    Scanning all Recycle Bin locations...")

    rb_scanner = RecycleBinScanner(
        output_dir=os.path.join(SCRIPT_DIR, "recovered_files")
    )
    rb_files = rb_scanner.scan()
    print(f"    Files found in Recycle Bin: {len(rb_files)}")
    print()

    if rb_files:
        for candidate in rb_files:
            orig = candidate.get("original_path", candidate["filename"])
            deleted = candidate.get("deleted_time", "unknown time")
            print(f"    Found: {os.path.basename(orig)} (deleted at {deleted})")
            classify_and_recover(candidate)
    else:
        print("    No files found in Recycle Bin.")
        print("    (Either Recycle Bin is empty, or f2 was permanently deleted)")
    print()

    # ══════════════════════════════════════════════════════
    # TEST 3: Raw Disk Scan (Admin required)
    # ══════════════════════════════════════════════════════
    print("[4] RAW DISK SCAN (finds permanently deleted files)")
    print("─" * 65)

    if not is_admin:
        print("    ⚠ NOT RUNNING AS ADMINISTRATOR")
        print("    To recover permanently deleted files (Recycle Bin emptied):")
        print("    ┌─────────────────────────────────────────────────────────┐")
        print("    │ 1. Close this terminal                                  │")
        print("    │ 2. Search 'PowerShell' in Start Menu                    │")
        print("    │ 3. Right-click → 'Run as Administrator'                 │")
        print("    │ 4. cd c:\\Users\\Dell\\Desktop\\FY_Project\\file_signature_recovery │")
        print("    │ 5. python test_recovery.py                               │")
        print("    └─────────────────────────────────────────────────────────┘")
    else:
        print("    ✓ Running as Administrator — raw disk access enabled")
        print("    Scanning C: drive sectors (up to 50,000 sectors ≈ 25MB)")
        print("    This may take 1-2 minutes...")
        print()

        disk_scanner = DiskScanner(
            drive_letter="C",
            output_dir=os.path.join(SCRIPT_DIR, "recovered_files"),
        )

        found = disk_scanner.scan_for_deleted_files(
            max_sectors=50000,
            start_sector=0,
            progress_callback=lambda cur, total, found: (
                print(f"\r    Progress: {cur:,}/{total:,} sectors | Found: {found}", end="", flush=True)
                if cur % 5000 == 0 else None
            ),
        )

        print()
        summary = disk_scanner.get_summary()
        print(f"\n    Sectors scanned: {summary['sectors_scanned']:,}")
        print(f"    Data scanned: {summary['data_scanned_mb']:.1f} MB")
        print(f"    Files found: {summary['files_found']}")

        if found:
            print()
            for candidate in found:
                classify_and_recover(candidate)

    print()

    # ══════════════════════════════════════════════════════
    # GENERATE REPORT
    # ══════════════════════════════════════════════════════
    print("[5] GENERATING FORENSIC REPORT")
    print("─" * 65)

    scan_summary = {
        "test_folder": test_folder,
        "admin_mode": is_admin,
        "total_sources": ["folder_scan", "recycle_bin"] + (["raw_disk"] if is_admin else []),
    }
    recon_summary = reconstructor.get_summary()
    report = verifier.generate_report(all_results, scan_summary, recon_summary)
    json_path = verifier.save_report(report)
    txt_path = verifier.save_report_txt(report)

    # ══════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════════════════
    totals = report["totals"]
    print()
    print("=" * 65)
    print("  TEST RESULTS SUMMARY")
    print("=" * 65)
    print(f"  Total files processed : {totals['total_files_scanned']}")
    print(f"  ✓ Recovered           : {totals['recovered']}")
    print(f"  ⚠ Quarantined         : {totals['quarantined']}")
    print(f"  ✗ Errors              : {totals['errors']}")
    print()
    print(f"  Recovered files saved to : recovered_files/")
    print(f"  JSON Report              : {json_path}")
    print(f"  Text Report              : {txt_path}")
    print()

    recovered_list = [r for r in all_results if r.get("action") == "recovered"]
    if recovered_list:
        print("  All Recovered Files:")
        for r in recovered_list:
            src = r.get("source", "folder")
            print(f"    → [{src}] {r['filename']} → {r['predicted_type']} ({r.get('confidence', 0)*100:.0f}%)")
    print("=" * 65)


if __name__ == "__main__":
    main()
