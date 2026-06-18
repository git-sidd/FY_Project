# """
# Deleted File Recovery Orchestrator
# =====================================

# Central coordinator that chains all recovery methods together to recover
# files that have been permanently deleted (even after emptying the Recycle Bin).

# Recovery pipeline (executed in order):
#   1. Recycle Bin scan      — check if file is still in trash
#   2. NTFS MFT scan         — parse deleted MFT entries & recover via data runs
#   3. USN Journal scan      — find deletion events, correlate with MFT
#   4. Signature-based carving — raw disk scanning as fallback
#   5. Heuristic matching    — score & deduplicate across all methods

# Each method produces results in a unified format that the existing
# recovery/reporting pipeline can consume.

# REQUIRES: Administrator privileges for methods 2–4.
# """

# import os
# import sys
# import ctypes
# import hashlib
# import datetime
# import difflib
# from pathlib import Path
# from typing import Optional

# from recovery.disk_scanner import DiskScanner, RecycleBinScanner, DISK_SIGNATURES
# from recovery.mft_parser import MFTParser, MFTEntry
# from recovery.journal_scanner import USNJournalScanner


# # ═══════════════════════════════════════════════════════
# # Filesystem detection
# # ═══════════════════════════════════════════════════════

# def _detect_filesystem(path: str) -> dict:
#     """
#     Detect the filesystem type and drive letter for *path*.

#     Uses ``GetVolumeInformationW`` on Windows.
#     Returns dict with keys: drive_letter, filesystem, volume_name.
#     """
#     drive = os.path.splitdrive(os.path.abspath(path))[0]
#     if not drive:
#         drive = "C:"
#     root = drive + "\\"

#     result = {
#         "drive_letter": drive.rstrip(":"),
#         "root": root,
#         "filesystem": "UNKNOWN",
#         "volume_name": "",
#     }

#     try:
#         vol_name_buf = ctypes.create_unicode_buffer(256)
#         fs_name_buf = ctypes.create_unicode_buffer(256)
#         serial = ctypes.wintypes.DWORD(0)
#         max_len = ctypes.wintypes.DWORD(0)
#         flags = ctypes.wintypes.DWORD(0)

#         ok = ctypes.windll.kernel32.GetVolumeInformationW(
#             root,
#             vol_name_buf, 256,
#             ctypes.byref(serial),
#             ctypes.byref(max_len),
#             ctypes.byref(flags),
#             fs_name_buf, 256,
#         )
#         if ok:
#             result["filesystem"] = fs_name_buf.value  # e.g. "NTFS", "FAT32", "exFAT"
#             result["volume_name"] = vol_name_buf.value
#     except Exception:
#         pass

#     return result


# # ═══════════════════════════════════════════════════════
# # Confidence scoring
# # ═══════════════════════════════════════════════════════

# def _compute_confidence(
#     candidate_name: str,
#     candidate_path: str,
#     candidate_time: Optional[datetime.datetime],
#     candidate_size: int,
#     *,
#     original_folder: str,
#     target_filename: Optional[str] = None,
#     target_extension: Optional[str] = None,
#     time_start: Optional[datetime.datetime] = None,
#     time_end: Optional[datetime.datetime] = None,
# ) -> float:
#     """
#     Heuristic confidence score (0.0–1.0) for how likely a candidate
#     matches the user's recovery request.
#     """
#     score = 0.0

#     # ── Filename match (+0.30) ──
#     if target_filename:
#         ratio = difflib.SequenceMatcher(
#             None, target_filename.lower(), candidate_name.lower()
#         ).ratio()
#         score += 0.30 * ratio
#     else:
#         # No filename filter — give partial credit if candidate has a name
#         score += 0.10 if candidate_name else 0.0

#     # ── Extension match (+0.20) ──
#     if target_extension:
#         ext = target_extension if target_extension.startswith(".") else f".{target_extension}"
#         cand_ext = Path(candidate_name).suffix.lower()
#         if cand_ext == ext.lower():
#             score += 0.20
#     else:
#         score += 0.05  # Slight credit if no extension filter

#     # ── Parent directory path match (+0.20) ──
#     if original_folder and candidate_path:
#         folder_norm = os.path.normpath(original_folder).lower()
#         cand_dir = os.path.dirname(os.path.normpath(candidate_path)).lower()
#         if cand_dir == folder_norm:
#             score += 0.20
#         elif cand_dir.startswith(folder_norm):
#             score += 0.10

#     # ── Timestamp within range (+0.15) ──
#     if candidate_time:
#         in_range = True
#         if time_start and candidate_time < time_start:
#             in_range = False
#         if time_end and candidate_time > time_end:
#             in_range = False
#         if in_range:
#             score += 0.15
#     else:
#         score += 0.05  # Unknown time

#     # ── File size plausibility (+0.15) ──
#     if candidate_size > 0:
#         score += 0.15
#     # Zero-size files are suspicious

#     return min(1.0, score)


# # ═══════════════════════════════════════════════════════
# # Orchestrator
# # ═══════════════════════════════════════════════════════

# class DeletedFileRecovery:
#     """
#     Orchestrates multiple recovery methods to find and restore
#     permanently deleted files.

#     Usage::

#         recovery = DeletedFileRecovery(output_dir="recovered_files")
#         results = recovery.recover(
#             original_folder_path="C:\\\\Users\\\\Dell\\\\Documents",
#             filename="report.pdf",
#             extension=".pdf",
#         )
#     """

#     def __init__(self, output_dir: str = "recovered_files"):
#         self.output_dir = Path(output_dir)
#         self.output_dir.mkdir(parents=True, exist_ok=True)
#         self.is_admin = self._check_admin()

#     @staticmethod
#     def _check_admin() -> bool:
#         try:
#             return ctypes.windll.shell32.IsUserAnAdmin() != 0
#         except Exception:
#             return False

#     def recover(
#         self,
#         original_folder_path: str,
#         filename: Optional[str] = None,
#         extension: Optional[str] = None,
#         deletion_time_start: Optional[str] = None,
#         deletion_time_end: Optional[str] = None,
#         max_mft_entries: int = 300_000,
#         max_disk_sectors: int = 200_000,
#         progress_callback=None,
#     ) -> list[dict]:
#         """
#         Run the full recovery pipeline.

#         Parameters
#         ----------
#         original_folder_path : str
#             The folder where the deleted file(s) originally lived.
#         filename : str, optional
#             Filename (or partial name) to search for.
#         extension : str, optional
#             File extension to filter (e.g. ".pdf").
#         deletion_time_start / deletion_time_end : str, optional
#             ISO-format datetime strings bounding the deletion window.
#         max_mft_entries : int
#             Maximum MFT entries to scan.
#         max_disk_sectors : int
#             Maximum disk sectors to scan for signature carving.
#         progress_callback : callable, optional
#             Called with (phase: str, detail: str, pct: float).

#         Returns
#         -------
#         list[dict]
#             Unified recovery results — one dict per recovered candidate.
#         """
#         all_results: list[dict] = []

#         # Parse time range
#         time_start = _parse_iso(deletion_time_start)
#         time_end = _parse_iso(deletion_time_end)

#         # Detect filesystem
#         fs_info = _detect_filesystem(original_folder_path)
#         drive = fs_info["drive_letter"]
#         fs_type = fs_info["filesystem"]

#         if progress_callback:
#             progress_callback("init", f"Filesystem: {fs_type} on {drive}:", 0.0)

#         # ── PHASE 1: Recycle Bin ─────────────────────────
#         if progress_callback:
#             progress_callback("recycle_bin", "Scanning Recycle Bin...", 0.05)

#         try:
#             rb_results = self._phase_recycle_bin(
#                 original_folder_path, filename, extension, time_start, time_end
#             )
#             all_results.extend(rb_results)
#         except Exception as e:
#             print(f"[!] Recycle Bin phase error: {e}")

#         if progress_callback:
#             progress_callback("recycle_bin",
#                               f"Recycle Bin: {len(all_results)} file(s) found", 0.15)

#         # ── PHASE 2: NTFS MFT ───────────────────────────
#         if fs_type == "NTFS" and self.is_admin:
#             if progress_callback:
#                 progress_callback("mft", "Parsing NTFS MFT...", 0.20)

#             try:
#                 mft_results, mft_entry_map = self._phase_mft(
#                     drive, original_folder_path, filename, extension,
#                     time_start, time_end, max_mft_entries, progress_callback,
#                 )
#                 all_results.extend(mft_results)
#             except Exception as e:
#                 print(f"[!] MFT phase error: {e}")
#                 mft_entry_map = {}

#             if progress_callback:
#                 progress_callback("mft",
#                                   f"MFT: {len(mft_results)} file(s) recovered", 0.45)

#             # ── PHASE 3: USN Journal ─────────────────────
#             if progress_callback:
#                 progress_callback("journal", "Reading USN Journal...", 0.50)

#             try:
#                 journal_results = self._phase_journal(
#                     drive, mft_entry_map, original_folder_path, filename, extension,
#                     time_start, time_end, progress_callback,
#                 )
#                 all_results.extend(journal_results)
#             except Exception as e:
#                 print(f"[!] USN Journal phase error: {e}")

#             if progress_callback:
#                 progress_callback("journal",
#                                   f"Journal: {len(journal_results)} additional match(es)", 0.60)
#         else:
#             if not self.is_admin:
#                 print("[!] Skipping MFT/Journal phases — Admin required")
#             elif fs_type != "NTFS":
#                 print(f"[!] Skipping MFT/Journal phases — filesystem is {fs_type}, not NTFS")

#         # ── PHASE 4: Signature-based carving ─────────────
#         if self.is_admin:
#             if progress_callback:
#                 progress_callback("carving", "Raw disk signature carving...", 0.65)

#             try:
#                 carving_results = self._phase_carving(
#                     drive, original_folder_path, filename, extension,
#                     time_start, time_end, max_disk_sectors, progress_callback,
#                 )
#                 all_results.extend(carving_results)
#             except Exception as e:
#                 print(f"[!] Carving phase error: {e}")

#             if progress_callback:
#                 progress_callback("carving",
#                                   f"Carving: {len(carving_results)} fragment(s) carved", 0.85)

#         # ── PHASE 5: Deduplicate & score ─────────────────
#         if progress_callback:
#             progress_callback("scoring", "Scoring & deduplicating results...", 0.90)

#         all_results = self._deduplicate(all_results)

#         # Final sort by confidence (highest first)
#         all_results.sort(key=lambda r: r.get("confidence_score", 0), reverse=True)

#         if progress_callback:
#             progress_callback("done",
#                               f"Recovery complete: {len(all_results)} file(s)", 1.0)

#         return all_results

#     # ══════════════════════════════════════════════════════
#     # Phase implementations
#     # ══════════════════════════════════════════════════════

#     def _phase_recycle_bin(self, folder_path, filename, extension, time_start, time_end):
#         """Phase 1 — Recycle Bin recovery."""
#         scanner = RecycleBinScanner(output_dir=str(self.output_dir))
#         matched = scanner.scan_folder(folder_path)
#         results = []

#         for entry in matched:
#             fname = entry.get("filename", "")
#             orig_path = entry.get("original_path", "")

#             # Apply additional filters
#             if filename and filename.lower() not in fname.lower():
#                 continue
#             if extension:
#                 ext = extension if extension.startswith(".") else f".{extension}"
#                 if Path(fname).suffix.lower() != ext.lower():
#                     continue

#             del_time_str = entry.get("deleted_time", "")
#             del_time = _parse_iso(del_time_str)
#             if time_start and del_time and del_time < time_start:
#                 continue
#             if time_end and del_time and del_time > time_end:
#                 continue

#             # Copy $R file to output
#             src = Path(entry.get("filepath", ""))
#             dest = self.output_dir / fname
#             if dest.exists():
#                 dest = self.output_dir / f"{dest.stem}_rb{dest.suffix}"

#             recovered_path = ""
#             sha256 = ""
#             status = "failed"
#             warnings = []
#             try:
#                 if src.exists():
#                     import shutil
#                     shutil.copy2(str(src), str(dest))
#                     sha256 = hashlib.sha256(dest.read_bytes()).hexdigest()
#                     recovered_path = str(dest)
#                     status = "recovered"
#                 else:
#                     warnings.append(f"$R file not found: {src}")
#             except Exception as e:
#                 warnings.append(str(e))

#             conf = _compute_confidence(
#                 fname, orig_path, del_time,
#                 entry.get("file_size", 0),
#                 original_folder=folder_path,
#                 target_filename=filename,
#                 target_extension=extension,
#                 time_start=time_start,
#                 time_end=time_end,
#             )

#             results.append({
#                 "filename": fname,
#                 "original_path": orig_path,
#                 "recovered_path": recovered_path,
#                 "file_size": entry.get("file_size", 0),
#                 "sha256": sha256,
#                 "recovery_method": "recycle_bin",
#                 "confidence_score": round(conf, 3),
#                 "status": status,
#                 "warnings": warnings,
#                 "metadata": {
#                     "created_time": "",
#                     "modified_time": "",
#                     "deleted_time": del_time_str,
#                     "mft_entry_number": None,
#                     "disk_sector": None,
#                 },
#             })

#         return results

#     def _phase_mft(self, drive, folder_path, filename, extension,
#                    time_start, time_end, max_entries, progress_callback):
#         """Phase 2 — NTFS MFT parsing & recovery."""
#         parser = MFTParser(drive_letter=drive, output_dir=str(self.output_dir))

#         def mft_progress(scanned, deleted_found):
#             if progress_callback:
#                 pct = 0.20 + 0.20 * min(scanned / max_entries, 1.0)
#                 progress_callback("mft", f"MFT: {scanned:,} entries scanned, "
#                                          f"{deleted_found} deleted", pct)

#         parser.parse_mft(max_entries=max_entries, deleted_only=False,
#                          progress_callback=mft_progress)

#         # Find matches
#         matches = parser.find_deleted_entries(
#             folder_path=folder_path,
#             filename=filename,
#             extension=extension,
#             time_start=time_start,
#             time_end=time_end,
#         )

#         results = []
#         for mft_entry in matches:
#             rec = parser.recover_entry(mft_entry, dest_dir=str(self.output_dir))

#             # Compute confidence
#             ts = mft_entry.modified_time or mft_entry.mft_changed_time
#             conf = _compute_confidence(
#                 mft_entry.filename, mft_entry.full_path, ts,
#                 mft_entry.file_size,
#                 original_folder=folder_path,
#                 target_filename=filename,
#                 target_extension=extension,
#                 time_start=time_start,
#                 time_end=time_end,
#             )
#             rec["confidence_score"] = round(conf, 3)
#             results.append(rec)

#         return results, parser._entry_map

#     def _phase_journal(self, drive, mft_entry_map, original_folder_path, filename, extension,
#                        time_start, time_end, progress_callback):
#         """Phase 3 — USN Journal correlation."""
#         journal = USNJournalScanner(drive_letter=drive)
#         if not journal.query_journal():
#             return []

#         def j_progress(read, found):
#             if progress_callback:
#                 progress_callback("journal", f"USN: {read:,} records, {found} deletions", 0.55)

#         journal.read_deletion_events(max_records=200_000, progress_callback=j_progress)

#         # Filter deletions
#         filtered = journal.find_deletions(
#             filename=filename, extension=extension,
#             time_start=time_start, time_end=time_end,
#         )

#         # Correlate with MFT — only recover entries not already recovered in Phase 2
#         already_recovered = set()
#         correlated = []
#         for usn in filtered:
#             mft_num = usn.file_reference_number & 0x0000FFFFFFFFFFFF
#             if mft_num in mft_entry_map and mft_num not in already_recovered:
#                 mft_e = mft_entry_map[mft_num]
#                 if mft_e.is_deleted and not mft_e.is_directory:
#                     # Filter by folder path
#                     if original_folder_path:
#                         folder_norm = os.path.normpath(original_folder_path).lower()
#                         entry_dir = os.path.dirname(os.path.normpath(mft_e.full_path)).lower()
#                         if not entry_dir.startswith(folder_norm):
#                             continue
#                     correlated.append((usn, mft_e))
#                     already_recovered.add(mft_num)

#         # Recover correlated entries
#         results = []
#         if correlated:
#             parser = MFTParser(drive_letter=drive, output_dir=str(self.output_dir))
#             # Re-use existing boot-sector info
#             for usn_entry, mft_entry in correlated:
#                 rec = parser.recover_entry(mft_entry, dest_dir=str(self.output_dir))
#                 rec["recovery_method"] = "usn_journal"
#                 rec["metadata"]["deleted_time"] = (
#                     usn_entry.timestamp.isoformat() if usn_entry.timestamp else ""
#                 )

#                 conf = _compute_confidence(
#                     mft_entry.filename, mft_entry.full_path,
#                     usn_entry.timestamp, mft_entry.file_size,
#                     original_folder=original_folder_path,
#                     target_filename=filename,
#                     target_extension=extension,
#                     time_start=time_start,
#                     time_end=time_end,
#                 )
#                 rec["confidence_score"] = round(conf, 3)
#                 results.append(rec)

#         return results

#     def _phase_carving(self, drive, folder_path, filename, extension,
#                        time_start, time_end, max_sectors, progress_callback):
#         """Phase 4 — Signature-based raw disk carving."""
#         # If extension specified, narrow the signatures to scan for
#         target_sigs = None
#         if extension:
#             ext = extension if extension.startswith(".") else f".{extension}"
#             target_sigs = {k: v for k, v in DISK_SIGNATURES.items()
#                            if v.get("extension", "").lower() == ext.lower()}
#             if not target_sigs:
#                 target_sigs = None  # Fallback to all signatures

#         scanner = DiskScanner(drive_letter=drive, output_dir=str(self.output_dir))

#         # Temporarily override signatures if filtering
#         original_sigs = None
#         if target_sigs:
#             original_sigs = dict(DISK_SIGNATURES)
#             DISK_SIGNATURES.clear()
#             DISK_SIGNATURES.update(target_sigs)

#         try:
#             def carve_progress(cur, total, found):
#                 if progress_callback:
#                     pct = 0.65 + 0.20 * min(cur / max(total, 1), 1.0)
#                     progress_callback("carving",
#                                       f"Carving: sector {cur:,}/{total:,}, {found} found",
#                                       pct)

#             found = scanner.scan_for_deleted_files(
#                 max_sectors=max_sectors,
#                 progress_callback=carve_progress,
#             )
#         finally:
#             if original_sigs is not None:
#                 DISK_SIGNATURES.clear()
#                 DISK_SIGNATURES.update(original_sigs)

#         # Convert DiskScanner results to unified format
#         results = []
#         for f in found:
#             fname = f.get("filename", "")
#             conf = _compute_confidence(
#                 fname, "", None, f.get("carved_size", 0),
#                 original_folder=folder_path,
#                 target_filename=filename,
#                 target_extension=extension,
#                 time_start=time_start,
#                 time_end=time_end,
#             )

#             results.append({
#                 "filename": fname,
#                 "original_path": "",
#                 "recovered_path": f.get("filepath", ""),
#                 "file_size": f.get("carved_size", 0),
#                 "sha256": f.get("sha256", ""),
#                 "recovery_method": "signature_carving",
#                 "confidence_score": round(conf, 3),
#                 "status": "recovered",
#                 "warnings": [
#                     "Recovered via raw disk carving — file may be incomplete or corrupted",
#                     f"Carved from sector {f.get('disk_sector', '?')}",
#                 ],
#                 "metadata": {
#                     "created_time": "",
#                     "modified_time": "",
#                     "deleted_time": "",
#                     "mft_entry_number": None,
#                     "disk_sector": f.get("disk_sector"),
#                 },
#             })

#         return results

#     # ══════════════════════════════════════════════════════
#     # Deduplication
#     # ══════════════════════════════════════════════════════

#     def _deduplicate(self, results: list[dict]) -> list[dict]:
#         """
#         Remove duplicates found by different methods.
#         Keeps the result with the highest confidence score per unique SHA-256.
#         """
#         seen: dict[str, dict] = {}
#         unique = []

#         for r in results:
#             sha = r.get("sha256", "")
#             if not sha or sha == "":
#                 unique.append(r)
#                 continue

#             if sha in seen:
#                 if r.get("confidence_score", 0) > seen[sha].get("confidence_score", 0):
#                     # Replace the previous entry
#                     unique = [x for x in unique if x.get("sha256") != sha]
#                     unique.append(r)
#                     seen[sha] = r
#             else:
#                 seen[sha] = r
#                 unique.append(r)

#         return unique


# # ═══════════════════════════════════════════════════════
# # Helpers
# # ═══════════════════════════════════════════════════════

# def _parse_iso(s: Optional[str]) -> Optional[datetime.datetime]:
#     """Parse an ISO datetime string, returning None on failure."""
#     if not s:
#         return None
#     try:
#         return datetime.datetime.fromisoformat(s)
#     except (ValueError, TypeError):
#         return None


# # ═══════════════════════════════════════════════════════
# # Main — quick test
# # ═══════════════════════════════════════════════════════

# if __name__ == "__main__":
#     import sys

#     folder = sys.argv[1] if len(sys.argv) > 1 else "C:\\Users"
#     fn = sys.argv[2] if len(sys.argv) > 2 else None

#     recovery = DeletedFileRecovery(output_dir="recovered_files")

#     def show_progress(phase, detail, pct):
#         print(f"  [{phase}] {detail}  ({pct*100:.0f}%)")

#     results = recovery.recover(
#         original_folder_path=folder,
#         filename=fn,
#         progress_callback=show_progress,
#     )

#     print(f"\n{'='*60}")
#     print(f"  RESULTS: {len(results)} file(s)")
#     print(f"{'='*60}")
#     for r in results:
#         print(f"  {r['filename']}")
#         print(f"    Method:     {r['recovery_method']}")
#         print(f"    Confidence: {r['confidence_score']*100:.0f}%")
#         print(f"    Status:     {r['status']}")
#         if r['warnings']:
#             for w in r['warnings']:
#                 print(f"    ⚠ {w}")
#         print()


#------------------------------------------------------------------
"""
deleted_file_recovery.py — Forensic Recovery of Permanently Deleted Files
==========================================================================
 
Recovers files that have been deleted even after the Recycle Bin / Trash
has been emptied.  No filesystem metadata is assumed to be intact.
 
Strategy (layered, fastest → deepest):
  1. Recycle Bin check  — files may still be in $Recycle.Bin even if the
     user thinks they are gone (quick, zero-privilege).
  2. Raw disk sector carve — reads the volume that hosted the original
     folder and searches unallocated space for file-signature magic bytes
     (requires Administrator on Windows).
 
The caller (PermanentRecoveryThread in main.py) expects:
 
    orchestrator = DeletedFileRecovery(output_dir=dest_dir)
    results = orchestrator.recover(
        original_folder_path = str,
        filename             = str | None,   # optional name filter
        extension            = str | None,   # optional ext filter  e.g. "pdf"
        deletion_time_start  = str | None,   # ISO-8601
        deletion_time_end    = str | None,   # ISO-8601
        progress_callback    = callable,     # (phase, detail, pct:float 0-1)
    )
 
Each result dict must contain at minimum:
    status          : "recovered" | "error"
    recovered_path  : str   — absolute path to the file on disk
    filename        : str
    original_path   : str
    file_size       : int
    sha256          : str
"""
 
from __future__ import annotations
 
import datetime
import hashlib
import os
import shutil
from pathlib import Path
from typing import Callable, Optional
 
from recovery.disk_scanner import DiskScanner, RecycleBinScanner, DISK_SIGNATURES
 
# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
 
def _iso_to_dt(iso: Optional[str]) -> Optional[datetime.datetime]:
    """Convert an ISO-8601 string to a naive datetime, or return None."""
    if not iso:
        return None
    try:
        return datetime.datetime.fromisoformat(iso)
    except ValueError:
        return None
 
 
def _sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
 
 
def _ext_filter_matches(filename: str, extension: Optional[str]) -> bool:
    """Return True when *filename* ends with the requested extension (if any)."""
    if not extension:
        return True
    ext = extension.lstrip(".").lower()
    return filename.lower().endswith(f".{ext}")
 
 
def _name_filter_matches(filename: str, name_filter: Optional[str]) -> bool:
    """Return True when *filename* contains the requested name fragment (if any)."""
    if not name_filter:
        return True
    return name_filter.lower() in filename.lower()
 
 
def _time_filter_matches(
    deleted_time_str: Optional[str],
    start: Optional[datetime.datetime],
    end: Optional[datetime.datetime],
) -> bool:
    """Return True when *deleted_time_str* falls within [start, end]."""
    if start is None and end is None:
        return True
    if not deleted_time_str or deleted_time_str in ("unknown", ""):
        # Cannot determine time — include by default so we don't miss files
        return True
    try:
        dt = datetime.datetime.fromisoformat(deleted_time_str)
    except ValueError:
        return True
    if start and dt < start:
        return False
    if end and dt > end:
        return False
    return True
 
 
def _drive_letter_from_path(path: str) -> str:
    """Extract the drive letter from an absolute Windows path (e.g. 'C')."""
    p = os.path.abspath(path)
    if len(p) >= 2 and p[1] == ":":
        return p[0].upper()
    return "C"  # sensible fallback
 
 
# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------
 
class DeletedFileRecovery:
    """
    Orchestrates multi-stage forensic recovery of permanently deleted files.
 
    Parameters
    ----------
    output_dir : str
        Directory where recovered files will be written.
    """
 
    def __init__(self, output_dir: str = "recovered_files"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
 
    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------
 
    def recover(
        self,
        original_folder_path: str,
        filename: Optional[str] = None,
        extension: Optional[str] = None,
        deletion_time_start: Optional[str] = None,
        deletion_time_end: Optional[str] = None,
        progress_callback: Optional[Callable[[str, str, float], None]] = None,
    ) -> list[dict]:
        """
        Attempt to recover files that were permanently deleted from
        *original_folder_path*.
 
        Parameters
        ----------
        original_folder_path : str
            The folder the files lived in before deletion.
        filename : str, optional
            Filter: only recover files whose name contains this string.
        extension : str, optional
            Filter: only recover files with this extension (e.g. ``"pdf"``).
        deletion_time_start : str, optional
            ISO-8601 lower bound on deletion timestamp.
        deletion_time_end : str, optional
            ISO-8601 upper bound on deletion timestamp.
        progress_callback : callable, optional
            ``callback(phase: str, detail: str, pct: float)`` where pct is
            in [0.0, 1.0].
 
        Returns
        -------
        list of dict — one entry per recovered file.
        """
        def _cb(phase: str, detail: str, pct: float):
            if progress_callback:
                progress_callback(phase, detail, max(0.0, min(1.0, pct)))
 
        time_start = _iso_to_dt(deletion_time_start)
        time_end   = _iso_to_dt(deletion_time_end)
 
        all_results: list[dict] = []
 
        # ── Stage 1: Recycle Bin (fast, no privileges needed) ──────────────
        _cb("recycle_bin", "Scanning Recycle Bin for matching entries…", 0.0)
        rb_results = self._stage_recycle_bin(
            original_folder_path, filename, extension,
            time_start, time_end, _cb,
        )
        all_results.extend(rb_results)
        _cb("recycle_bin", f"Recycle Bin stage done — {len(rb_results)} file(s) found", 0.25)
 
        # ── Stage 2: Raw disk carve (deeper, needs Admin) ──────────────────
        _cb("disk_carve", "Starting raw disk sector scan for carved signatures…", 0.26)
        disk_results = self._stage_disk_carve(
            original_folder_path, filename, extension, _cb,
        )
        all_results.extend(disk_results)
        _cb("disk_carve", f"Disk carve stage done — {len(disk_results)} fragment(s) found", 1.0)
 
        return all_results
 
    # ------------------------------------------------------------------
    # Stage 1 — Recycle Bin
    # ------------------------------------------------------------------
 
    def _stage_recycle_bin(
        self,
        folder_path: str,
        filename: Optional[str],
        extension: Optional[str],
        time_start: Optional[datetime.datetime],
        time_end: Optional[datetime.datetime],
        cb: Callable,
    ) -> list[dict]:
        """
        Restore files from the Windows Recycle Bin whose original path
        resided inside *folder_path*.
        """
        try:
            rb_scanner = RecycleBinScanner(output_dir=str(self.output_dir))
            matched = rb_scanner.scan_folder(folder_path)
        except Exception as exc:
            return [self._error_result("recycle_bin_scan", str(exc))]
 
        # Apply filters
        filtered = []
        for entry in matched:
            fname = entry.get("filename", "")
            deleted_time = entry.get("deleted_time", "")
            if not _name_filter_matches(fname, filename):
                continue
            if not _ext_filter_matches(fname, extension):
                continue
            if not _time_filter_matches(deleted_time, time_start, time_end):
                continue
            filtered.append(entry)
 
        if not filtered:
            return []
 
        results = []
        total = len(filtered)
        for idx, entry in enumerate(filtered):
            cb(
                "recycle_bin",
                f"Restoring {entry.get('filename', '?')} ({idx + 1}/{total})",
                0.05 + 0.18 * (idx / max(total, 1)),
            )
            result = self._copy_rb_entry(entry, idx)
            results.append(result)
 
        return results
 
    def _copy_rb_entry(self, entry: dict, idx: int) -> dict:
        """Copy a single Recycle Bin $R file to the output directory."""
        src = Path(entry.get("filepath", ""))
        fname = entry.get("filename", f"recovered_{idx}")
        dest = self.output_dir / fname
 
        # Avoid overwriting a previous recovery of the same name
        if dest.exists():
            stem, suffix = dest.stem, dest.suffix
            dest = self.output_dir / f"{stem}_{idx}{suffix}"
 
        base = {
            "filename": fname,
            "original_path": entry.get("original_path", ""),
            "file_size": entry.get("file_size", 0),
            "source": "recycle_bin",
        }
 
        if not src.exists():
            return {**base,
                    "status": "error",
                    "recovered_path": "",
                    "sha256": "",
                    "error": f"$R file missing: {src}"}
 
        try:
            shutil.copy2(str(src), str(dest))
            sha = _sha256_of(str(dest))
            return {**base,
                    "status": "recovered",
                    "recovered_path": str(dest),
                    "sha256": sha,
                    "error": None}
        except Exception as exc:
            return {**base,
                    "status": "error",
                    "recovered_path": "",
                    "sha256": "",
                    "error": str(exc)}
 
    # ------------------------------------------------------------------
    # Stage 2 — Raw disk sector carve
    # ------------------------------------------------------------------
 
    def _stage_disk_carve(
        self,
        folder_path: str,
        filename: Optional[str],
        extension: Optional[str],
        cb: Callable,
    ) -> list[dict]:
        """
        Carve the raw disk of the drive that hosted *folder_path*, looking
        for deleted file signatures.  Requires Administrator on Windows.
        """
        drive = _drive_letter_from_path(folder_path)
        scanner = DiskScanner(drive_letter=drive, output_dir=str(self.output_dir))
 
        if not scanner.is_admin:
            # Non-fatal — report as an informational result so the UI can
            # surface the message without crashing the whole recovery.
            return [{
                "status": "error",
                "filename": "_admin_required.txt",
                "original_path": folder_path,
                "recovered_path": "",
                "file_size": 0,
                "sha256": "",
                "source": "disk_carve",
                "error": (
                    "Raw disk scan requires Administrator privileges. "
                    "Re-run the application as Administrator to enable "
                    "deep sector-level recovery."
                ),
            }]
 
        # Narrow the signature set to the requested extension when possible
        original_sigs = dict(DISK_SIGNATURES)
        try:
            if extension:
                ext_norm = "." + extension.lstrip(".").lower()
                narrowed = {
                    k: v for k, v in DISK_SIGNATURES.items()
                    if v.get("extension", "").lower() == ext_norm
                }
                if narrowed:
                    DISK_SIGNATURES.clear()
                    DISK_SIGNATURES.update(narrowed)
 
            # Progress relay: disk scan uses 26%–95% of the overall bar
            def _disk_cb(cur: int, total: int, found: int):
                pct = 0.26 + 0.69 * (cur / max(total, 1))
                cb("disk_carve",
                   f"Sector {cur:,}/{total:,} — {found} fragment(s) found", pct)
 
            carved = scanner.scan_for_deleted_files(
                max_sectors=500_000,          # ≈ 256 MB — balanced depth/speed
                progress_callback=_disk_cb,
            )
        finally:
            DISK_SIGNATURES.clear()
            DISK_SIGNATURES.update(original_sigs)
 
        # Apply filename filter to carved results (extension already narrowed)
        results = []
        for entry in carved:
            fname = entry.get("filename", "")
            if not _name_filter_matches(fname, filename):
                continue
            results.append(self._wrap_carved(entry))
 
        return results
 
    def _wrap_carved(self, entry: dict) -> dict:
        """Convert a DiskScanner carve dict into the standard result shape."""
        return {
            "status": "recovered",
            "filename": entry.get("filename", "carved_file"),
            "original_path": entry.get("filepath", ""),   # best guess — no MFT
            "recovered_path": entry.get("filepath", ""),
            "file_size": entry.get("file_size", entry.get("carved_size", 0)),
            "sha256": entry.get("sha256", ""),
            "source": "disk_carve",
            "disk_sector": entry.get("disk_sector"),
            "sig_name": entry.get("sig_name", ""),
            "error": None,
        }
 
    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------
 
    @staticmethod
    def _error_result(filename: str, error: str) -> dict:
        return {
            "status": "error",
            "filename": filename,
            "original_path": "",
            "recovered_path": "",
            "file_size": 0,
            "sha256": "",
            "source": "unknown",
            "error": error,
        }



