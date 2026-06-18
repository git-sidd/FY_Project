"""
USN Journal Scanner — Reads the NTFS Update Sequence Number Journal
=====================================================================

The USN (Change) Journal records every filesystem change on an NTFS volume.
By reading it we can find precise deletion events (timestamp, filename,
parent directory) for files that were recently deleted — even if the Recycle
Bin has been emptied.

This information is correlated with MFT entries to guide data recovery.

REQUIRES: Administrator privileges on Windows.

Key DeviceIoControl codes used:
  FSCTL_QUERY_USN_JOURNAL  = 0x000900f4
  FSCTL_ENUM_USN_DATA      = 0x000900b3
"""

import os
import ctypes
import ctypes.wintypes
import struct
import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


# ═══════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════

FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_ENUM_USN_DATA = 0x000900B3

# USN_REASON flags we care about
USN_REASON_FILE_DELETE = 0x00000200
USN_REASON_CLOSE = 0x80000000
USN_REASON_RENAME_OLD = 0x00001000

_EPOCH_DIFF = 116444736000000000


def _filetime_to_datetime(ft: int) -> Optional[datetime.datetime]:
    if ft <= 0:
        return None
    try:
        timestamp = (ft - _EPOCH_DIFF) / 10_000_000
        return datetime.datetime.fromtimestamp(timestamp)
    except (OSError, ValueError, OverflowError):
        return None


# ═══════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════

@dataclass
class USNEntry:
    """A single USN journal record."""
    file_reference_number: int = 0
    parent_reference_number: int = 0
    usn: int = 0
    timestamp: Optional[datetime.datetime] = None
    reason: int = 0
    filename: str = ""
    # Derived
    is_delete: bool = False
    parent_entry_number: int = 0


# ═══════════════════════════════════════════════════════
# USN Journal Scanner
# ═══════════════════════════════════════════════════════

class USNJournalScanner:
    """
    Reads the NTFS USN Change Journal to find deletion events.
    Requires Administrator privileges.
    """

    def __init__(self, drive_letter: str = "C"):
        self.drive_letter = drive_letter.rstrip(":\\")
        self.handle = None
        self.journal_id = 0
        self.first_usn = 0
        self.next_usn = 0
        self.entries: list[USNEntry] = []
        self.is_admin = self._check_admin()

    @staticmethod
    def _check_admin() -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _open_volume(self) -> bool:
        drive_path = f"\\\\.\\{self.drive_letter}:"
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x01
        FILE_SHARE_WRITE = 0x02
        OPEN_EXISTING = 3

        self.handle = ctypes.windll.kernel32.CreateFileW(
            drive_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )

        if self.handle == ctypes.wintypes.HANDLE(-1).value or self.handle == -1:
            err = ctypes.windll.kernel32.GetLastError()
            print(f"[!] Failed to open volume {drive_path} (Error {err})")
            self.handle = None
            return False
        return True

    def _close_volume(self):
        if self.handle is not None:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

    # ── Query journal metadata ───────────────────────────

    def query_journal(self) -> bool:
        """Query the USN Journal to get journal ID and bounds."""
        if not self._open_volume():
            return False

        try:
            # USN_JOURNAL_DATA_V0 output: 64 bytes
            out_buf = ctypes.create_string_buffer(64)
            bytes_returned = ctypes.wintypes.DWORD(0)

            ok = ctypes.windll.kernel32.DeviceIoControl(
                self.handle,
                FSCTL_QUERY_USN_JOURNAL,
                None, 0,
                out_buf, 64,
                ctypes.byref(bytes_returned),
                None,
            )

            if not ok:
                err = ctypes.windll.kernel32.GetLastError()
                print(f"[!] FSCTL_QUERY_USN_JOURNAL failed (Error {err})")
                if err == 22:
                    print("    USN Journal may not be enabled on this volume.")
                return False

            data = out_buf.raw[: bytes_returned.value]
            if len(data) >= 24:
                self.journal_id = struct.unpack_from("<Q", data, 0)[0]
                self.first_usn = struct.unpack_from("<Q", data, 8)[0]
                self.next_usn = struct.unpack_from("<Q", data, 16)[0]

                print(f"[OK] USN Journal found on {self.drive_letter}:")
                print(f"    Journal ID:  {self.journal_id}")
                print(f"    First USN:   {self.first_usn}")
                print(f"    Next USN:    {self.next_usn}")
                return True

            return False
        finally:
            self._close_volume()

    # ── Enumerate USN records ────────────────────────────

    def read_deletion_events(
        self,
        max_records: int = 200_000,
        progress_callback=None,
    ) -> list[USNEntry]:
        """
        Read USN journal entries and filter for deletion events.

        Parameters
        ----------
        max_records : int
            Maximum records to read from the journal.
        progress_callback : callable, optional
            Called with (records_read, deletions_found).
        """
        if not self._open_volume():
            return []

        if self.journal_id == 0:
            self._close_volume()
            if not self.query_journal():
                return []
            if not self._open_volume():
                return []

        try:
            self.entries = []
            records_read = 0

            # MFT_ENUM_DATA_V0 input structure: 8+8+8 = 24 bytes
            # StartFileReferenceNumber (8), LowUsn (8), HighUsn (8)
            input_buf = struct.pack("<QQQ", 0, 0, self.next_usn)
            input_arr = ctypes.create_string_buffer(input_buf)

            out_size = 65536
            out_buf = ctypes.create_string_buffer(out_size)
            bytes_returned = ctypes.wintypes.DWORD(0)

            while records_read < max_records:
                ok = ctypes.windll.kernel32.DeviceIoControl(
                    self.handle,
                    FSCTL_ENUM_USN_DATA,
                    input_arr, len(input_buf),
                    out_buf, out_size,
                    ctypes.byref(bytes_returned),
                    None,
                )

                if not ok:
                    break

                returned = bytes_returned.value
                if returned <= 8:
                    break

                data = out_buf.raw[:returned]

                # First 8 bytes: next start file reference number
                next_ref = struct.unpack_from("<Q", data, 0)[0]

                # Parse USN_RECORD entries after the 8-byte header
                pos = 8
                found_any = False
                while pos + 60 <= returned:
                    record_len = struct.unpack_from("<I", data, pos)[0]
                    if record_len == 0 or pos + record_len > returned:
                        break

                    record = data[pos: pos + record_len]
                    entry = self._parse_usn_record(record)
                    if entry:
                        records_read += 1
                        if entry.is_delete:
                            self.entries.append(entry)
                        found_any = True

                    pos += record_len

                if not found_any:
                    break

                # Update start reference for next batch
                input_buf = struct.pack("<QQQ", next_ref, 0, self.next_usn)
                input_arr = ctypes.create_string_buffer(input_buf)

                if progress_callback and records_read % 10000 == 0:
                    progress_callback(records_read, len(self.entries))

            print(f"[OK] Read {records_read:,} USN records, "
                  f"{len(self.entries)} deletion event(s) found")
            return self.entries

        finally:
            self._close_volume()

    def _parse_usn_record(self, data: bytes) -> Optional[USNEntry]:
        """Parse a single USN_RECORD_V2 structure."""
        if len(data) < 60:
            return None

        try:
            entry = USNEntry()

            # USN_RECORD_V2 layout:
            # 0: RecordLength (4)
            # 4: MajorVersion (2), MinorVersion (2)
            # 8: FileReferenceNumber (8)
            # 16: ParentFileReferenceNumber (8)
            # 24: Usn (8)
            # 32: TimeStamp (8) — FILETIME
            # 40: Reason (4)
            # 44: SourceInfo (4)
            # 48: SecurityId (4)
            # 52: FileAttributes (4)
            # 56: FileNameLength (2)
            # 58: FileNameOffset (2)
            # 60+: FileName (UTF-16LE)

            entry.file_reference_number = struct.unpack_from("<Q", data, 8)[0]
            entry.parent_reference_number = struct.unpack_from("<Q", data, 16)[0]
            entry.usn = struct.unpack_from("<Q", data, 24)[0]
            entry.timestamp = _filetime_to_datetime(struct.unpack_from("<Q", data, 32)[0])
            entry.reason = struct.unpack_from("<I", data, 40)[0]

            name_len = struct.unpack_from("<H", data, 56)[0]
            name_offset = struct.unpack_from("<H", data, 58)[0]

            if name_offset + name_len <= len(data):
                try:
                    entry.filename = data[name_offset: name_offset + name_len].decode("utf-16-le")
                except UnicodeDecodeError:
                    entry.filename = ""

            # Check if this is a delete event
            entry.is_delete = bool(entry.reason & USN_REASON_FILE_DELETE)
            entry.parent_entry_number = entry.parent_reference_number & 0x0000FFFFFFFFFFFF

            return entry

        except Exception:
            return None

    # ── Filtered search ──────────────────────────────────

    def find_deletions(
        self,
        filename: Optional[str] = None,
        extension: Optional[str] = None,
        time_start: Optional[datetime.datetime] = None,
        time_end: Optional[datetime.datetime] = None,
    ) -> list[USNEntry]:
        """Filter stored deletion events by optional criteria."""
        results = []
        for entry in self.entries:
            if filename and filename.lower() not in entry.filename.lower():
                continue

            if extension:
                ext = extension if extension.startswith(".") else f".{extension}"
                file_ext = Path(entry.filename).suffix.lower()
                if file_ext != ext.lower():
                    continue

            if time_start and entry.timestamp and entry.timestamp < time_start:
                continue
            if time_end and entry.timestamp and entry.timestamp > time_end:
                continue

            results.append(entry)

        return results

    # ── Correlation with MFT ─────────────────────────────

    def correlate_with_mft(self, mft_entry_map: dict) -> list[dict]:
        """
        Cross-reference USN deletion events with MFT entries.

        Returns a list of dicts combining USN and MFT information for
        entries where a matching MFT record was found.
        """
        correlated = []
        for usn_entry in self.entries:
            # MFT entry number is the lower 48 bits of the file reference
            mft_num = usn_entry.file_reference_number & 0x0000FFFFFFFFFFFF
            if mft_num in mft_entry_map:
                mft_entry = mft_entry_map[mft_num]
                correlated.append({
                    "usn_entry": usn_entry,
                    "mft_entry": mft_entry,
                    "filename": usn_entry.filename or mft_entry.filename,
                    "deleted_time": usn_entry.timestamp,
                    "mft_entry_number": mft_num,
                    "file_size": mft_entry.file_size,
                    "full_path": mft_entry.full_path,
                })
        return correlated


# ═══════════════════════════════════════════════════════
# Main — quick test
# ═══════════════════════════════════════════════════════

if __name__ == "__main__":
    scanner = USNJournalScanner(drive_letter="C")
    if scanner.is_admin:
        if scanner.query_journal():
            deletions = scanner.read_deletion_events(max_records=100000)
            print(f"\nFound {len(deletions)} deletion events")
            for d in deletions[:10]:
                print(f"  {d.filename} | deleted: {d.timestamp} | "
                      f"reason: 0x{d.reason:08X}")
    else:
        print("[!] Not running as Admin — USN Journal requires elevation")
