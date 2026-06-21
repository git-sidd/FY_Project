"""
NTFS MFT Parser — Parse the Master File Table to find and recover deleted files
=================================================================================

Reads the NTFS Master File Table (MFT) directly from raw disk to locate
deleted file entries whose MFT records have not yet been overwritten.

For each deleted entry the parser extracts:
  - Original filename and parent directory reference
  - Creation / modification / access / MFT-change timestamps
  - File size
  - Data attribute (resident data or non-resident data-run list)

Recovery is then attempted by reading the file's cluster chain from disk.

REQUIRES: Administrator privileges on Windows.

References:
  - NTFS MFT entry structure (FILE record)
  - $STANDARD_INFORMATION  attribute type 0x10
  - $FILE_NAME             attribute type 0x30
  - $DATA                  attribute type 0x80
"""

import os
import sys
import ctypes
import ctypes.wintypes
import struct
import hashlib
import datetime
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Generator


# ═══════════════════════════════════════════════════════
# Data structures
# ═══════════════════════════════════════════════════════

@dataclass
class MFTEntry:
    """Parsed representation of a single MFT entry."""
    entry_number: int = 0
    is_deleted: bool = False
    is_directory: bool = False
    sequence_number: int = 0
    # $FILE_NAME attributes
    filename: str = ""
    parent_entry_number: int = 0
    parent_sequence: int = 0
    # $STANDARD_INFORMATION timestamps
    created_time: Optional[datetime.datetime] = None
    modified_time: Optional[datetime.datetime] = None
    accessed_time: Optional[datetime.datetime] = None
    mft_changed_time: Optional[datetime.datetime] = None
    # $DATA attribute
    file_size: int = 0
    data_resident: bool = False
    resident_data: bytes = b""
    data_runs: list = field(default_factory=list)  # [(length_clusters, offset_clusters), ...]
    # Resolved path (filled later)
    full_path: str = ""
    # Extension for quick filtering
    extension: str = ""
    # Raw flags
    flags: int = 0


# Windows FILETIME epoch offset (100-ns intervals between 1601-01-01 and 1970-01-01)
_EPOCH_DIFF = 116444736000000000


def _filetime_to_datetime(ft: int) -> Optional[datetime.datetime]:
    """Convert a Windows FILETIME (64-bit) to a Python datetime."""
    if ft <= 0:
        return None
    try:
        timestamp = (ft - _EPOCH_DIFF) / 10_000_000
        return datetime.datetime.fromtimestamp(timestamp)
    except (OSError, ValueError, OverflowError):
        return None


# ═══════════════════════════════════════════════════════
# MFT Parser
# ═══════════════════════════════════════════════════════

# Standard MFT entry size (most NTFS volumes)
MFT_ENTRY_SIZE = 1024
SECTOR_SIZE = 512


class MFTParser:
    """
    Parses the NTFS Master File Table to find deleted file entries and
    recover their data from disk.

    Requires Administrator privileges for raw volume access.
    """

    def __init__(self, drive_letter: str = "C", output_dir: str = "recovered_files"):
        self.drive_letter = drive_letter.rstrip(":\\")
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.handle = None

        # NTFS boot-sector parameters (populated by _read_boot_sector)
        self.bytes_per_sector = 512
        self.sectors_per_cluster = 8
        self.bytes_per_cluster = 4096
        self.mft_start_cluster = 0
        self.mft_offset = 0
        self.mft_entry_size = MFT_ENTRY_SIZE

        # Parsed data
        self.entries: list[MFTEntry] = []
        self._entry_map: dict[int, MFTEntry] = {}  # entry_number -> MFTEntry

        self.is_admin = self._check_admin()

    # ── Admin check ──────────────────────────────────────

    @staticmethod
    def _check_admin() -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    # ── Volume handle ────────────────────────────────────

    def _open_volume(self) -> bool:
        """Open the raw NTFS volume for reading."""
        if not self.is_admin:
            print("[!] ERROR: Administrator privileges required for MFT parsing.")
            return False

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
            print(f"[!] Failed to open {drive_path} (Error {err})")
            self.handle = None
            return False

        print(f"[OK] Opened {drive_path} for MFT reading")
        return True

    def _close_volume(self):
        if self.handle is not None:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

    def _read_at(self, offset: int, size: int) -> Optional[bytes]:
        """Read *size* bytes starting at absolute byte *offset* on the volume."""
        if self.handle is None:
            return None

        # Align reads to sector boundaries
        aligned_offset = (offset // SECTOR_SIZE) * SECTOR_SIZE
        extra = offset - aligned_offset
        aligned_size = ((size + extra + SECTOR_SIZE - 1) // SECTOR_SIZE) * SECTOR_SIZE

        high = ctypes.c_long(aligned_offset >> 32)
        low = ctypes.windll.kernel32.SetFilePointer(
            self.handle,
            ctypes.c_long(aligned_offset & 0xFFFFFFFF),
            ctypes.byref(high),
            0,
        )
        if low == 0xFFFFFFFF and ctypes.windll.kernel32.GetLastError() != 0:
            return None

        buf = ctypes.create_string_buffer(aligned_size)
        read = ctypes.wintypes.DWORD(0)
        ok = ctypes.windll.kernel32.ReadFile(
            self.handle, buf, aligned_size, ctypes.byref(read), None
        )
        if not ok or read.value == 0:
            return None

        return buf.raw[extra: extra + size]

    # ── Boot sector ──────────────────────────────────────

    def _read_boot_sector(self) -> bool:
        """Read and parse the NTFS boot sector to locate the MFT."""
        data = self._read_at(0, 512)
        if data is None or len(data) < 512:
            print("[!] Failed to read boot sector")
            return False

        # Validate NTFS OEM ID at offset 3
        oem_id = data[3:11]
        if b"NTFS" not in oem_id:
            print(f"[!] Not an NTFS volume (OEM: {oem_id})")
            return False

        self.bytes_per_sector = struct.unpack_from("<H", data, 0x0B)[0]
        self.sectors_per_cluster = data[0x0D]
        self.bytes_per_cluster = self.bytes_per_sector * self.sectors_per_cluster
        self.mft_start_cluster = struct.unpack_from("<Q", data, 0x30)[0]
        self.mft_offset = self.mft_start_cluster * self.bytes_per_cluster

        # MFT entry size: byte at 0x40, if negative it is log2 of size
        entry_size_raw = struct.unpack_from("<b", data, 0x40)[0]
        if entry_size_raw < 0:
            self.mft_entry_size = 1 << abs(entry_size_raw)
        else:
            self.mft_entry_size = entry_size_raw * self.bytes_per_cluster

        print(f"    Bytes/sector:      {self.bytes_per_sector}")
        print(f"    Sectors/cluster:   {self.sectors_per_cluster}")
        print(f"    Bytes/cluster:     {self.bytes_per_cluster}")
        print(f"    MFT start cluster: {self.mft_start_cluster}")
        print(f"    MFT offset:        {self.mft_offset} (0x{self.mft_offset:X})")
        print(f"    MFT entry size:    {self.mft_entry_size}")
        return True

    # ── MFT entry parsing ────────────────────────────────

    def _parse_mft_entry(self, data: bytes, entry_number: int) -> Optional[MFTEntry]:
        """Parse a single 1024-byte MFT entry."""
        if len(data) < 42:
            return None

        # Signature check: "FILE"
        sig = data[0:4]
        if sig != b"FILE":
            return None

        entry = MFTEntry(entry_number=entry_number)

        # Fix-up: apply the update sequence array
        try:
            data = bytearray(data)
            usa_offset = struct.unpack_from("<H", data, 0x04)[0]
            usa_count = struct.unpack_from("<H", data, 0x06)[0]
            if usa_offset > 0 and usa_count > 0 and usa_offset + usa_count * 2 <= len(data):
                update_seq = struct.unpack_from("<H", data, usa_offset)[0]
                for i in range(1, usa_count):
                    pos = i * self.bytes_per_sector - 2
                    if pos + 2 <= len(data):
                        replacement = struct.unpack_from("<H", data, usa_offset + i * 2)[0]
                        struct.pack_into("<H", data, pos, replacement)
            data = bytes(data)
        except Exception:
            data = bytes(data) if isinstance(data, bytearray) else data

        # Flags at offset 0x16
        entry.flags = struct.unpack_from("<H", data, 0x16)[0]
        entry.is_deleted = (entry.flags & 0x01) == 0       # Bit 0 = in-use
        entry.is_directory = (entry.flags & 0x02) != 0     # Bit 1 = directory

        # Sequence number at offset 0x10
        entry.sequence_number = struct.unpack_from("<H", data, 0x10)[0]

        # First attribute offset
        attr_offset = struct.unpack_from("<H", data, 0x14)[0]

        # Walk attributes
        pos = attr_offset
        while pos + 4 <= len(data):
            attr_type = struct.unpack_from("<I", data, pos)[0]
            if attr_type == 0xFFFFFFFF:
                break  # End marker

            attr_len = struct.unpack_from("<I", data, pos + 4)[0]
            if attr_len == 0 or pos + attr_len > len(data):
                break

            attr_data = data[pos: pos + attr_len]
            self._parse_attribute(attr_data, attr_type, entry)
            pos += attr_len

        # Derive extension
        if entry.filename:
            ext = Path(entry.filename).suffix.lower()
            entry.extension = ext

        return entry

    def _parse_attribute(self, attr_data: bytes, attr_type: int, entry: MFTEntry):
        """Parse a single MFT attribute."""
        if len(attr_data) < 16:
            return

        non_resident = attr_data[8]  # 0 = resident, 1 = non-resident

        if attr_type == 0x10:
            # $STANDARD_INFORMATION
            self._parse_standard_info(attr_data, entry)

        elif attr_type == 0x30:
            # $FILE_NAME
            self._parse_file_name(attr_data, non_resident, entry)

        elif attr_type == 0x80:
            # $DATA
            self._parse_data_attr(attr_data, non_resident, entry)

    def _parse_standard_info(self, attr_data: bytes, entry: MFTEntry):
        """Parse $STANDARD_INFORMATION attribute (type 0x10)."""
        if len(attr_data) < 24:
            return
        # Resident attribute: content offset at byte 0x14
        content_offset = struct.unpack_from("<H", attr_data, 0x14)[0]
        content = attr_data[content_offset:]
        if len(content) < 32:
            return

        entry.created_time = _filetime_to_datetime(struct.unpack_from("<Q", content, 0)[0])
        entry.modified_time = _filetime_to_datetime(struct.unpack_from("<Q", content, 8)[0])
        entry.mft_changed_time = _filetime_to_datetime(struct.unpack_from("<Q", content, 16)[0])
        entry.accessed_time = _filetime_to_datetime(struct.unpack_from("<Q", content, 24)[0])

    def _parse_file_name(self, attr_data: bytes, non_resident: int, entry: MFTEntry):
        """Parse $FILE_NAME attribute (type 0x30)."""
        if non_resident:
            return  # $FILE_NAME should always be resident

        content_offset = struct.unpack_from("<H", attr_data, 0x14)[0]
        content = attr_data[content_offset:]
        if len(content) < 66:
            return

        # Parent directory reference (6 bytes entry number + 2 bytes sequence)
        parent_ref = struct.unpack_from("<Q", content, 0)[0]
        entry.parent_entry_number = parent_ref & 0x0000FFFFFFFFFFFF
        entry.parent_sequence = (parent_ref >> 48) & 0xFFFF

        # Filename length and namespace
        name_length = content[64]       # number of characters
        name_namespace = content[65]    # 0=POSIX, 1=Win32, 2=DOS, 3=Win32+DOS

        # Skip DOS-only names (namespace 2) if we already have a Win32 name
        if name_namespace == 2 and entry.filename:
            return

        # Filename (UTF-16LE) starting at offset 66
        name_bytes = content[66: 66 + name_length * 2]
        try:
            filename = name_bytes.decode("utf-16-le")
        except UnicodeDecodeError:
            filename = ""

        if filename:
            entry.filename = filename

        # Allocated and real size of file (from $FILE_NAME — may differ from $DATA)
        if len(content) >= 48:
            entry.file_size = max(entry.file_size,
                                  struct.unpack_from("<Q", content, 48)[0])

    def _parse_data_attr(self, attr_data: bytes, non_resident: int, entry: MFTEntry):
        """Parse $DATA attribute (type 0x80)."""
        if not non_resident:
            # Resident data — file content is stored inline in the MFT entry
            if len(attr_data) < 24:
                return
            content_size = struct.unpack_from("<I", attr_data, 0x10)[0]
            content_offset = struct.unpack_from("<H", attr_data, 0x14)[0]
            if content_offset + content_size <= len(attr_data):
                entry.data_resident = True
                entry.resident_data = attr_data[content_offset: content_offset + content_size]
                entry.file_size = max(entry.file_size, content_size)
        else:
            # Non-resident data — parse data run list
            if len(attr_data) < 0x40:
                return

            # Real size of file content
            real_size = struct.unpack_from("<Q", attr_data, 0x30)[0]
            entry.file_size = max(entry.file_size, real_size)

            # Data runs start offset
            run_offset = struct.unpack_from("<H", attr_data, 0x20)[0]
            entry.data_runs = self._parse_data_runs(attr_data[run_offset:])
            entry.data_resident = False

    @staticmethod
    def _parse_data_runs(data: bytes) -> list[tuple[int, int]]:
        """
        Parse an NTFS data run list.

        Each run is encoded as:
          header byte: high nibble = size of offset field,
                       low nibble  = size of length field
          length field: cluster count (little-endian)
          offset field: cluster offset from previous run (signed, little-endian)

        Returns list of (cluster_count, absolute_cluster_offset).
        """
        runs = []
        pos = 0
        prev_offset = 0

        while pos < len(data):
            header = data[pos]
            if header == 0:
                break  # End of run list

            len_size = header & 0x0F
            off_size = (header >> 4) & 0x0F
            pos += 1

            if pos + len_size > len(data):
                break
            run_length = int.from_bytes(data[pos: pos + len_size], "little", signed=False)
            pos += len_size

            if off_size == 0:
                # Sparse run (no offset)
                runs.append((run_length, None))
            else:
                if pos + off_size > len(data):
                    break
                run_offset = int.from_bytes(data[pos: pos + off_size], "little", signed=True)
                pos += off_size

                absolute_offset = prev_offset + run_offset
                prev_offset = absolute_offset
                runs.append((run_length, absolute_offset))

        return runs

    # ── Full MFT scan ────────────────────────────────────

    def parse_mft(
        self,
        max_entries: int = 500_000,
        deleted_only: bool = True,
        progress_callback=None,
    ) -> list[MFTEntry]:
        """
        Parse MFT entries from the volume.

        Parameters
        ----------
        max_entries : int
            Maximum number of MFT entries to read.
        deleted_only : bool
            If True, only keep deleted (non-directory) entries.
        progress_callback : callable
            Called with (entries_scanned, deleted_found) periodically.
        """
        if not self._open_volume():
            return []

        try:
            if not self._read_boot_sector():
                return []

            print(f"\n[*] Parsing MFT (up to {max_entries:,} entries)...")
            self.entries = []
            self._entry_map = {}

            batch_size = 64  # read 64 entries at a time
            batch_bytes = batch_size * self.mft_entry_size

            for start in range(0, max_entries, batch_size):
                offset = self.mft_offset + start * self.mft_entry_size
                block = self._read_at(offset, batch_bytes)
                if block is None or len(block) < self.mft_entry_size:
                    break

                entries_in_block = len(block) // self.mft_entry_size
                for i in range(entries_in_block):
                    entry_data = block[i * self.mft_entry_size: (i + 1) * self.mft_entry_size]
                    entry_num = start + i
                    parsed = self._parse_mft_entry(entry_data, entry_num)
                    if parsed is None:
                        continue

                    self._entry_map[entry_num] = parsed

                    if deleted_only:
                        if parsed.is_deleted and not parsed.is_directory and parsed.filename:
                            self.entries.append(parsed)
                    else:
                        self.entries.append(parsed)

                if progress_callback and start % (batch_size * 16) == 0:
                    progress_callback(start + entries_in_block, len(self.entries))

            # Resolve parent paths for deleted entries
            self._resolve_paths()

            print(f"[OK] Parsed {len(self._entry_map):,} MFT entries, "
                  f"{len(self.entries)} deleted file(s) found")
            return self.entries

        finally:
            self._close_volume()

    def _resolve_paths(self):
        """Resolve full paths for entries by walking parent directory references."""
        for entry in self.entries:
            parts = [entry.filename]
            current = entry.parent_entry_number
            visited = set()
            depth = 0

            while current in self._entry_map and current not in visited and depth < 20:
                visited.add(current)
                parent = self._entry_map[current]
                if parent.filename and parent.filename != ".":
                    parts.append(parent.filename)
                if parent.parent_entry_number == current:
                    break  # Root
                current = parent.parent_entry_number
                depth += 1

            # Prepend drive letter
            parts.reverse()
            entry.full_path = f"{self.drive_letter}:\\" + "\\".join(parts)

    # ── Filtered search ──────────────────────────────────

    def find_deleted_entries(
        self,
        folder_path: Optional[str] = None,
        filename: Optional[str] = None,
        extension: Optional[str] = None,
        time_start: Optional[datetime.datetime] = None,
        time_end: Optional[datetime.datetime] = None,
    ) -> list[MFTEntry]:
        """
        Filter parsed deleted MFT entries by the given criteria.

        All filters are optional; if none are provided, all deleted entries
        are returned.
        """
        results = []
        folder_norm = os.path.normpath(folder_path).lower() if folder_path else None

        for entry in self.entries:
            # Folder path filter
            if folder_norm:
                entry_dir = os.path.dirname(os.path.normpath(entry.full_path)).lower()
                if not entry_dir.startswith(folder_norm):
                    continue

            # Filename filter
            if filename:
                if filename.lower() not in entry.filename.lower():
                    continue

            # Extension filter
            if extension:
                ext = extension if extension.startswith(".") else f".{extension}"
                if entry.extension.lower() != ext.lower():
                    continue

            # Time range filter (use modified_time or mft_changed_time)
            ts = entry.modified_time or entry.mft_changed_time
            if time_start and ts and ts < time_start:
                continue
            if time_end and ts and ts > time_end:
                continue

            results.append(entry)

        return results

    # ── File recovery ────────────────────────────────────

    def recover_entry(self, entry: MFTEntry, dest_dir: Optional[str] = None) -> dict:
        """
        Recover the data for a deleted MFT entry.

        Returns a result dict compatible with the rest of the recovery system.
        """
        out_dir = Path(dest_dir) if dest_dir else self.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        result = {
            "filename": entry.filename,
            "original_path": entry.full_path,
            "recovered_path": "",
            "file_size": entry.file_size,
            "sha256": "",
            "recovery_method": "",
            "confidence_score": 0.0,
            "status": "failed",
            "warnings": [],
            "metadata": {
                "created_time": entry.created_time.isoformat() if entry.created_time else "",
                "modified_time": entry.modified_time.isoformat() if entry.modified_time else "",
                "deleted_time": entry.mft_changed_time.isoformat() if entry.mft_changed_time else "",
                "mft_entry_number": entry.entry_number,
                "disk_sector": None,
            },
        }

        recovered_data = None

        # Method 1: Resident data (small files stored inline in MFT)
        if entry.data_resident and entry.resident_data:
            recovered_data = entry.resident_data
            result["recovery_method"] = "mft_resident"

        # Method 2: Non-resident data runs
        elif entry.data_runs:
            recovered_data = self._read_data_runs(entry)
            result["recovery_method"] = "mft_data_runs"
            if recovered_data and len(recovered_data) != entry.file_size:
                result["warnings"].append(
                    f"Recovered size ({len(recovered_data)}) differs from "
                    f"expected ({entry.file_size})"
                )

        if recovered_data is None:
            result["warnings"].append("No data attribute found or data runs unreadable")
            return result

        # Trim to expected file size
        if entry.file_size > 0 and len(recovered_data) > entry.file_size:
            recovered_data = recovered_data[: entry.file_size]

        # Save
        safe_name = "".join(c if c.isalnum() or c in "._- " else "_" for c in entry.filename)
        if not safe_name:
            safe_name = f"mft_entry_{entry.entry_number}"
        output_path = out_dir / f"recovered_{safe_name}"

        # Handle collision
        if output_path.exists():
            stem = output_path.stem
            suffix = output_path.suffix
            output_path = out_dir / f"{stem}_{entry.entry_number}{suffix}"

        with open(output_path, "wb") as f:
            f.write(recovered_data)

        result["recovered_path"] = str(output_path)
        result["sha256"] = hashlib.sha256(recovered_data).hexdigest()
        result["file_size"] = len(recovered_data)
        result["status"] = "recovered"

        return result

    def _read_data_runs(self, entry: MFTEntry) -> Optional[bytes]:
        """Read file content from disk following the data run list."""
        if not self._open_volume():
            return None

        try:
            parts = []
            for cluster_count, cluster_offset in entry.data_runs:
                if cluster_offset is None:
                    # Sparse run — fill with zeros
                    parts.append(b"\x00" * cluster_count * self.bytes_per_cluster)
                    continue

                offset = cluster_offset * self.bytes_per_cluster
                size = cluster_count * self.bytes_per_cluster
                chunk = self._read_at(offset, size)
                if chunk is None:
                    return None
                parts.append(chunk)

            return b"".join(parts)

        finally:
            self._close_volume()


# ═══════════════════════════════════════════════════════
# Main — quick test
# ═══════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = MFTParser(drive_letter="C")
    if parser.is_admin:
        entries = parser.parse_mft(max_entries=50000, deleted_only=True)
        print(f"\nFound {len(entries)} deleted entries")
        for e in entries[:10]:
            print(f"  [{e.entry_number}] {e.filename} | "
                  f"{e.file_size:,} bytes | {e.full_path}")
    else:
        print("[!] Not running as Admin — MFT parsing requires elevation")
        print("    Right-click PowerShell → 'Run as Administrator'")
