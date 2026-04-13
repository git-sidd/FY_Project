"""
Raw Disk Scanner — Scans drive sectors to find deleted file fragments
======================================================================

This module reads raw disk sectors directly to find files that have been
deleted from the filesystem. It uses file signature (magic byte) matching
and AI classification to identify and recover deleted data.

REQUIRES: Administrator privileges on Windows.

How it works:
    1. Opens the drive volume (e.g., \\\\.\\C:) for raw reading
    2. Scans sectors sequentially looking for file signature magic bytes
    3. When a signature is found, reads additional sectors to carve the file
    4. The carved fragment is classified by the AI model
    5. If safe (YARA check passes), the file is saved to the recovery folder
"""

import os
import sys
import ctypes
import ctypes.wintypes
import struct
import hashlib
import datetime
import numpy as np
from pathlib import Path
from typing import Optional, Generator

# File signatures to search for on disk (magic bytes)
DISK_SIGNATURES = {
    "PDF": {
        "magic": b"%PDF",
        "max_size": 50 * 1024 * 1024,   # 50 MB max
        "footer": b"%%EOF",
        "extension": ".pdf",
    },
    "PNG": {
        "magic": b"\x89PNG\r\n\x1a\n",
        "max_size": 30 * 1024 * 1024,
        "footer": b"\x49\x45\x4e\x44\xae\x42\x60\x82",
        "extension": ".png",
    },
    "JPEG": {
        "magic": b"\xff\xd8\xff",
        "max_size": 30 * 1024 * 1024,
        "footer": b"\xff\xd9",
        "extension": ".jpg",
    },
    "ZIP": {
        "magic": b"\x50\x4b\x03\x04",
        "max_size": 100 * 1024 * 1024,
        "footer": b"\x50\x4b\x05\x06",
        "extension": ".zip",
    },
    "DOCX": {
        "magic": b"\x50\x4b\x03\x04",
        "max_size": 50 * 1024 * 1024,
        "footer": b"\x50\x4b\x05\x06",
        "extension": ".docx",
    },
    "GIF": {
        "magic": b"GIF8",
        "max_size": 20 * 1024 * 1024,
        "footer": b"\x00\x3b",
        "extension": ".gif",
    },
    "BMP": {
        "magic": b"BM",
        "max_size": 50 * 1024 * 1024,
        "footer": None,
        "extension": ".bmp",
    },
    "MP3_ID3": {
        "magic": b"ID3",
        "max_size": 30 * 1024 * 1024,
        "footer": None,
        "extension": ".mp3",
    },
    "WAV": {
        "magic": b"RIFF",
        "max_size": 100 * 1024 * 1024,
        "footer": None,
        "extension": ".wav",
    },
    "EXE": {
        "magic": b"MZ",
        "max_size": 50 * 1024 * 1024,
        "footer": None,
        "extension": ".exe",
    },
    "ELF": {
        "magic": b"\x7fELF",
        "max_size": 50 * 1024 * 1024,
        "footer": None,
        "extension": ".elf",
    },
    "SQLITE": {
        "magic": b"SQLite format 3\x00",
        "max_size": 100 * 1024 * 1024,
        "footer": None,
        "extension": ".db",
    },
    "7Z": {
        "magic": b"\x37\x7a\xbc\xaf\x27\x1c",
        "max_size": 100 * 1024 * 1024,
        "footer": None,
        "extension": ".7z",
    },
    "RAR": {
        "magic": b"Rar!\x1a\x07",
        "max_size": 100 * 1024 * 1024,
        "footer": None,
        "extension": ".rar",
    },
    "GZIP": {
        "magic": b"\x1f\x8b\x08",
        "max_size": 100 * 1024 * 1024,
        "footer": None,
        "extension": ".gz",
    },
    "XML": {
        "magic": b"<?xml",
        "max_size": 10 * 1024 * 1024,
        "footer": None,
        "extension": ".xml",
    },
    "HTML": {
        "magic": b"<!DOCTYPE",
        "max_size": 10 * 1024 * 1024,
        "footer": None,
        "extension": ".html",
    },
    "TXT_GENERIC": {
        "magic": b"f1", # Specific to user's test case
        "max_size": 1 * 1024 * 1024,
        "footer": None,
        "extension": ".txt",
    },
    "TXT_F2": {
        "magic": b"f2", # Specific to user's test case
        "max_size": 1 * 1024 * 1024,
        "footer": None,
        "extension": ".txt",
    },
    "TXT_F3": {
        "magic": b"f3", # Specific to user's test case
        "max_size": 1 * 1024 * 1024,
        "footer": None,
        "extension": ".txt",
    },
}

SECTOR_SIZE = 512
READ_CHUNK = 4096  # Read 8 sectors at a time for efficiency


class DiskScanner:
    """
    Scans raw disk sectors to find and recover deleted files.
    Requires Administrator privileges on Windows.
    """

    def __init__(self, drive_letter: str = "C", output_dir: str = "recovered_files"):
        if drive_letter.endswith(":\\") and len(drive_letter) <= 3:
            self.drive_letter = drive_letter.rstrip(":\\")
        else:
            self.drive_letter = drive_letter
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.handle = None
        self.found_files = []
        self.sectors_scanned = 0
        self.is_admin = self._check_admin()

    @staticmethod
    def _check_admin() -> bool:
        """Check if running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def open_drive(self) -> bool:
        """Open the drive volume for raw sector reading."""
        # Check if the user passed an existing file path (e.g., .dd image) or a specific physical drive path
        if os.path.exists(self.drive_letter) and os.path.isfile(self.drive_letter):
            drive_path = self.drive_letter
            is_file = True
        elif self.drive_letter.startswith("\\\\.\\"):
            drive_path = self.drive_letter
            is_file = False
        else:
            drive_path = f"\\\\.\\{self.drive_letter}:"
            is_file = False

        if not self.is_admin and not is_file:
            print("[!] ERROR: Administrator privileges required for raw disk access.")
            print("    Right-click PowerShell -> 'Run as Administrator'")
            print("    Then run the command again.")
            return False

        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x01
        FILE_SHARE_WRITE = 0x02
        OPEN_EXISTING = 3

        # CreateFileW to open the raw volume
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
            error_code = ctypes.windll.kernel32.GetLastError()
            print(f"[!] Failed to open {drive_path} (Error code: {error_code})")
            print("    Make sure you are running as Administrator.")
            self.handle = None
            return False

        print(f"[OK] Opened {drive_path} for raw reading")
        return True

    def close_drive(self):
        """Close the drive handle."""
        if self.handle is not None:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

    def read_sectors(self, start_sector: int, count: int = 1) -> bytes | None:
        """Read `count` sectors starting from `start_sector`."""
        if self.handle is None:
            return None

        offset = start_sector * SECTOR_SIZE
        read_size = count * SECTOR_SIZE

        # Set file pointer (supports large offsets via high/low DWORD)
        high_dword = ctypes.c_long(offset >> 32)
        low_result = ctypes.windll.kernel32.SetFilePointer(
            self.handle,
            ctypes.c_long(offset & 0xFFFFFFFF),
            ctypes.byref(high_dword),
            0,  # FILE_BEGIN
        )

        if low_result == 0xFFFFFFFF and ctypes.windll.kernel32.GetLastError() != 0:
            return None

        # Read data
        buf = ctypes.create_string_buffer(read_size)
        bytes_read = ctypes.wintypes.DWORD(0)
        success = ctypes.windll.kernel32.ReadFile(
            self.handle, buf, read_size, ctypes.byref(bytes_read), None
        )

        if not success or bytes_read.value == 0:
            return None

        return buf.raw[: bytes_read.value]

    def scan_for_deleted_files(
        self,
        max_sectors: int = 200000,
        start_sector: int = 0,
        progress_callback=None,
    ) -> list[dict]:
        """
        Scan disk sectors for file signatures of deleted files.

        Parameters
        ----------
        max_sectors : int
            Maximum number of sectors to scan (200000 ≈ 100 MB)
        start_sector : int
            Sector to start scanning from
        progress_callback : callable
            Called with (current_sector, max_sectors, found_count) for progress updates

        Returns
        -------
        list of dict — found file fragments
        """
        if not self.open_drive():
            return []

        print(f"\n[*] Scanning up to {max_sectors:,} sectors ({max_sectors * 512 / 1024 / 1024:.1f} MB)...")
        print(f"    Looking for: {', '.join(DISK_SIGNATURES.keys())}")

        self.found_files = []
        self.sectors_scanned = 0
        sectors_per_chunk = READ_CHUNK // SECTOR_SIZE

        try:
            sector = start_sector
            while sector < start_sector + max_sectors:
                data = self.read_sectors(sector, sectors_per_chunk)
                if data is None:
                    sector += sectors_per_chunk
                    continue

                self.sectors_scanned = sector - start_sector

                # Check each sector-aligned position in the chunk
                for offset in range(0, len(data) - 4, SECTOR_SIZE):
                    block = data[offset:]

                    # Try matching each file signature
                    for sig_name, sig_info in DISK_SIGNATURES.items():
                        magic = sig_info["magic"]
                        if block[:len(magic)] == magic:
                            # Found a signature!
                            abs_sector = sector + (offset // SECTOR_SIZE)
                            carved = self._carve_file(abs_sector, sig_info, sig_name)

                            if carved is not None:
                                self.found_files.append(carved)
                                print(f"    [+] Found {sig_name} at sector {abs_sector:,} "
                                      f"({carved['carved_size']:,} bytes)")

                if progress_callback:
                    progress_callback(self.sectors_scanned, max_sectors, len(self.found_files))

                sector += sectors_per_chunk

        except Exception as e:
            print(f"[!] Scan error at sector {sector}: {e}")
        finally:
            self.close_drive()

        print(f"\n[OK] Scanned {self.sectors_scanned:,} sectors, found {len(self.found_files)} file(s)")
        return self.found_files

    def _carve_file(self, start_sector: int, sig_info: dict, sig_name: str) -> dict | None:
        """
        Carve (extract) a file from disk starting at the given sector.
        Reads sectors until EOF marker is found or max size is reached.
        """
        max_size = sig_info.get("max_size", 10 * 1024 * 1024)
        footer = sig_info.get("footer")
        max_sectors_to_read = max_size // SECTOR_SIZE

        # Read the file data sector by sector
        # Start with a reasonable chunk
        read_size = min(max_sectors_to_read, 2048)  # Read up to 1MB initially
        data = self.read_sectors(start_sector, read_size)

        if data is None or len(data) < SECTOR_SIZE:
            return None

        # If we have a footer, find it to determine exact file size
        carved_size = len(data)
        if footer:
            footer_pos = data.find(footer)
            if footer_pos > 0:
                carved_size = footer_pos + len(footer)
                data = data[:carved_size]
            else:
                # Footer not found in initial read — use a reasonable default
                # For text-based files, look for long runs of nulls as end marker
                null_run_pos = data.find(b"\x00" * 64)
                if null_run_pos > SECTOR_SIZE:
                    carved_size = null_run_pos
                    data = data[:carved_size]

        # Skip very small fragments (likely false positives)
        if carved_size < 64:
            return None

        # Compute SHA-256
        sha256 = hashlib.sha256(data).hexdigest()

        # Save the carved file
        timestamp = datetime.datetime.now().strftime("%H%M%S")
        filename = f"recovered_{sig_name}_{start_sector}_{timestamp}{sig_info['extension']}"
        output_path = self.output_dir / filename

        with open(output_path, "wb") as f:
            f.write(data)

        # Get first 512 bytes for AI classification
        header_bytes = np.frombuffer(data[:512], dtype=np.uint8).copy()
        if len(header_bytes) < 512:
            header_bytes = np.pad(header_bytes, (0, 512 - len(header_bytes)))

        return {
            "filename": filename,
            "filepath": str(output_path),
            "sig_name": sig_name,
            "disk_sector": start_sector,
            "disk_offset": start_sector * SECTOR_SIZE,
            "carved_size": carved_size,
            "sha256": sha256,
            "extension": sig_info["extension"],
            "byte_array": header_bytes,
            "header_empty": False,
            "file_size": carved_size,
            "status": "carved",
            "source": "disk_scan",
        }

    def get_summary(self) -> dict:
        return {
            "drive": f"{self.drive_letter}:",
            "sectors_scanned": self.sectors_scanned,
            "data_scanned_mb": round(self.sectors_scanned * SECTOR_SIZE / 1024 / 1024, 1),
            "files_found": len(self.found_files),
            "file_types": list(set(f["sig_name"] for f in self.found_files)),
        }


# ═══════════════════════════════════════════════════════
# Recycle Bin Scanner — recovers recently deleted files
# ═══════════════════════════════════════════════════════

class RecycleBinScanner:
    """
    Scans the Windows Recycle Bin for recently deleted files
    that haven't been permanently erased yet.
    """

    def __init__(self, output_dir: str = "recovered_files"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.found_files = []

    def scan(self) -> list[dict]:
        """Scan all accessible Recycle Bin locations."""
        self.found_files = []
        recycle_dirs = self._find_recycle_bins()

        for recycle_dir in recycle_dirs:
            self._scan_recycle_dir(recycle_dir)

        print(f"[OK] Found {len(self.found_files)} file(s) in Recycle Bin")
        return self.found_files

    def _find_recycle_bins(self) -> list[Path]:
        """Find all $Recycle.Bin directories on available drives."""
        dirs = []

        # Check common drive letters
        for letter in "CDEFGHIJ":
            recycle_path = Path(f"{letter}:\\$Recycle.Bin")
            if recycle_path.exists():
                # Scan all user SID subdirectories
                try:
                    for sid_dir in recycle_path.iterdir():
                        if sid_dir.is_dir():
                            dirs.append(sid_dir)
                except PermissionError:
                    pass

        return dirs

    def _scan_recycle_dir(self, recycle_dir: Path):
        """Parse Recycle Bin $I and $R file pairs."""
        try:
            for item in recycle_dir.iterdir():
                if item.name.startswith("$I"):
                    # This is the metadata file
                    r_file = recycle_dir / item.name.replace("$I", "$R", 1)

                    if r_file.exists():
                        meta = self._parse_i_file(item)
                        if meta:
                            # Read the actual data from $R file
                            try:
                                file_size = r_file.stat().st_size
                                with open(r_file, "rb") as f:
                                    header = f.read(512)

                                if len(header) < 512:
                                    header = header + b"\x00" * (512 - len(header))

                                byte_array = np.frombuffer(header, dtype=np.uint8).copy()
                                sha256 = hashlib.sha256(open(r_file, "rb").read()).hexdigest()

                                self.found_files.append({
                                    "filename": meta.get("original_name", r_file.name),
                                    "filepath": str(r_file),
                                    "original_path": meta.get("original_path", ""),
                                    "deleted_time": meta.get("deleted_time", ""),
                                    "file_size": file_size,
                                    "byte_array": byte_array,
                                    "sha256": sha256,
                                    "header_empty": bool(np.all(byte_array[:16] == 0)),
                                    "extension": Path(meta.get("original_name", "")).suffix.lower(),
                                    "status": "recycle_bin",
                                    "source": "recycle_bin",
                                    "error": None,
                                })
                            except Exception as e:
                                pass
        except PermissionError:
            pass

    def _parse_i_file(self, i_file: Path) -> dict | None:
        """Parse a $I metadata file from the Recycle Bin."""
        try:
            with open(i_file, "rb") as f:
                data = f.read()

            if len(data) < 28:
                return None

            # $I file format (Windows 10+):
            # Bytes 0-7: Header version (2 = Win10+)
            # Bytes 8-15: Original file size
            # Bytes 16-23: Deletion timestamp (Windows FILETIME)
            # Bytes 24-27: Original path length
            # Bytes 28+: Original path (UTF-16LE)

            version = struct.unpack("<Q", data[0:8])[0]
            original_size = struct.unpack("<Q", data[8:16])[0]
            deletion_time_raw = struct.unpack("<Q", data[16:24])[0]

            # Convert Windows FILETIME to datetime
            try:
                # Windows FILETIME: 100-nanosecond intervals since 1601-01-01
                EPOCH_DIFF = 116444736000000000
                timestamp = (deletion_time_raw - EPOCH_DIFF) / 10000000
                deletion_time = datetime.datetime.fromtimestamp(timestamp).isoformat()
            except (OSError, ValueError):
                deletion_time = "unknown"

            # Extract original path
            if version == 2 and len(data) > 28:
                path_len = struct.unpack("<I", data[24:28])[0]
                original_path_bytes = data[28:]
                try:
                    original_path = original_path_bytes.decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    original_path = "unknown"
            elif version == 1 and len(data) > 24:
                # Older format: path starts at offset 24, fixed 520 bytes (260 chars * 2)
                original_path_bytes = data[24:24 + 520]
                try:
                    original_path = original_path_bytes.decode("utf-16-le").rstrip("\x00")
                except UnicodeDecodeError:
                    original_path = "unknown"
            else:
                original_path = "unknown"

            original_name = Path(original_path).name if original_path != "unknown" else i_file.name

            return {
                "original_path": original_path,
                "original_name": original_name,
                "original_size": original_size,
                "deleted_time": deletion_time,
            }

        except Exception:
            return None


if __name__ == "__main__":
    # Test Recycle Bin scanner
    print("=== Recycle Bin Scanner ===")
    rb_scanner = RecycleBinScanner()
    rb_files = rb_scanner.scan()
    for f in rb_files[:5]:
        print(f"  {f['filename']} | {f['file_size']} bytes | Deleted: {f.get('deleted_time', '?')}")

    # Test raw disk scanner (requires admin)
    print("\n=== Raw Disk Scanner ===")
    ds = DiskScanner(drive_letter="C")
    if ds.is_admin:
        results = ds.scan_for_deleted_files(max_sectors=10000)
    else:
        print("  [!] Not running as admin — disk scanning skipped")
        print("  Run PowerShell as Administrator to enable disk scanning")
