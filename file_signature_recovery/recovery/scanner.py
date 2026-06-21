"""
Folder Scanner — Scans directories for files to analyze and recover
====================================================================
"""

import os
import hashlib
import datetime
import numpy as np
from pathlib import Path
from typing import Generator


# File status codes
STATUS_VALID = "valid"
STATUS_CORRUPTED = "corrupted"
STATUS_MISMATCH = "mismatch"
STATUS_UNKNOWN = "unknown"
STATUS_HEADERLESS = "headerless"

SAMPLE_SIZE = 512


class FolderScanner:
    """Scans a folder recursively and yields file candidates for analysis."""

    def __init__(self, target_path: str, recursive: bool = True):
        self.target_path = Path(target_path)
        self.recursive = recursive
        self.scan_results = []
        self.scan_start = None
        self.scan_end = None

    def scan(self) -> list[dict]:
        """Scan the target folder and return a list of file candidates."""
        self.scan_start = datetime.datetime.now()
        self.scan_results = []

        if not self.target_path.exists():
            raise FileNotFoundError(f"Path does not exist: {self.target_path}")

        if self.target_path.is_file():
            # Single file mode
            self.scan_results.append(self._analyze_file(self.target_path))
        else:
            # Directory mode
            pattern = "**/*" if self.recursive else "*"
            for filepath in self.target_path.glob(pattern):
                if filepath.is_file():
                    try:
                        candidate = self._analyze_file(filepath)
                        self.scan_results.append(candidate)
                    except Exception as e:
                        self.scan_results.append({
                            "filepath": str(filepath),
                            "filename": filepath.name,
                            "error": str(e),
                            "status": "error",
                        })

        self.scan_end = datetime.datetime.now()
        return self.scan_results

    def scan_generator(self) -> Generator[dict, None, None]:
        """Yield file candidates one at a time (for progress tracking)."""
        self.scan_start = datetime.datetime.now()
        self.scan_results = []

        if self.target_path.is_file():
            result = self._analyze_file(self.target_path)
            self.scan_results.append(result)
            yield result
        else:
            pattern = "**/*" if self.recursive else "*"
            for filepath in self.target_path.glob(pattern):
                if filepath.is_file():
                    try:
                        result = self._analyze_file(filepath)
                    except Exception as e:
                        result = {
                            "filepath": str(filepath),
                            "filename": filepath.name,
                            "error": str(e),
                            "status": "error",
                        }
                    self.scan_results.append(result)
                    yield result

        self.scan_end = datetime.datetime.now()

    def count_files(self) -> int:
        """Count total files without scanning."""
        if self.target_path.is_file():
            return 1
        pattern = "**/*" if self.recursive else "*"
        return sum(1 for f in self.target_path.glob(pattern) if f.is_file())

    def _analyze_file(self, filepath: Path) -> dict:
        """Read file header and compute basic metadata."""
        stat = filepath.stat()

        # Read first 512 bytes
        with open(filepath, "rb") as f:
            raw_header = f.read(SAMPLE_SIZE)

        file_size = stat.st_size
        actual_read = len(raw_header)

        # Pad if shorter than 512
        if actual_read < SAMPLE_SIZE:
            raw_header = raw_header + b"\x00" * (SAMPLE_SIZE - actual_read)

        byte_array = np.frombuffer(raw_header, dtype=np.uint8).copy()

        # Compute SHA-256 of full file
        sha256 = self._compute_sha256(filepath)

        # Check if header looks empty/zeroed
        header_empty = np.all(byte_array[:16] == 0)

        return {
            "filepath": str(filepath),
            "filename": filepath.name,
            "extension": filepath.suffix.lower(),
            "file_size": file_size,
            "byte_array": byte_array,
            "sha256": sha256,
            "header_empty": bool(header_empty),
            "modified_time": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "created_time": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "status": STATUS_HEADERLESS if header_empty else STATUS_UNKNOWN,
            "error": None,
        }

    @staticmethod
    def _compute_sha256(filepath: Path) -> str:
        """Compute SHA-256 hash of the full file."""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get_summary(self) -> dict:
        """Return scan summary statistics."""
        total = len(self.scan_results)
        errors = sum(1 for r in self.scan_results if r.get("error"))
        headerless = sum(1 for r in self.scan_results if r.get("header_empty"))

        return {
            "target_path": str(self.target_path),
            "total_files": total,
            "errors": errors,
            "headerless_files": headerless,
            "scan_start": self.scan_start.isoformat() if self.scan_start else None,
            "scan_end": self.scan_end.isoformat() if self.scan_end else None,
            "scan_duration_seconds": (self.scan_end - self.scan_start).total_seconds() if self.scan_end and self.scan_start else 0,
        }


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    scanner = FolderScanner(path, recursive=False)
    results = scanner.scan()
    summary = scanner.get_summary()
    print(f"Scanned {summary['total_files']} files in {summary['scan_duration_seconds']:.2f}s")
    for r in results[:5]:
        print(f"  {r['filename']} | {r['extension']} | {r['file_size']} bytes | SHA: {r['sha256'][:16]}...")
