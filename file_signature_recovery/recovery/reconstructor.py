"""
File Reconstructor — Repairs corrupted files by injecting headers and fixing structure
========================================================================================
"""

import os
import shutil
import numpy as np
from pathlib import Path
from typing import Optional

# Standard file headers for injection
FILE_HEADERS = {
    "PDF":      b"%PDF-1.7\n",
    "PNG":      b"\x89PNG\r\n\x1a\n",
    "JPEG":     b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
    "JPG":      b"\xff\xd8\xff\xe1",
    "GIF":      b"GIF89a",
    "BMP":      b"BM",
    "TIFF":     b"\x49\x49\x2a\x00",
    "TIFF_BE":  b"\x4d\x4d\x00\x2a",
    "WEBP":     b"RIFF\x00\x00\x00\x00WEBP",
    "ZIP":      b"\x50\x4b\x03\x04",
    "DOCX":     b"\x50\x4b\x03\x04",
    "XLSX":     b"\x50\x4b\x03\x04",
    "PPTX":     b"\x50\x4b\x03\x04",
    "RAR":      b"\x52\x61\x72\x21\x1a\x07\x00",
    "RAR5":     b"\x52\x61\x72\x21\x1a\x07\x01\x00",
    "7Z":       b"\x37\x7a\xbc\xaf\x27\x1c",
    "GZIP":     b"\x1f\x8b\x08",
    "BZIP2":    b"\x42\x5a\x68",
    "EXE":      b"\x4d\x5a",
    "PE":       b"\x4d\x5a",
    "ELF":      b"\x7f\x45\x4c\x46",
    "CLASS":    b"\xca\xfe\xba\xbe",
    "MP3":      b"\xff\xfb",
    "MP3_ID3":  b"\x49\x44\x33",
    "WAV":      b"RIFF\x00\x00\x00\x00WAVE",
    "OGG":      b"\x4f\x67\x67\x53",
    "FLAC":     b"\x66\x4c\x61\x43",
    "MP4":      b"\x00\x00\x00\x20\x66\x74\x79\x70",
    "AVI":      b"RIFF\x00\x00\x00\x00AVI ",
    "SQLITE":   b"SQLite format 3\x00",
    "XML":      b"<?xml",
    "HTML":     b"<!DOCTYPE",
    "HTML_TAG": b"<html",
}

# File extension mapping
TYPE_TO_EXTENSION = {
    "PDF": ".pdf", "PNG": ".png", "JPEG": ".jpg", "JPG": ".jpg",
    "GIF": ".gif", "BMP": ".bmp", "TIFF": ".tiff", "TIFF_BE": ".tiff",
    "WEBP": ".webp", "ZIP": ".zip", "DOCX": ".docx", "XLSX": ".xlsx",
    "PPTX": ".pptx", "RAR": ".rar", "RAR5": ".rar", "7Z": ".7z",
    "GZIP": ".gz", "BZIP2": ".bz2", "EXE": ".exe", "PE": ".exe",
    "ELF": ".elf", "CLASS": ".class", "MP3": ".mp3", "MP3_ID3": ".mp3",
    "WAV": ".wav", "OGG": ".ogg", "FLAC": ".flac", "MP4": ".mp4",
    "AVI": ".avi", "SQLITE": ".db", "XML": ".xml", "HTML": ".html",
    "HTML_TAG": ".html", "UNKNOWN": ".bin",
}

# File footers for EOF repair
FILE_FOOTERS = {
    "PDF": b"%%EOF",
    "PNG": b"\x49\x45\x4e\x44\xae\x42\x60\x82",
    "JPEG": b"\xff\xd9",
    "JPG": b"\xff\xd9",
    "GIF": b"\x00\x3b",
    "ZIP": b"\x50\x4b\x05\x06",
}


class FileReconstructor:
    """Reconstructs corrupted or headerless files."""

    def __init__(self, output_dir: str = "recovered_files", quarantine_dir: str = "quarantine"):
        self.output_dir = Path(output_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.reconstruction_log = []

    def reconstruct(self, filepath: str, predicted_type: str,
                    header_intact: bool, is_malicious: bool,
                    confidence: float = 0.0) -> dict:
        """
        Reconstruct a file based on AI prediction.

        Parameters
        ----------
        filepath : str - Path to the original file
        predicted_type : str - AI-predicted file type (e.g., "PDF", "PNG")
        header_intact : bool - Whether the file header is intact
        is_malicious : bool - Whether YARA flagged this as malware
        confidence : float - AI confidence score

        Returns
        -------
        dict with reconstruction details
        """
        filepath = Path(filepath)
        original_name = filepath.stem
        predicted_ext = TYPE_TO_EXTENSION.get(predicted_type, ".bin")

        result = {
            "original_path": str(filepath),
            "original_name": filepath.name,
            "predicted_type": predicted_type,
            "confidence": confidence,
            "header_intact": header_intact,
            "is_malicious": is_malicious,
            "action": None,
            "output_path": None,
            "repairs": [],
        }

        # ── MALICIOUS: Quarantine ──
        if is_malicious:
            quarantine_path = self.quarantine_dir / f"QUARANTINE_{filepath.name}"
            shutil.copy2(str(filepath), str(quarantine_path))
            result["action"] = "quarantined"
            result["output_path"] = str(quarantine_path)
            self.reconstruction_log.append(result)
            return result

        # ── Read full file ──
        with open(filepath, "rb") as f:
            file_data = f.read()

        reconstructed_data = bytearray(file_data)
        repairs = []

        # ── HEADER INJECTION ──
        if not header_intact and predicted_type in FILE_HEADERS:
            correct_header = FILE_HEADERS[predicted_type]
            header_len = len(correct_header)

            # Check if header needs replacement
            current_header = file_data[:header_len]
            if current_header != correct_header:
                # Inject correct header
                reconstructed_data[:header_len] = correct_header
                repairs.append(f"Header injected: {predicted_type} signature ({header_len} bytes)")

        # ── EOF FIX ──
        if predicted_type in FILE_FOOTERS:
            correct_footer = FILE_FOOTERS[predicted_type]
            if not file_data.endswith(correct_footer):
                # Check if footer exists anywhere near the end
                last_256 = file_data[-256:] if len(file_data) > 256 else file_data
                if correct_footer not in last_256:
                    reconstructed_data.extend(correct_footer)
                    repairs.append(f"EOF marker appended: {predicted_type} footer ({len(correct_footer)} bytes)")

        # ── EXTENSION FIX ──
        current_ext = filepath.suffix.lower()
        if current_ext != predicted_ext and confidence > 0.7:
            repairs.append(f"Extension corrected: {current_ext} → {predicted_ext}")

        # ── Save reconstructed file ──
        output_name = f"{original_name}_recovered{predicted_ext}"
        output_path = self.output_dir / output_name
        with open(output_path, "wb") as f:
            f.write(bytes(reconstructed_data))

        result["action"] = "recovered"
        result["output_path"] = str(output_path)
        result["repairs"] = repairs
        result["output_size"] = len(reconstructed_data)
        self.reconstruction_log.append(result)
        return result

    def get_log(self) -> list[dict]:
        return self.reconstruction_log

    def get_summary(self) -> dict:
        recovered = sum(1 for r in self.reconstruction_log if r["action"] == "recovered")
        quarantined = sum(1 for r in self.reconstruction_log if r["action"] == "quarantined")
        total_repairs = sum(len(r.get("repairs", [])) for r in self.reconstruction_log)

        return {
            "total_processed": len(self.reconstruction_log),
            "recovered": recovered,
            "quarantined": quarantined,
            "total_repairs": total_repairs,
            "output_dir": str(self.output_dir),
            "quarantine_dir": str(self.quarantine_dir),
        }


if __name__ == "__main__":
    recon = FileReconstructor()
    print(f"Output dir: {recon.output_dir}")
    print(f"Quarantine dir: {recon.quarantine_dir}")
    print("✅ FileReconstructor OK")
