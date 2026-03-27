"""
YARA Malware Scanner — Scans file bytes for malware patterns
===============================================================

Safety: Only READS bytes. Never executes any file.
If yara-python is not installed, falls back to signature-based detection.
"""

import os
import sys
from pathlib import Path

# Try to import yara; provide fallback
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("[!] yara-python not installed. Using fallback signature detection.")


# ── Built-in malware byte signatures (fallback when YARA not available) ──
MALWARE_SIGNATURES = [
    {"name": "Suspicious_MZ_in_PDF", "pattern": b"MZ", "offset_range": (0, 16),
     "context": "PE executable header found in non-executable file"},
    {"name": "Suspicious_ShellCode_NOP", "pattern": b"\x90" * 16, "offset_range": (0, 512),
     "context": "NOP sled detected - common in shellcode"},
    {"name": "Suspicious_PowerShell", "pattern": b"powershell", "offset_range": (0, 512),
     "context": "PowerShell invocation in binary file"},
    {"name": "Suspicious_CMD_Exec", "pattern": b"cmd.exe", "offset_range": (0, 512),
     "context": "Command shell reference in file"},
    {"name": "Suspicious_Download", "pattern": b"URLDownloadToFile", "offset_range": (0, 512),
     "context": "Download function reference detected"},
    {"name": "Suspicious_CreateRemoteThread", "pattern": b"CreateRemoteThread", "offset_range": (0, 512),
     "context": "Process injection API detected"},
    {"name": "Suspicious_VirtualAlloc", "pattern": b"VirtualAlloc", "offset_range": (0, 512),
     "context": "Memory allocation API in suspicious context"},
    {"name": "Suspicious_Base64_Exec", "pattern": b"base64", "offset_range": (0, 512),
     "context": "Base64 encoding reference - possible obfuscation"},
]

# Path to YARA rules
SCRIPT_DIR = Path(__file__).resolve().parent.parent
YARA_RULES_DIR = SCRIPT_DIR / "yara_rules"
DEFAULT_RULES_PATH = YARA_RULES_DIR / "malware_rules.yar"


class YARAScanner:
    """Scans file bytes for malware patterns using YARA rules or fallback signatures."""

    def __init__(self, rules_path: str | Path | None = None):
        self.rules = None
        self.rules_loaded = False

        if YARA_AVAILABLE:
            rules_file = Path(rules_path) if rules_path else DEFAULT_RULES_PATH
            if rules_file.exists():
                try:
                    self.rules = yara.compile(filepath=str(rules_file))
                    self.rules_loaded = True
                    print(f"[OK] YARA rules loaded from {rules_file}")
                except Exception as e:
                    print(f"[!] Failed to compile YARA rules: {e}")
            else:
                print(f"[!] YARA rules not found at {rules_file}")

    def scan_bytes(self, data: bytes, filename: str = "") -> dict:
        """
        Scan raw bytes for malware patterns.
        SAFETY: Only reads bytes, never executes.

        Returns dict with:
            threat_detected: bool
            threats: list of matched rules
            risk_score: float (0.0 = clean, 1.0 = definitely malware)
            action: "allow" | "quarantine"
        """
        threats = []

        if YARA_AVAILABLE and self.rules_loaded and self.rules:
            # YARA scanning
            try:
                matches = self.rules.match(data=data)
                for match in matches:
                    threats.append({
                        "rule": match.rule,
                        "tags": list(match.tags) if match.tags else [],
                        "meta": dict(match.meta) if match.meta else {},
                        "description": match.meta.get("description", match.rule) if match.meta else match.rule,
                    })
            except Exception as e:
                print(f"  [!] YARA scan error for {filename}: {e}")
        else:
            # Fallback: manual signature matching
            threats = self._fallback_scan(data, filename)

        # Compute risk score
        num_threats = len(threats)
        risk_score = min(1.0, num_threats * 0.3)  # Each threat adds 0.3

        return {
            "filename": filename,
            "threat_detected": num_threats > 0,
            "threats": threats,
            "threat_count": num_threats,
            "risk_score": risk_score,
            "action": "quarantine" if num_threats > 0 else "allow",
            "scanner": "yara" if (YARA_AVAILABLE and self.rules_loaded) else "fallback",
        }

    def scan_file(self, filepath: str | Path) -> dict:
        """Scan a file from disk."""
        filepath = Path(filepath)
        with open(filepath, "rb") as f:
            data = f.read()
        return self.scan_bytes(data, filename=filepath.name)

    def _fallback_scan(self, data: bytes, filename: str) -> list[dict]:
        """Manual signature detection when YARA is not available."""
        threats = []
        extension = os.path.splitext(filename)[1].lower() if filename else ""

        for sig in MALWARE_SIGNATURES:
            start, end = sig["offset_range"]
            search_region = data[start:min(end, len(data))]

            if sig["pattern"] in search_region:
                # Check context: MZ in a PDF is suspicious, MZ in an EXE is normal
                is_suspicious = True
                if sig["name"] == "Suspicious_MZ_in_PDF" and extension in [".exe", ".dll", ".sys"]:
                    is_suspicious = False

                if is_suspicious:
                    threats.append({
                        "rule": sig["name"],
                        "tags": ["suspicious"],
                        "meta": {"description": sig["context"]},
                        "description": sig["context"],
                    })

        return threats


if __name__ == "__main__":
    scanner = YARAScanner()

    # Test with clean PDF header
    clean_pdf = b"%PDF-1.7\n" + b"\x00" * 503
    result = scanner.scan_bytes(clean_pdf, "test.pdf")
    print(f"Clean PDF: threats={result['threat_count']}, action={result['action']}")

    # Test with suspicious file (MZ header in a .pdf)
    suspicious = b"MZ\x90\x00" + b"\x00" * 508
    result = scanner.scan_bytes(suspicious, "report.pdf")
    print(f"Suspicious: threats={result['threat_count']}, action={result['action']}")
    for t in result["threats"]:
        print(f"  → {t['rule']}: {t['description']}")

    print("✅ YARA Scanner OK")
