"""
Integrity Verification & Forensic Report Generator
=====================================================
"""

import os
import json
import hashlib
import datetime
from pathlib import Path
from typing import Optional


class IntegrityVerifier:
    """Generates forensic reports and verifies file integrity."""

    def __init__(self, output_dir: str = "outputs"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, recovery_results: list[dict], scan_summary: dict,
                        reconstruction_summary: dict) -> dict:
        """Generate a comprehensive forensic report."""
        timestamp = datetime.datetime.now()

        report = {
            "report_metadata": {
                "generated_at": timestamp.isoformat(),
                "tool": "File Signature Recovery & Analysis System",
                "version": "2.0.0",
                "report_id": hashlib.md5(timestamp.isoformat().encode()).hexdigest()[:12],
            },
            "scan_summary": scan_summary,
            "reconstruction_summary": reconstruction_summary,
            "files": [],
        }

        recovered_count = 0
        quarantined_count = 0
        error_count = 0

        for result in recovery_results:
            file_entry = {
                "filename": result.get("filename", "unknown"),
                "original_path": result.get("filepath", ""),
                "file_size": result.get("file_size", 0),
                "predicted_type": result.get("predicted_type", "UNKNOWN"),
                "confidence": round(result.get("confidence", 0) * 100, 2),
                "malware_risk": result.get("risk_level", "UNKNOWN"),
                "malware_score": round(result.get("malware_score", 0), 4),
                "yara_threats": result.get("yara_threats", []),
                "action": result.get("action", "unknown"),
                "sha256": result.get("sha256", ""),
                "repairs": result.get("repairs", []),
                "output_path": result.get("output_path", ""),
                "recovered_at": timestamp.isoformat(),
            }

            report["files"].append(file_entry)

            if file_entry["action"] == "recovered":
                recovered_count += 1
            elif file_entry["action"] == "quarantined":
                quarantined_count += 1
            elif file_entry["action"] == "error":
                error_count += 1

        report["totals"] = {
            "total_files_scanned": len(recovery_results),
            "recovered": recovered_count,
            "quarantined": quarantined_count,
            "errors": error_count,
        }

        return report

    def save_report(self, report: dict, filename: str | None = None) -> str:
        """Save report to JSON file."""
        if filename is None:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recovery_report_{ts}.json"

        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        print(f"[OK] Forensic report saved: {filepath}")
        return str(filepath)

    def save_report_txt(self, report: dict, filename: str | None = None) -> str:
        """Save a human-readable text report."""
        if filename is None:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recovery_report_{ts}.txt"

        filepath = self.output_dir / filename
        lines = []
        lines.append("=" * 65)
        lines.append("  FILE SIGNATURE RECOVERY — FORENSIC REPORT")
        lines.append("=" * 65)
        lines.append(f"  Generated : {report['report_metadata']['generated_at']}")
        lines.append(f"  Report ID : {report['report_metadata']['report_id']}")
        lines.append("")

        totals = report.get("totals", {})
        lines.append(f"  Total Scanned  : {totals.get('total_files_scanned', 0)}")
        lines.append(f"  Recovered      : {totals.get('recovered', 0)}")
        lines.append(f"  Quarantined    : {totals.get('quarantined', 0)}")
        lines.append(f"  Errors         : {totals.get('errors', 0)}")
        lines.append("")
        lines.append("-" * 65)

        # Recovered files
        lines.append("  RECOVERED FILES")
        lines.append("-" * 65)
        for f in report.get("files", []):
            if f["action"] == "recovered":
                lines.append(f"  {f['filename']}")
                lines.append(f"    Type       : {f['predicted_type']} ({f['confidence']}% confidence)")
                lines.append(f"    Malware    : {f['malware_risk']} ({f['malware_score']})")
                lines.append(f"    SHA-256    : {f['sha256'][:32]}...")
                if f.get("repairs"):
                    for repair in f["repairs"]:
                        lines.append(f"    Repair     : {repair}")
                lines.append(f"    Saved to   : {f['output_path']}")
                lines.append("")

        # Quarantined files
        quarantined = [f for f in report.get("files", []) if f["action"] == "quarantined"]
        if quarantined:
            lines.append("-" * 65)
            lines.append("  ⚠ QUARANTINED (MALICIOUS) FILES")
            lines.append("-" * 65)
            for f in quarantined:
                lines.append(f"  {f['filename']}")
                lines.append(f"    Threat     : {', '.join(t.get('rule', 'unknown') for t in f.get('yara_threats', []))}")
                lines.append(f"    SHA-256    : {f['sha256'][:32]}...")
                lines.append("")

        lines.append("=" * 65)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        print(f"[OK] Text report saved: {filepath}")
        return str(filepath)

    @staticmethod
    def verify_hash(filepath: str, expected_hash: str) -> bool:
        """Verify SHA-256 hash of a file matches expected value."""
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest() == expected_hash


if __name__ == "__main__":
    verifier = IntegrityVerifier()
    print("✅ IntegrityVerifier OK")
