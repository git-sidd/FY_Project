import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)

from recovery.yara_scanner import YARAScanner
scanner = YARAScanner()

for f in os.listdir("recovered_files"):
    with open(os.path.join("recovered_files", f), "rb") as fl:
        res = scanner.scan_bytes(fl.read(), f)
        print(f"{f}: threat={res['threat_detected']}")
