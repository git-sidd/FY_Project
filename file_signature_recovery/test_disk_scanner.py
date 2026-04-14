import os
import sys
from pathlib import Path

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)

from recovery.disk_scanner import DiskScanner
import time

def progress(cur, total, found):
    if cur % 4000 == 0 or cur == total:
        print(f"Scanning sector {cur}/{total}... Found: {found}")

print("Starting scan...")
start_time = time.time()
path = os.path.join(SCRIPT_DIR, "test_image.dd")
scanner = DiskScanner(drive_letter=path)
found = scanner.scan_for_deleted_files(max_sectors=100000, progress_callback=progress)
print(f"Scan finished in {time.time() - start_time:.2f} seconds.")
print(f"Found {len(found)} files.")
for f in found:
    print(f" - {f['sig_name']} at sector {f['disk_sector']} with size {f['carved_size']}")
