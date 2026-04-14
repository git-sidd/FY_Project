import sys
from PyQt6.QtWidgets import QApplication
from main import RecoveryApp
import os
import shutil
import hashlib
from PyQt6.QtWidgets import QTableWidgetItem
from PyQt6.QtGui import QColor, QBrush

app = QApplication(sys.path)
window = RecoveryApp()
window.scan_results = [
    {
        "filename": "fake_file.pdf",
        "filepath": os.path.abspath("fake_file.pdf"),
        "action": "Ready",
    }
]

with open("fake_file.pdf", "wb") as f:
    f.write(b"fake data")

try:
    window.dest_lbl.setText(os.path.abspath("recovered_files"))
    window.export_and_verify()
    print("Export log rows:", window.export_log.rowCount())
    print("Button enabled:", window.btn_export.isEnabled())
    print("Button text:", window.btn_export.text())
except Exception as e:
    import traceback
    traceback.print_exc()

sys.exit(0)
