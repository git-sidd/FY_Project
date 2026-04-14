import sys
from PyQt6.QtWidgets import QApplication
from main import RecoveryApp

app = QApplication(sys.path)
window = RecoveryApp()
window.show()

# Mock the scan results
window.scan_results = [
    {
        "filename": "fake_file.pdf",
        "filepath": "fake_file.pdf",
        "action": "Ready",
    }
]

# Create a fake file
with open("fake_file.pdf", "wb") as f:
    f.write(b"fake data")

try:
    window.dest_lbl.setText("test_output_dir")
    window.export_and_verify()
    print("Export log rows:", window.export_log.rowCount())
except Exception as e:
    import traceback
    traceback.print_exc()

sys.exit(0)
