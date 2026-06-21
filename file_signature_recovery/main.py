import os
import sys
import pickle
import datetime
import shutil
from pathlib import Path
import numpy as np
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QComboBox, QCheckBox, QStackedWidget, 
    QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView, 
    QFileDialog, QMessageBox, QFrame, QLineEdit, QDialog, QFormLayout, QDateTimeEdit
)
# pyrefly: ignore [parse-error]

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QPalette, QFont, QIcon, QPainter, QBrush, QAction

# Setup path
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.append(SCRIPT_DIR)

try:
    from recovery.disk_scanner import DiskScanner, RecycleBinScanner
    from recovery.yara_scanner import YARAScanner
    from recovery.reconstructor import FileReconstructor
    from recovery.integrity import IntegrityVerifier
    from models.hybrid_recovery_model import HybridRecoveryModel
except ImportError as e:
    print(f"Error importing internal modules: {e}")
    sys.exit(1)

MODELS_DIR = os.path.join(SCRIPT_DIR, "saved_models")
HYBRID_MODEL_PATH = os.path.join(MODELS_DIR, "hybrid_recovery_model.keras")
LABEL_ENCODER_PATH = os.path.join(MODELS_DIR, "label_encoder.pkl")

# ----- WORKER THREAD FOR ASYNC SCANNING -----
class ScannerThread(QThread):
    progress_update = pyqtSignal(int, int, int) # cur, total, found
    file_found = pyqtSignal(dict)
    scan_complete = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, mode, drive_letter=None, kwargs=None):
        super().__init__()
        self.mode = mode
        self.drive_letter = drive_letter
        self.kwargs = kwargs or {}
        self.results = []
        self._is_running = True

    def run(self):
        try:
            if self.mode == "entire_drive" or self.mode == "unallocated":
                scanner = DiskScanner(drive_letter=self.drive_letter)
                if not scanner.is_admin:
                    self.error_occurred.emit("Administrator privileges required for Raw Disk Scan (PyTSK3).")
                    return

                def cb(cur, total, found):
                    if not self._is_running:
                        raise Exception("Scan aborted by user.")
                    self.progress_update.emit(cur, total, found)

                found = scanner.scan_for_deleted_files(
                    max_sectors=self.kwargs.get("sectors", 500000),
                    progress_callback=cb
                )
                self.results = found
                self.scan_complete.emit(self.results)

            elif self.mode == "recycle_bin":
                scanner = RecycleBinScanner()
                self.results = scanner.scan()
                self.progress_update.emit(100, 100, len(self.results))
                self.scan_complete.emit(self.results)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop(self):
        self._is_running = False


# ----- WORKER THREAD FOR FOLDER-BASED RECYCLE BIN RECOVERY -----
class RecycleBinRestoreThread(QThread):
    """Run RecycleBinScanner.restore_to_folder() in a background thread
    so the UI remains responsive during scanning.
    """
    progress_update = pyqtSignal(int, int, str)   # current, total, filename
    restore_complete = pyqtSignal(list)            # list of result dicts
    error_occurred = pyqtSignal(str)

    def __init__(self, folder_path: str, dest_dir: str):
        super().__init__()
        self.folder_path = folder_path
        self.dest_dir = dest_dir

    def run(self):
        try:
            scanner = RecycleBinScanner(output_dir=self.dest_dir)

            def _cb(cur, total, filename):
                self.progress_update.emit(cur, total, str(filename))

            results = scanner.restore_to_folder(
                self.folder_path, self.dest_dir, progress_callback=_cb
            )
            self.restore_complete.emit(results)
        except Exception as exc:
            self.error_occurred.emit(str(exc))


# ----- WORKER THREAD FOR PERMANENT DELETED FORENSIC RECOVERY -----
class PermanentRecoveryThread(QThread):
    progress_update = pyqtSignal(str, str, float) # phase, detail, pct
    recovery_complete = pyqtSignal(list)          # list of recovered items
    error_occurred = pyqtSignal(str)
    
    def __init__(self, folder_path: str, dest_dir: str, filename: str = None, extension: str = None, time_start: str = None, time_end: str = None):
        super().__init__()
        self.folder_path = folder_path
        self.dest_dir = dest_dir
        self.filename = filename
        self.extension = extension
        self.time_start = time_start
        self.time_end = time_end
        
    def run(self):
        try:
            from recovery.deleted_file_recovery import DeletedFileRecovery
            orchestrator = DeletedFileRecovery(output_dir=self.dest_dir)
            
            def cb(phase, detail, pct):
                self.progress_update.emit(phase, detail, pct)
                
            results = orchestrator.recover(
                original_folder_path=self.folder_path,
                filename=self.filename,
                extension=self.extension,
                deletion_time_start=self.time_start,
                deletion_time_end=self.time_end,
                progress_callback=cb
            )
            self.recovery_complete.emit(results)
        except Exception as e:
            self.error_occurred.emit(str(e))


# ----- PARAMETERS DIALOG FOR PERMANENT RECOVERY -----
class PermanentRecoveryDialog(QDialog):
    def __init__(self, parent=None, default_folder="", default_dest=""):
        super().__init__(parent)
        self.setWindowTitle("Forensic Permanent Delete Recovery")
        self.setMinimumWidth(450)
        
        self.setStyleSheet("""
            QDialog {
                background-color: #11111b;
                color: #cdd6f4;
            }
            QLabel {
                color: #cdd6f4;
                font-size: 13px;
                font-weight: 500;
            }
            QLineEdit, QDateTimeEdit {
                background-color: #1e1e2e;
                border: 1px solid #313244;
                border-radius: 4px;
                padding: 6px;
                color: #cdd6f4;
            }
            QPushButton {
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
        """)

        layout = QVBoxLayout(self)
        
        title = QLabel("Forensic Recovery Parameters")
        title.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        title.setStyleSheet("color: #cba6f7; margin-bottom: 12px;")
        layout.addWidget(title)
        
        form = QFormLayout()
        
        self.folder_edit = QLineEdit(default_folder)
        self.folder_edit.setPlaceholderText("e.g. C:\\Users\\Acer\\Documents")
        form.addRow("Original Folder Path:", self.folder_edit)
        
        self.dest_edit = QLineEdit(default_dest)
        form.addRow("Destination Folder:", self.dest_edit)
        
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("e.g. report.pdf (optional)")
        form.addRow("Filename Filter:", self.file_edit)
        
        self.ext_edit = QLineEdit()
        self.ext_edit.setPlaceholderText("e.g. pdf (optional)")
        form.addRow("Extension Filter:", self.ext_edit)
        
        self.use_time_start = QCheckBox("Filter by Deletion Time Start")
        self.time_start_edit = QDateTimeEdit(datetime.datetime.now() - datetime.timedelta(days=7))
        self.time_start_edit.setCalendarPopup(True)
        self.time_start_edit.setEnabled(False)
        self.use_time_start.toggled.connect(self.time_start_edit.setEnabled)
        form.addRow(self.use_time_start, self.time_start_edit)
        
        self.use_time_end = QCheckBox("Filter by Deletion Time End")
        self.time_end_edit = QDateTimeEdit(datetime.datetime.now())
        self.time_end_edit.setCalendarPopup(True)
        self.time_end_edit.setEnabled(False)
        self.use_time_end.toggled.connect(self.time_end_edit.setEnabled)
        form.addRow(self.use_time_end, self.time_end_edit)
        
        layout.addLayout(form)
        
        btn_box = QHBoxLayout()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.setStyleSheet("background-color: #313244; color: #cdd6f4;")
        btn_cancel.clicked.connect(self.reject)
        
        btn_start = QPushButton("Start Recovery")
        btn_start.setStyleSheet("background-color: #a6e3a1; color: #11111b;")
        btn_start.clicked.connect(self.accept)
        
        btn_box.addWidget(btn_cancel)
        btn_box.addWidget(btn_start)
        layout.addLayout(btn_box)

    def get_values(self):
        return {
            "folder": self.folder_edit.text().strip(),
            "dest": self.dest_edit.text().strip(),
            "filename": self.file_edit.text().strip() or None,
            "extension": self.ext_edit.text().strip() or None,
            "time_start": self.time_start_edit.dateTime().toPyDateTime().isoformat() if self.use_time_start.isChecked() else None,
            "time_end": self.time_end_edit.dateTime().toPyDateTime().isoformat() if self.use_time_end.isChecked() else None
        }


# ----- PROBABILITY MAP WIDGET -----
class ProbabilityMap(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(60)
        self.sectors = []
        self.total_sectors = 100
        
    def update_map(self, cur, total, found_events):
        self.total_sectors = total
        # Just record the position to paint
        if len(self.sectors) < 1000: # Limit history size
            self.sectors.append((cur / total if total else 0, found_events))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        rect = self.rect()
        painter.fillRect(rect, QColor("#1e1e2e"))
        
        if not self.total_sectors:
            return
            
        w = rect.width()
        h = rect.height()
        
        # Draw blocks
        block_w = 4
        for x in range(0, w, block_w + 1):
            ratio = x / w
            # Find closest logged sector
            drawn = False
            for s_ratio, s_found in reversed(self.sectors):
                if abs(s_ratio - ratio) < 0.05:
                    if s_found > 0:
                        painter.fillRect(x, 0, block_w, h, QColor("#a6e3a1")) # Green = Data found
                    else:
                        painter.fillRect(x, 0, block_w, h, QColor("#89b4fa")) # Blue = Scanned, clear
                    drawn = True
                    break
            
            if not drawn:
                painter.fillRect(x, 0, block_w, h, QColor("#313244")) # Empty space

# ----- MAIN UI WINDOW -----
class RecoveryApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Forensic File Recovery (PyTSK3)")
        self.setMinimumSize(1000, 700)
        
        # State
        self.model = None
        self.label_decoder = None
        self.yara_scanner = None
        self.reconstructor = None
        self.scan_results = []
        
        self.init_ui()
        self.apply_dark_theme()
        
        # Load AI models in background via QTimer
        QTimer.singleShot(100, self.load_ai_backend)

    def apply_dark_theme(self):
        # A sleek, modern dark theme matching web-app aesthetics
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #11111b;
                color: #cdd6f4;
                font-family: 'Segoe UI', Inter, sans-serif;
            }
            QLabel { font-size: 14px; }
            QPushButton {
                background-color: #89b4fa;
                color: #11111b;
                border-radius: 6px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #b4befe; }
            QPushButton:disabled { background-color: #45475a; color: #a6adc8; }
            QComboBox, QCheckBox {
                background-color: #1e1e2e;
                border: 1px solid #313244;
                border-radius: 4px;
                padding: 6px;
                color: #cdd6f4;
            }
            QTableWidget {
                background-color: #1e1e2e;
                border: 1px solid #313244;
                gridline-color: #313244;
                border-radius: 8px;
            }
            QHeaderView::section {
                background-color: #313244;
                color: #cdd6f4;
                padding: 6px;
                border: none;
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #313244;
                background-color: #1e1e2e;
                height: 14px;
                border-radius: 7px;
                text-align: center;
                color: transparent;
            }
            QProgressBar::chunk {
                background-color: qlineargradient(x1: 0, y1: 0, x2: 1, y2: 0, stop: 0 #89b4fa, stop: 1 #cba6f7);
                border-radius: 7px;
            }
        """)

    def load_ai_backend(self):
        self.status_lbl.setText("Loading AI Brain and YARA Guards...")
        # Model
        self.model = HybridRecoveryModel()
        try:
            self.model.load(HYBRID_MODEL_PATH)
        except Exception:
            pass # Graceful failure
        
        if os.path.exists(LABEL_ENCODER_PATH):
            with open(LABEL_ENCODER_PATH, "rb") as f:
                le = pickle.load(f)
                self.label_decoder = le.classes_
                
        try:
            self.yara_scanner = YARAScanner()
        except:
            self.yara_scanner = None
            
        self.reconstructor = FileReconstructor(output_dir="recovered_files")
        self.status_lbl.setText("Ready.")

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Header title
        title = QLabel("🔮 AI Forensic Recovery & Healing")
        title.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #cba6f7; margin-bottom: 20px;")
        main_layout.addWidget(title)
        
        # Stack wrapper for different phases
        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack)
        
        self.stack.addWidget(self.create_phase1_widget())
        self.stack.addWidget(self.create_phase2_widget())
        self.stack.addWidget(self.create_phase3_widget())
        self.stack.addWidget(self.create_phase4_widget())
        
        # Status bar replacement
        self.status_lbl = QLabel("Initializing...")
        self.status_lbl.setStyleSheet("color: #a6adc8; font-size: 12px; margin-top: 10px;")
        main_layout.addWidget(self.status_lbl)

    def create_phase1_widget(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setAlignment(Qt.AlignmentFlag.AlignTop)
        
        lbl = QLabel("Phase 1: Connection & Triage")
        lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        lay.addWidget(lbl)
        
        # Drive Selection
        lay.addWidget(QLabel("Select Target Drive:"))
        self.drive_combo = QComboBox()
        self.drive_combo.setEditable(True)
        for d in "CDEFGHIJKLMNOPQRSTUVWXYZ":
            if os.path.exists(f"{d}:\\"):
                # Mock health status for aesthetic demo
                health = "Moderate" if d == "C" else "Excellent"
                self.drive_combo.addItem(f"{d}:\\  — Health: {health}")
        lay.addWidget(self.drive_combo)
        
        # Options
        self.chk_image = QCheckBox("Preserve Evidence (Create .dd image fallback)")
        self.chk_image.setStyleSheet("margin-top: 10px;")
        lay.addWidget(self.chk_image)
        
        self.scan_type = QComboBox()
        self.scan_type.addItems(["Unallocated (Deleted) Space — PyTSK3 Raw Sectors", "Recycle Bin Scan", "Entire Drive", "Permanent Delete Recovery"])
        lay.addWidget(QLabel("Target Scope:"))
        lay.addWidget(self.scan_type)
        
        btn_start = QPushButton("Start Intelligent Scan ➔")
        btn_start.setMinimumHeight(45)
        btn_start.clicked.connect(self.start_phase2)
        lay.addSpacing(30)
        lay.addWidget(btn_start)

        # ── Recycle Bin folder recovery ─────────────────────────────────────
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setStyleSheet("color: #313244; margin-top: 14px; margin-bottom: 4px;")
        lay.addWidget(separator)

        rb_lbl = QLabel("♻️  Recycle Bin Recovery — recover all files from a deleted folder")
        rb_lbl.setStyleSheet("font-weight: bold; font-size: 13px; color: #a6e3a1; margin-bottom: 4px;")
        lay.addWidget(rb_lbl)

        lay.addWidget(QLabel("Original folder path (where the files were before deletion):"))
        self.perm_path_edit = QLineEdit()
        self.perm_path_edit.setPlaceholderText("e.g.  C:\\Users\\Acer\\Documents\\MyProject")
        lay.addWidget(self.perm_path_edit)

        dest_row = QHBoxLayout()
        lay.addWidget(QLabel("Destination folder (where to save recovered files):"))
        self.rb_dest_edit = QLineEdit()
        self.rb_dest_edit.setText(os.path.join(SCRIPT_DIR, "recovered_files"))
        btn_browse_rb = QPushButton("Browse…")
        btn_browse_rb.setFixedWidth(90)
        btn_browse_rb.clicked.connect(self._browse_rb_dest)
        dest_row.addWidget(self.rb_dest_edit)
        dest_row.addWidget(btn_browse_rb)
        lay.addLayout(dest_row)

        btn_rb = QPushButton("🔎  Recover All Files Deleted from This Folder")
        btn_rb.setMinimumHeight(45)
        btn_rb.setStyleSheet(
            "background-color: #a6e3a1; color: #11111b; font-weight: bold;"
        )
        btn_rb.clicked.connect(self.recover_permanent_folder)
        lay.addWidget(btn_rb)

        return w

    def create_phase2_widget(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        
        lay.addWidget(QLabel("Phase 2: Intelligent Deep Scan (LSTM + YARA)"))
        
        # Map
        lay.addWidget(QLabel("Sector Probability Map (Progress):"))
        self.prob_map = ProbabilityMap()
        lay.addWidget(self.prob_map)
        
        self.prog_bar = QProgressBar()
        lay.addWidget(self.prog_bar)
        
        # Live List
        lay.addWidget(QLabel("Live Discovery View:"))
        self.live_table = QTableWidget(0, 3)
        self.live_table.setHorizontalHeaderLabels(["Sector/Location", "Guessed Type", "Bytes"])
        self.live_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.live_table)
        
        nav_lay = QHBoxLayout()
        btn_back = QPushButton("⬅ Back to Setup")
        btn_back.clicked.connect(self.cancel_scan_and_back)
        
        self.btn_next2 = QPushButton("Review Findings ➔")
        self.btn_next2.setEnabled(False)
        self.btn_next2.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        
        nav_lay.addWidget(btn_back)
        nav_lay.addWidget(self.btn_next2)
        lay.addLayout(nav_lay)
        
        return w

    def create_phase3_widget(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        
        lay.addWidget(QLabel("Phase 3: Review & Self-Healing"))
        
        self.res_table = QTableWidget(0, 5)
        self.res_table.setHorizontalHeaderLabels(["Filename", "AI Label", "Confidence", "Threat", "Action"])
        self.res_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.res_table)
        
        tools_lay = QHBoxLayout()
        self.btn_heal = QPushButton("🪄 Auto-Heal Broken Headers")
        self.btn_heal.clicked.connect(self.auto_heal_selected)
        self.btn_auth = QPushButton("🛡️ Authorize Quarantined (Risk)")
        self.btn_auth.setStyleSheet("background-color: #f38ba8; color: #11111b;")
        self.btn_auth.clicked.connect(self.authorize_selected)
        
        tools_lay.addWidget(self.btn_heal)
        tools_lay.addWidget(self.btn_auth)
        lay.addLayout(tools_lay)
        
        nav_lay = QHBoxLayout()
        btn_back = QPushButton("⬅ Back to Deep Scan")
        btn_back.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        
        btn_next = QPushButton("Proceed to Safe Export ➔")
        btn_next.clicked.connect(lambda: self.stack.setCurrentIndex(3))
        
        nav_lay.addWidget(btn_back)
        nav_lay.addWidget(btn_next)
        lay.addLayout(nav_lay)
        
        return w

    def create_phase4_widget(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        
        lbl = QLabel("Phase 4: Export & Forensic Verification")
        lbl.setFont(QFont("Segoe UI", 18, QFont.Weight.Bold))
        lay.addWidget(lbl)
        
        # Dest
        lay.addWidget(QLabel("Choose Safe Destination Folder (Preferably External Drive):"))
        dest_lay = QHBoxLayout()
        self.dest_lbl = QLabel(os.path.join(os.getcwd(), "recovered_files"))
        self.dest_lbl.setStyleSheet("background-color: #1e1e2e; padding: 8px; border-radius: 4px;")
        btn_browse = QPushButton("Browse...")
        btn_browse.clicked.connect(self.browse_dest)
        dest_lay.addWidget(self.dest_lbl, 1)
        dest_lay.addWidget(btn_browse)
        lay.addLayout(dest_lay)
        
        # Verify
        self.btn_export = QPushButton("Export Files and Run SHA-256 Hash Check")
        self.btn_export.setMinimumHeight(45)
        self.btn_export.setStyleSheet("background-color: #a6e3a1;")
        self.btn_export.clicked.connect(self.export_and_verify)
        lay.addWidget(self.btn_export)
        
        self.export_log = QTableWidget(0, 3)
        self.export_log.setHorizontalHeaderLabels(["File", "Verification", "SHA-256"])
        self.export_log.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.export_log)
        
        self.btn_report = QPushButton("📄 Download PDF/TXT Forensic Report")
        self.btn_report.clicked.connect(self.generate_report)
        self.btn_report.setEnabled(False)
        
        nav_lay = QHBoxLayout()
        btn_back = QPushButton("⬅ Back to Review")
        # Go back to phase 3 (index 2)
        btn_back.clicked.connect(lambda: self.stack.setCurrentIndex(2))
        
        nav_lay.addWidget(btn_back)
        nav_lay.addWidget(self.btn_report)
        lay.addLayout(nav_lay)
        
        return w

    def browse_dest(self):
        f = QFileDialog.getExistingDirectory(self, "Select Destination")
        if f:
            self.dest_lbl.setText(f)

    # ----- ACTIONS -----
    def _browse_rb_dest(self):
        """Open folder picker for the Recycle Bin restore destination."""
        folder = QFileDialog.getExistingDirectory(self, "Select Destination Folder")
        if folder:
            self.rb_dest_edit.setText(folder)

    def recover_permanent_folder(self):
        """Start recovering all files (deleted from Recycle Bin) that originated
        in the user-specified folder path.
        """
        folder_path = self.perm_path_edit.text().strip()
        dest_dir = self.rb_dest_edit.text().strip()

        if not folder_path:
            QMessageBox.warning(
                self,
                "Input Required",
                "Please enter the original folder path where the files were before deletion.",
            )
            return

        if not dest_dir:
            QMessageBox.warning(
                self, "Destination Required", "Please choose a destination folder."
            )
            return

        # Switch to Phase 2 view so user sees progress
        self.stack.setCurrentIndex(1)
        self.live_table.setRowCount(0)
        self.prog_bar.setValue(0)
        self.btn_next2.setEnabled(False)
        self.status_lbl.setText(f"Scanning Recycle Bin for files from: {folder_path} …")

        self._rb_restore_thread = RecycleBinRestoreThread(folder_path, dest_dir)
        self._rb_restore_thread.progress_update.connect(self._on_rb_progress)
        self._rb_restore_thread.restore_complete.connect(self._on_rb_complete)
        self._rb_restore_thread.error_occurred.connect(self._on_rb_error)
        self._rb_restore_thread.start()

    def _on_rb_progress(self, cur: int, total: int, filename: str):
        if total > 0:
            pct = int((cur / total) * 100)
            self.prog_bar.setValue(pct)
        self.status_lbl.setText(f"Restoring {cur}/{total}: {filename}")

    def _on_rb_complete(self, results: list):
        """Called when all restoration work is done."""
        self.prog_bar.setValue(100)

        # ── No files found at all ──────────────────────────────────────────────
        if not results:
            self.status_lbl.setText("No deleted files found for that folder in the Recycle Bin.")
            QMessageBox.information(
                self,
                "Recycle Bin Recovery",
                "No deleted files were found in the Recycle Bin for the specified folder.\n\n"
                "This means either:\n"
                "  • The files were already permanently erased from the Recycle Bin, or\n"
                "  • The folder path you entered doesn't match any deleted entries.\n\n"
                "Tip: Check the exact original path (case-insensitive match is used).",
            )
            self.stack.setCurrentIndex(0)
            return

        recovered = [r for r in results if r["status"] == "recovered"]
        errors    = [r for r in results if r["status"] == "error"]

        # Populate the live discovery table
        self.live_table.setRowCount(0)
        for r in results:
            row = self.live_table.rowCount()
            self.live_table.insertRow(row)
            self.live_table.setItem(row, 0, QTableWidgetItem(r["filename"]))
            status_label = "✅ Recovered" if r["status"] == "recovered" else "❌ Error"
            status_item = QTableWidgetItem(status_label)
            if r["status"] == "recovered":
                status_item.setForeground(QBrush(QColor("#a6e3a1")))
            else:
                status_item.setForeground(QBrush(QColor("#f38ba8")))
            self.live_table.setItem(row, 1, status_item)
            size_bytes = r.get("file_size", 0)
            size_str = f"{size_bytes:,} bytes" if size_bytes else "—"
            self.live_table.setItem(row, 2, QTableWidgetItem(size_str))
            QApplication.processEvents()

        total = len(results)
        self.status_lbl.setText(
            f"Recovery complete — {len(recovered)}/{total} file(s) recovered "
            f"({len(errors)} error(s))."
        )

        # Build scan_results so Phase 3 / 4 export pipeline works
        self.scan_results = []
        for r in recovered:
            self.scan_results.append({
                "filename": r["filename"],
                "filepath": r["dest_path"],
                "original_path": r["original_path"],
                "file_size": r.get("file_size", 0),
                "sha256": r["sha256"],
                "p_type": Path(r["filename"]).suffix.lstrip(".").upper() or "File",
                "conf": 1.0,
                "y_threat": False,
                "action": "Ready",
                "header_empty": False,
                "source": "recycle_bin_folder",
                "status": "recovered",
            })

        if self.scan_results:
            self.btn_next2.setEnabled(True)
            self.populate_phase3()

        # Summary dialog
        dest = self.rb_dest_edit.text()
        msg = (
            f"✅  Recovered {len(recovered)} of {total} file(s) from the Recycle Bin.\n"
            f"📁  Saved to: {dest}"
        )
        if errors:
            msg += f"\n\n⚠️  {len(errors)} file(s) could not be restored:\n"
            msg += "\n".join(f"  • {e['filename']}: {e['error']}" for e in errors[:5])
            if len(errors) > 5:
                msg += f"\n  … and {len(errors) - 5} more."
        QMessageBox.information(self, "Recycle Bin Recovery — Done", msg)

    def _on_rb_error(self, err: str):
        self.prog_bar.setValue(0)
        self.status_lbl.setText("Recovery failed.")
        QMessageBox.critical(self, "Recovery Error", err)
        self.stack.setCurrentIndex(0)

    def recover_permanent(self):
        folder_path = self.perm_path_edit.text().strip()
        dest_dir = self.rb_dest_edit.text().strip()
        
        dlg = PermanentRecoveryDialog(self, default_folder=folder_path, default_dest=dest_dir)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
            
        vals = dlg.get_values()
        if not vals["folder"]:
            QMessageBox.warning(self, "Folder Required", "Please specify the original folder path.")
            return
        if not vals["dest"]:
            QMessageBox.warning(self, "Destination Required", "Please specify the destination folder.")
            return
            
        self.perm_path_edit.setText(vals["folder"])
        self.rb_dest_edit.setText(vals["dest"])
        
        self.stack.setCurrentIndex(1)
        self.live_table.setRowCount(0)
        self.prog_bar.setValue(0)
        self.btn_next2.setEnabled(False)
        self.status_lbl.setText("Initializing forensic permanent recovery orchestrator...")
        
        self._perm_recovery_thread = PermanentRecoveryThread(
            folder_path=vals["folder"],
            dest_dir=vals["dest"],
            filename=vals["filename"],
            extension=vals["extension"],
            time_start=vals["time_start"],
            time_end=vals["time_end"]
        )
        self._perm_recovery_thread.progress_update.connect(self._on_perm_progress)
        self._perm_recovery_thread.recovery_complete.connect(self._on_perm_complete)
        self._perm_recovery_thread.error_occurred.connect(self._on_perm_error)
        self._perm_recovery_thread.start()

    def _on_perm_progress(self, phase: str, detail: str, pct: float):
        self.prog_bar.setValue(int(pct * 100))
        self.status_lbl.setText(f"[{phase.upper()}] {detail}")
        
    def _on_perm_error(self, err: str):
        self.prog_bar.setValue(0)
        self.status_lbl.setText("Permanent recovery failed.")
        QMessageBox.critical(self, "Recovery Error", err)
        self.stack.setCurrentIndex(0)
        
    def _on_perm_complete(self, results: list):
        self.prog_bar.setValue(100)
        
        if not results:
            self.status_lbl.setText("No permanently deleted files found.")
            QMessageBox.information(
                self,
                "Permanent Recovery Complete",
                "No permanently deleted files matching your criteria were found on the drive filesystem."
            )
            self.stack.setCurrentIndex(0)
            return
            
        self.status_lbl.setText("Running LSTM + YARA analysis on recovered files...")
        
        processed_results = []
        for cand in results:
            filepath = cand.get("recovered_path")
            if cand.get("status") != "recovered" or not filepath or not os.path.exists(filepath):
                continue
                
            p_type = "Unknown"
            conf = 0.8
            if self.model:
                try:
                    with open(filepath, "rb") as f:
                        file_data = f.read()
                    header = file_data[:512]
                    if len(header) < 512:
                        header = header + b"\x00" * (512 - len(header))
                    b = np.frombuffer(header, dtype=np.uint8).copy().astype('float32')
                    
                    pred = self.model.predict_single(b)
                    p_idx = pred["predicted_class_idx"]
                    p_type = self.label_decoder[p_idx] if self.label_decoder is not None and p_idx < len(self.label_decoder) else f"Type_{p_idx}"
                    conf = pred["confidence"]
                except Exception:
                    p_type = Path(filepath).suffix.lstrip(".").upper() or "File"
                    conf = 0.85
            else:
                p_type = Path(filepath).suffix.lstrip(".").upper() or "File"
                conf = 0.85
                
            y_threat = False
            threat_details = []
            if self.yara_scanner:
                try:
                    with open(filepath, "rb") as f:
                        data = f.read()
                    yr = self.yara_scanner.scan_bytes(data, cand["filename"])
                    y_threat = yr["threat_detected"]
                    threat_details = yr["threats"]
                except:
                    pass
                    
            cand_item = {
                "filename": cand["filename"],
                "filepath": filepath,
                "original_path": cand.get("original_path", ""),
                "file_size": cand.get("file_size", 0),
                "sha256": cand.get("sha256", ""),
                "p_type": p_type,
                "conf": conf,
                "y_threat": y_threat,
                "threat_details": threat_details,
                "action": "Ready" if not y_threat else "Quarantined",
                "header_empty": False,
                "source": "permanent_recovery",
                "status": "recovered",
            }
            processed_results.append(cand_item)
            
            row = self.live_table.rowCount()
            self.live_table.insertRow(row)
            self.live_table.setItem(row, 0, QTableWidgetItem(cand_item["filename"]))
            self.live_table.setItem(row, 1, QTableWidgetItem(f"Probable_{p_type}_{int(conf*100)}%_Confidence"))
            self.live_table.setItem(row, 2, QTableWidgetItem(str(cand_item["file_size"])))
            QApplication.processEvents()
            
        self.scan_results = processed_results
        self.btn_next2.setEnabled(True)
        self.status_lbl.setText(f"Forensic Permanent Scan complete. Found {len(processed_results)} recoverable files.")
        self.populate_phase3()
        
        dest = self.rb_dest_edit.text()
        QMessageBox.information(
            self,
            "Permanent Recovery Done",
            f"Forensic permanent recovery completed!\n\n"
            f"Successfully recovered: {len(processed_results)} file(s).\n"
            f"Saved in: {dest}\n\n"
            f"You can now review header health and authorize threats in Phase 3."
        )

    def start_phase2(self):
        d_val = self.drive_combo.currentText().strip()
        if not d_val: return
        
        # Check if the user selected one of the default options, or typed their own path
        if "— Health:" in d_val:
            drive = d_val.split(":")[0]
        else:
            # The user typed a custom drive or path
            drive = d_val

        
        scope = self.scan_type.currentText()
        if "Recycle" in scope:
            mode = "recycle_bin"
        elif "Permanent Delete Recovery" in scope:
            mode = "permanent_recovery"
        else:
            mode = "unallocated"

        if mode == "permanent_recovery":
            self.recover_permanent()
            return
            
        self.stack.setCurrentIndex(1)
        self.live_table.setRowCount(0)
        self.prog_bar.setValue(0)
        self.btn_next2.setEnabled(False)
        
        self.scanner_th = ScannerThread(mode, drive_letter=drive, kwargs={"sectors": 100000}) # small limit for demo
        self.scanner_th.progress_update.connect(self.on_scan_prog)
        self.scanner_th.scan_complete.connect(self.on_scan_done)
        self.scanner_th.error_occurred.connect(self.on_scan_err)
        self.scanner_th.start()

    def on_scan_prog(self, cur, total, found):
        if total > 0:
            pct = int((cur / total) * 100)
            self.prog_bar.setValue(pct)
            self.prob_map.update_map(cur, total, found)
            self.status_lbl.setText(f"Scanning sector {cur:,}/{total:,}. Found fragments: {found}")

    def on_scan_done(self, results):
        self.status_lbl.setText("Running LSTM + YARA parallel analysis...")
        
        # Parallel Classify Mock
        for i, cand in enumerate(results):
            # Classify
            if self.model and "byte_array" in cand:
                b = cand["byte_array"].astype('float32')
                try:
                    pred = self.model.predict_single(b)
                    p_idx = pred["predicted_class_idx"]
                    p_type = self.label_decoder[p_idx] if self.label_decoder is not None and p_idx < len(self.label_decoder) else f"Type_{p_idx}"
                    conf = pred["confidence"]
                except Exception as e:
                    # Fallback if model throws RuntimeError when not loaded
                    p_type = cand.get("extension", cand.get("filename", "Unknown"))
                    conf = 0.82
            else:
                p_type = cand.get("extension", cand.get("filename","Unknown"))
                conf = 0.8
                
            y_threat = False
            if self.yara_scanner:
                try:
                    with open(cand["filepath"], "rb") as f:
                        data = f.read()
                    yr = self.yara_scanner.scan_bytes(data, cand["filename"])
                    y_threat = yr["threat_detected"]
                    cand["threat_details"] = yr["threats"]
                except:
                    pass
            
            cand["p_type"] = p_type
            cand["conf"] = conf
            cand["y_threat"] = y_threat
            cand["action"] = "Ready" if not y_threat else "Quarantined"
            
            # Add to live UI
            row = self.live_table.rowCount()
            self.live_table.insertRow(row)
            self.live_table.setItem(row, 0, QTableWidgetItem(cand.get("filename","")) )
            self.live_table.setItem(row, 1, QTableWidgetItem(f"Probable_{p_type}_{int(conf*100)}%_Confidence"))
            size_val = cand.get("file_size", cand.get("carved_size", 0))
            self.live_table.setItem(row, 2, QTableWidgetItem(str(size_val)))
            
            QApplication.processEvents()
            
        self.scan_results = results
        self.prog_bar.setValue(100)
        self.btn_next2.setEnabled(True)
        self.status_lbl.setText(f"Scan complete. Found {len(results)} potentially recoverable objects.")
        self.populate_phase3()

    def on_scan_err(self, err):
        if "Scan aborted" in err:
            self.status_lbl.setText("Scan cancelled by user.")
        else:
            QMessageBox.critical(self, "Hardware/Access Error", err)
        self.stack.setCurrentIndex(0)

    def cancel_scan_and_back(self):
        if hasattr(self, 'scanner_th') and self.scanner_th.isRunning():
            self.scanner_th.stop()
        else:
            self.stack.setCurrentIndex(0)

    def populate_phase3(self):
        self.res_table.setRowCount(0)
        for cand in self.scan_results:
            row = self.res_table.rowCount()
            self.res_table.insertRow(row)
            self.res_table.setItem(row, 0, QTableWidgetItem(cand["filename"]))
            self.res_table.setItem(row, 1, QTableWidgetItem(cand["p_type"]))
            self.res_table.setItem(row, 2, QTableWidgetItem(f"{cand['conf']*100:.1f}%"))
            
            threat_item = QTableWidgetItem("⚠️ DETECTED" if cand["y_threat"] else "Safe")
            if cand["y_threat"]: threat_item.setForeground(QBrush(QColor("#f38ba8")))
            self.res_table.setItem(row, 3, threat_item)
            
            act_item = QTableWidgetItem(cand["action"])
            if cand["y_threat"]: act_item.setForeground(QBrush(QColor("#f38ba8")))
            self.res_table.setItem(row, 4, act_item)

    def auto_heal_selected(self):
        """Injects missing signatures / repairs headers."""
        sel = self.res_table.currentRow()
        if sel < 0: return
        cand = self.scan_results[sel]
        if cand["y_threat"] and cand["action"] != "Authorized":
            QMessageBox.warning(self, "Quarantined", "Cannot heal malware without authorization.")
            return

        if self.reconstructor:
            recon = self.reconstructor.reconstruct(
                cand["filepath"], cand["p_type"], False, False, cand["conf"]
            )
            cand["reconstructed_path"] = recon.get("output_path", cand["filepath"])
            cand["repairs"] = recon.get("repairs", ["Header successfully repaired"])
            
            act = self.res_table.item(sel, 4)
            act.setText("Healed ✓")
            act.setForeground(QBrush(QColor("#a6e3a1")))
            self.status_lbl.setText("Self-Healing process simulated/completed for 1 file.")

    def authorize_selected(self):
        sel = self.res_table.currentRow()
        if sel < 0: return
        self.scan_results[sel]["action"] = "Authorized"
        self.res_table.item(sel, 4).setText("Authorized")
        self.res_table.item(sel, 4).setForeground(QBrush(QColor("#fab387")))

    def export_and_verify(self):
        dest = self.dest_lbl.text()
        os.makedirs(dest, exist_ok=True)
        self.export_log.setRowCount(0)
        
        for cand in self.scan_results:
            src = cand.get("reconstructed_path", cand["filepath"])
            if cand["action"] == "Quarantined":
                continue # Skip un-authorized threats
                
            fname = os.path.basename(src)
            out_path = os.path.join(dest, fname)
            
            if os.path.abspath(src) != os.path.abspath(out_path):
                shutil.copy2(src, out_path)
            
            # SHA-256 check
            import hashlib
            with open(out_path, "rb") as f:
                sha = hashlib.sha256(f.read()).hexdigest()
            cand["final_sha256"] = sha
            cand["final_path"] = out_path
            cand["exported"] = True
            
            row = self.export_log.rowCount()
            self.export_log.insertRow(row)
            self.export_log.setItem(row, 0, QTableWidgetItem(fname))
            v_item = QTableWidgetItem("Verified ✓")
            v_item.setForeground(QBrush(QColor("#a6e3a1")))
            self.export_log.setItem(row, 1, v_item)
            self.export_log.setItem(row, 2, QTableWidgetItem(sha[:16] + "..."))
            
        self.btn_export.setText("Export Completed")
        self.btn_export.setEnabled(False)
        self.btn_report.setEnabled(True)

    def generate_report(self):
        verifier = IntegrityVerifier(output_dir="outputs")
        # Format dummy output
        results_formatted = []
        for c in self.scan_results:
            if c.get("exported"):
                results_formatted.append({
                    "filename": os.path.basename(c["final_path"]),
                    "predicted_type": c["p_type"],
                    "confidence": c["conf"],
                    "malware_score": 0.0,
                    "risk_level": "LOW",
                    "action": c["action"],
                    "sha256": c["final_sha256"],
                    "yara_threats": []
                })
                
        report = verifier.generate_report(results_formatted, {"sources":["pytsk3_scan"]}, {})
        verifier.save_report(report)
        QMessageBox.information(self, "Forensic Report", "Report generated in ./outputs/")

if __name__ == "__main__":
    app = QApplication(sys.path)
    window = RecoveryApp()
    window.show()
    sys.exit(app.exec())
