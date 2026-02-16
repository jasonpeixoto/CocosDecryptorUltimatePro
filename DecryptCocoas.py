import sys
import os
import glob
import re
import zipfile
import json
import shutil
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLineEdit, QLabel,
                             QFileDialog, QTextBrowser, QDialog, QSpacerItem, QSizePolicy)
from PyQt5.QtCore import QProcess, Qt, QObject, pyqtSignal, QProcessEnvironment, QUrl, QTimer
from PyQt5.QtGui import QTextCursor, QDesktopServices

CONFIG_FILE = "config.json"


# --- SETTINGS DIALOG ---
class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Global Binary Settings")
        self.setFixedWidth(600)
        self.layout = QVBoxLayout(self)

        self.at_edit = self.add_setting("Apktool Path:")
        self.rv_edit = self.add_setting("Reverse Path:")
        self.pt_edit = self.add_setting("Prettier Path:")

        self.btn_save = QPushButton("Save Settings")
        self.btn_save.setFixedHeight(35)
        self.btn_save.clicked.connect(self.accept)
        self.layout.addWidget(self.btn_save)
        self.load()

    def add_setting(self, label):
        h = QHBoxLayout()
        h.addWidget(QLabel(label))
        le = QLineEdit()
        h.addWidget(le)
        btn = QPushButton("Browse")
        btn.clicked.connect(lambda: le.setText(QFileDialog.getOpenFileName(self, label, "", "")[0]))
        h.addWidget(btn)
        self.layout.addLayout(h)
        return le

    def load(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                d = json.load(f)
                self.at_edit.setText(d.get("at", ""))
                self.rv_edit.setText(d.get("rv", ""))
                self.pt_edit.setText(d.get("pt", ""))

    def get_data(self):
        return {"at": self.at_edit.text(), "rv": self.rv_edit.text(), "pt": self.pt_edit.text()}


# --- BASE PIPELINE STEP ---
class PipelineStep(QObject):
    finished_signal = pyqtSignal(bool)
    log_signal = pyqtSignal(str, str)

    def __init__(self, main_win):
        super().__init__()
        self.main_win = main_win
        self.process = QProcess()
        self.process.readyReadStandardOutput.connect(self.read_out)
        self.process.readyReadStandardError.connect(self.read_err)
        self.process.finished.connect(self.on_process_finished)
        self.spinner = ["|", "/", "-", "\\"]
        self.spinner_idx = 0

    def read_out(self):
        data = self.process.readAllStandardOutput().data().decode(errors='replace').strip()
        if not data: return
        if "✓ Found key:" in data:
            key_match = re.search(r'Found key: "([^"]+)"', data)
            if key_match:
                key = key_match.group(1)
                self.main_win.key_input.setText(key)
                self.log_signal.emit(f"<b>{data}</b>", "#4CAF50")
            return
        if "Trying key" in data:
            char = self.spinner[self.spinner_idx % 4]
            self.spinner_idx += 1
            self.main_win.update_status_line(f"{char} {data}", "#FFEB3B")
            return
        self.log_signal.emit(data, "#d4d4d4")

    def read_err(self):
        data = self.process.readAllStandardError().data().decode(errors='replace').strip()
        if not data: return
        if "Successfully" in data or "written to" in data:
            self.log_signal.emit(data, "#4CAF50")
        else:
            self.log_signal.emit(f"[LOG] {data}", "#d4d4d4")

    def on_process_finished(self):
        self.finished_signal.emit(True)

    def run_bash(self, cmd, cwd=None):
        env = QProcessEnvironment.systemEnvironment()
        path = env.value("PATH")
        new_path = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:" + path
        env.insert("PATH", new_path)
        self.process.setProcessEnvironment(env)
        if cwd: self.process.setWorkingDirectory(cwd)
        self.log_signal.emit(f"[EXEC] {cmd}", "#5c5c5c")
        self.process.start("bash", ["-c", cmd])


# --- STEP CLASSES ---
class Step0_Unzip(PipelineStep):
    def run(self):
        self.log_signal.emit(f"\n--- STEP 0: Unzipping Container ---", "#FF9800")
        try:
            with zipfile.ZipFile(self.main_win.zip_path.text(), 'r') as z:
                z.extractall(self.main_win.output_path.text())
            self.finished_signal.emit(True)
        except Exception as e:
            self.log_signal.emit(f"Unzip Failed: {e}", "#f44336");
            self.finished_signal.emit(False)


class Step1_Apktool(PipelineStep):
    def __init__(self, main_win):
        super().__init__(main_win)
        self.queue = [];
        self.process.finished.disconnect()
        self.process.finished.connect(self.process_next)

    def run(self):
        self.log_signal.emit(f"\n--- STEP 1: Extracting APKs ---", "#2196F3")
        self.queue = glob.glob(os.path.join(self.main_win.output_path.text(), "*.apk"))
        self.process_next()

    def process_next(self):
        if not self.queue: self.finished_signal.emit(True); return
        apk = self.queue.pop(0)
        dest = os.path.join(self.main_win.output_path.text(), os.path.basename(apk).replace(".apk", ""))
        self.run_bash(f"'{self.main_win.binaries['at']}' d '{apk}' -o '{dest}' --force")


class Step2_FindFiles(PipelineStep):
    def run(self, folder_path):
        self.log_signal.emit(f"\n--- STEP 2: Finding Script Files ---", "#4CAF50")
        self.run_bash("find . -name '*.js'; find . -name '*.jsc'; find . -name '*.lua'; find . -name '*.luac'",
                      cwd=folder_path)


class Step3_FindEncrypted(PipelineStep):
    def run(self, folder_path):
        self.log_signal.emit(f"--- STEP 3: Checking Assets ---", "#E91E63")
        self.run_bash("find assets -name '*.jsc' -exec sh -c 'echo \"{}:\" && strings {} | head -n 5' \;",
                      cwd=folder_path)


class Step4_FindSignature(PipelineStep):
    def run(self, folder_path):
        self.log_signal.emit(f"--- STEP 4: Hex Signatures ---", "#9C27B0")
        self.run_bash("find . -name '*.jsc' -exec sh -c 'echo \"{}:\" && hexdump -C {} | head -n 1' \;",
                      cwd=folder_path)


class Step5_Bruteforce(PipelineStep):
    def run(self):
        self.log_signal.emit(f"\n--- STEP 5: Bruteforcing Key ---", "#FFEB3B")
        out_base = self.main_win.output_path.text()
        so = glob.glob(os.path.join(out_base, "**/lib/arm64-v8a/libcocos.so"), recursive=True) or glob.glob(
            os.path.join(out_base, "**/libcocos.so"), recursive=True)
        jsc = glob.glob(os.path.join(out_base, "**/assets/assets/internal/index.jsc"), recursive=True) or glob.glob(
            os.path.join(out_base, "**/*.jsc"), recursive=True)
        if so and jsc:
            self.run_bash(f"'{self.main_win.binaries['rv']}' --decrypt --bruteforce -w '{so[0]}' '{jsc[0]}'")
        else:
            self.log_signal.emit("[ERR] Assets not found.", "#f44336"); self.finished_signal.emit(False)


class Step6_Decrypt(PipelineStep):
    def run(self, base_path):
        key = self.main_win.key_input.text().strip()
        self.log_signal.emit(f"\n--- STEP 6: Global Decryption ---", "#00BCD4")
        self.run_bash(f"find . -name '*.jsc' -exec '{self.main_win.binaries['rv']}' --decrypt -w --key '{key}' {{}} \;",
                      cwd=base_path)


class Step7_Prettier(PipelineStep):
    def run(self, base_path):
        self.log_signal.emit(f"\n--- STEP 7: Global Prettier Cleanup ---", "#8BC34A")
        self.run_bash(f"find . -name '*.js' -exec '{self.main_win.binaries['pt']}' -w {{}} \;", cwd=base_path)


# --- MAIN WINDOW ---
class CocosDecompiler(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cocos Decryptor Ultimate Pro")
        self.is_status_active = False
        self.binaries = {"at": "", "rv": "", "pt": ""}
        self.init_ui()
        self.init_pipeline()
        self.load_global_settings()
        self.showMaximized()

    def init_ui(self):
        widget = QWidget();
        self.setCentralWidget(widget)
        layout = QVBoxLayout(widget);
        layout.setSpacing(5);
        layout.setContentsMargins(15, 15, 15, 15)

        h_top = QHBoxLayout()
        self.btn_settings = QPushButton("⚙ Settings")
        self.btn_settings.setFixedWidth(120)
        self.btn_settings.clicked.connect(self.open_settings)
        h_top.addWidget(self.btn_settings);
        h_top.addStretch();
        layout.addLayout(h_top)

        self.zip_path = self.add_row(layout, "Zip Container:", "*.zip")
        self.output_path = self.add_row(layout, "Output Folder:", is_folder=True)

        h_key = QHBoxLayout();
        h_key.addWidget(QLabel("Decryption Key:"), 1)
        self.key_input = QLineEdit()
        h_key.addWidget(self.key_input, 5);
        layout.addLayout(h_key)

        self.btn_start = QPushButton("Decrypt Cocoa's")
        self.btn_start.setFixedHeight(50);
        self.btn_start.setStyleSheet("background-color: #d32f2f; color: white; font-weight: bold; font-size: 14px;")
        self.btn_start.clicked.connect(self.start_full_process);
        layout.addWidget(self.btn_start)

        self.console = QTextBrowser();
        self.console.setReadOnly(True)
        self.console.setOpenLinks(False);
        self.console.anchorClicked.connect(self.open_file_in_finder)
        self.console.setStyleSheet("background-color: #1e1e1e; color: #d4d4d4; font-family: 'Courier';")
        layout.addWidget(self.console)

    def add_row(self, layout, label, filt="*.*", is_folder=False):
        h = QHBoxLayout();
        lbl = QLabel(label);
        lbl.setFixedWidth(100);
        h.addWidget(lbl)
        le = QLineEdit();
        h.addWidget(le);
        btn = QPushButton("Browse")
        btn.clicked.connect(lambda: le.setText(QFileDialog.getExistingDirectory(self, label) if is_folder else
                                               QFileDialog.getOpenFileName(self, label, "", filt)[0]))
        h.addWidget(btn);
        layout.addLayout(h);
        return le

    def open_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec_():
            self.binaries = dlg.get_data()
            with open(CONFIG_FILE, 'w') as f: json.dump(self.binaries, f)

    def load_global_settings(self):
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f: self.binaries = json.load(f)

    def init_pipeline(self):
        self.s0 = Step0_Unzip(self);
        self.s1 = Step1_Apktool(self);
        self.s2 = Step2_FindFiles(self);
        self.s3 = Step3_FindEncrypted(self)
        self.s4 = Step4_FindSignature(self);
        self.s5 = Step5_Bruteforce(self);
        self.s6 = Step6_Decrypt(self);
        self.s7 = Step7_Prettier(self)
        for s in [self.s0, self.s1, self.s2, self.s3, self.s4, self.s5, self.s6, self.s7]: s.log_signal.connect(
            self.log)
        self.s0.finished_signal.connect(lambda ok: self.s1.run() if ok else None)
        self.s1.finished_signal.connect(self.begin_scan_loop)
        self.s2.finished_signal.connect(lambda: self.s3.run(self.current_folder))
        self.s3.finished_signal.connect(lambda: self.s4.run(self.current_folder))
        self.s4.finished_signal.connect(self.next_scan_folder)
        self.s5.finished_signal.connect(lambda ok: self.s6.run(self.output_path.text()) if ok else None)
        self.s6.finished_signal.connect(lambda ok: self.s7.run(self.output_path.text()) if ok else None)
        self.s7.finished_signal.connect(self.finalize_pipeline)

    def start_full_process(self):
        self.console.clear(); self.key_input.setText(""); self.s0.run()

    def finalize_pipeline(self):
        self.log("\n--- DECRYPTION PROCESS COMPLETE ---", "#00FF00")
        self.log("Decrypted Files (Click to reveal in Finder):", "#FFFFFF")

        files = glob.glob(os.path.join(self.output_path.text(), "**/*.js"), recursive=True)
        for f in sorted(files): self.log_link(f)

        # Display key as the very last line
        final_key = self.key_input.text().strip()
        self.log(f"\nFinal Decryption Key: <b>{final_key}</b>", "#4CAF50")

        QTimer.singleShot(500, self.flash_key_field)

    def open_file_in_finder(self, url):
        p = url.toLocalFile()
        if os.path.exists(p): os.system(f"open -R '{p}'")

    def log_link(self, path):
        u = QUrl.fromLocalFile(path).toString()
        self.console.insertHtml(f"<br><a href='{u}' style='color: #2196F3;'>{path}</a>")
        self.scroll_to_bottom()

    def flash_key_field(self):
        s = self.key_input.styleSheet()
        self.key_input.setStyleSheet("background-color: #FFEB3B; color: black; border: 2px solid #D32F2F;")
        QTimer.singleShot(1500, lambda: self.key_input.setStyleSheet(s))

    def begin_scan_loop(self):
        p = self.output_path.text()
        self.folders = [os.path.join(p, d) for d in os.listdir(p) if os.path.isdir(os.path.join(p, d))]
        self.idx = 0;
        self.next_scan_folder()

    def next_scan_folder(self):
        if self.idx < len(self.folders):
            self.current_folder = self.folders[self.idx];
            self.idx += 1
            self.log(f"\n--- SCANNING: {os.path.basename(self.current_folder)} ---", "#FFFFFF");
            self.s2.run(self.current_folder)
        else:
            self.s5.run()

    def update_status_line(self, m, color="#d4d4d4"):
        cursor = self.console.textCursor();
        cursor.movePosition(QTextCursor.End)
        if self.is_status_active:
            cursor.movePosition(QTextCursor.StartOfBlock, QTextCursor.KeepAnchor);
            cursor.removeSelectedText()
        else:
            cursor.insertBlock(); self.is_status_active = True
        cursor.insertHtml(f"<span style='color: {color};'>{m}</span>")
        self.console.setTextCursor(cursor)
        self.scroll_to_bottom()

    def log(self, m, color="#d4d4d4"):
        if self.is_status_active and "Trying key" not in m: self.is_status_active = False
        m_html = m.replace("\n", "<br>")
        self.console.append(f"<span style='color: {color};'>{m_html}</span>")
        self.scroll_to_bottom()

    def scroll_to_bottom(self):
        self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())


if __name__ == "__main__":
    app = QApplication(sys.argv);
    win = CocosDecompiler();
    win.show();
    sys.exit(app.exec_())