# BSTI
# version: 0.1
# Authors: Connor Fancy

import sys
import os
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QDialogButtonBox, QTableWidget, QTableWidgetItem, QCheckBox, QLabel, QAction, QTabBar, QStyle, QPlainTextEdit, QMainWindow, QGridLayout, QHBoxLayout, QTabWidget, QTextEdit, QPushButton, QVBoxLayout, QWidget, QFileDialog, QLabel, QDialog, QLineEdit, QFormLayout, QMessageBox, QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal, QUrl, QRegExp, Qt, QProcess
from PyQt5.QtGui import QTextCursor, QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QDesktopServices
from PyQt5.QtWebEngineWidgets import QWebEngineView
import paramiko
from scp import SCPClient
import tempfile
import json
import datetime
import subprocess
from htmlwebshot import WebShot, Config
import html
import re

# TODO 
"""
organize code :(
Integration with n2p tabs/menu bar --> main execution is done, need to figure out report gen and plugin manager
home page diagnostics
parser for csv built-in
metadata for modules to map to nessus findings, then convert to md5 when saving the screenshot
setup project folder per session

# Done
open NMB json for editing
render html, csv results from NMB/interpreter 
temp file creating when module is edited, that is executed for temp changes
Integration with nmb 
rework NMB to not prompt user for interactive input (csv and txt files)
fix underscore description requirement
create readme and dev guide
file transfer metadata 
screenshots of logs
improve homepage for links
make ui more clean and readable
prevent module editor or home from closing 
json payloads for multi windows
logging all output into session log logs/session_identifier/BSTI.log
allow for arguments in modules 
parse arguments and prompt user based on how many
create module file
terminal rework
"""

closeButtonStyle = """
    QPushButton {
        border: none;
        padding: 4px;
        border-radius: 2px;
        background-color: transparent;
    }
    QPushButton:hover {
        background-color: lightgrey;
    }
    QPushButton:pressed {
        background-color: grey;
    }
""" # Eventually move this - temp

DRACULA_STYLESHEET = """
    QMainWindow {
        background-color: #282a36;
    }
    QLabel, QPushButton, QComboBox, QLineEdit {
        font-size: 11pt;
        color: #f8f8f2;
        font-family: 'Arial';
    }
    QPushButton {
        min-height: 30px;
        background-color: #44475a;
        border: none;
        border-radius: 5px;
        padding: 5px 10px;
    }
    QPushButton#ExecuteNMBButton {  /* Style for Execute NMB button */
        background-color: #50fa7b;  /* Green color, but not too bright */
        color: #282a36;  /* Dark text for contrast */
        border: 1px solid #6272a4;  /* Border color from the theme */
    }

    QPushButton#ExecuteNMBButton:hover {  /* Hover effect */
        background-color: #5af78e;  /* Slightly lighter green */
        border-color: #50fa7b;  /* Border color changes on hover */
    }

    QPushButton#ExecuteNMBButton:pressed {  /* Pressed effect */
        background-color: #3f8c57;  /* Darker shade of green */
        border-color: #6272a4;  /* Keeping border consistent with theme */
    }
    QPushButton#CardButton {
        font-size: 12pt;  /* Larger font size */
        color: #f8f8f2;  /* Light text */
        background-color: #6272a4;  /* Card background */
        border-radius: 8px;  /* Rounded corners */
        padding: 15px;  /* Inner padding */
        text-align: left;
        border: none;
    }
    
    QPlainTextEdit {
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 11pt;
        color: #f8f8f2;
        background-color: #282a36;
        border: 1px solid #6272a4;
    }

    QPushButton#CardButton:hover {
        background-color: #50fa7b;  /* Change color on hover */
    }
    QPushButton:hover {
        background-color: #6272a4;
    }
    QPushButton:pressed {
        background-color: #50fa7b;
    }
    QTextEdit {
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 12pt;
        color: #f8f8f2;
        background-color: #44475a;
        padding: 5px;
        border: 1px solid #6272a4;
    }
    QTabWidget::pane {
        border-top: 2px solid #44475a;
    }
    QTabWidget::tab-bar {
        alignment: center;
    }
    QTabBar::tab {
        background: #6272a4;
        color: #f8f8f2;
        padding: 15px;
        margin: 5px;
        border-radius: 3px;
    }
    QTabBar::tab:selected {
        background: #50fa7b;
        color: #282a36;
    }
    QTabBar::tab:!selected:hover {
        background: #bd93f9;
    }
    QLineEdit {
        background-color: #44475a;
        border-radius: 5px;
        padding: 5px;
        border: 1px solid #6272a4;
    }
    QComboBox {
        min-height: 25px;
        background-color: #44475a;
        border-radius: 5px;
        padding: 5px;
        border: 1px solid #6272a4;
    }
    QComboBox::drop-down {
        border: none;
    }
    QComboBox::down-arrow {
        image: url(dropdown-arrow.png);
    }
    QDialog {
        background-color: #282a36;
    }
    QScrollBar:vertical {
        border: 1px solid #44475a;
        background: #282a36;
        width: 12px;
        margin: 0px 0px 0px 0px;
    }
    QScrollBar::handle:vertical {
        background: #6272a4;
        min-height: 20px;
    }
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        border: 0px solid grey;
        background: #44475a;
        height: 0px;
        subcontrol-position: top;
        subcontrol-origin: margin;
    }
    QStatusBar {
        font-size: 10pt;
        color: #f8f8f2;
        background-color: #44475a;
        padding: 3px;
    }

    QPushButton#DeleteLogsButton {  /* Style for delete logs button */
        background-color: #ff5555;  /* Red color */
        border: 1px solid #ff0000;  /* Slightly darker border */
    }
    QPushButton#DeleteLogsButton:hover {  /* Hover effect */
        background-color: #ff6e67;
    }
    QPushButton#DeleteLogsButton:pressed {  /* Pressed effect */
        background-color: #ff0000;
    }
"""

class CommandLineArgsDialog(QDialog):
    def __init__(self, script_path, host, username, password, parent=None, ):
        super().__init__(parent)
        self.host = host
        self.username = username
        self.password = password

        self.setWindowTitle('Enter Command-Line Arguments')

        layout = QVBoxLayout(self)

        # Parse the script for arguments and file requirements
        self.args_metadata, self.file_metadata = self.parse_script_for_args(script_path)
        self.arg_inputs = {}

        # Add argument fields
        for arg, desc in self.args_metadata.items():
            layout.addWidget(QLabel(f"{arg} - {desc}"))
            arg_input = QLineEdit(self)
            self.arg_inputs[arg] = arg_input
            layout.addWidget(arg_input)

        # Add file browsing fields
        self.file_inputs = {}
        for file_arg, desc in self.file_metadata.items():
            layout.addWidget(QLabel(f"{file_arg} - {desc}"))
            file_input_layout = QHBoxLayout()
            file_input = QLineEdit(self)
            self.file_inputs[file_arg] = file_input
            file_input_layout.addWidget(file_input)
            browse_button = QPushButton('Browse', self)
            browse_button.clicked.connect(lambda _, arg=file_arg: self.browse_file(arg))
            file_input_layout.addWidget(browse_button)
            layout.addLayout(file_input_layout)

        self.submit_button = QPushButton('Submit', self)
        self.submit_button.setCursor(Qt.PointingHandCursor)
        # self.submit_button.clicked.connect(self.accept)
        self.submit_button.clicked.connect(self.on_submit)
        layout.addWidget(self.submit_button)

    def browse_file(self, arg):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.file_inputs[arg].setText(file_path)

    def get_arguments(self):
        args_str = ' '.join(input.text().strip() for input in self.arg_inputs.values())
        file_paths = {arg: input.text().strip() for arg, input in self.file_inputs.items()}

        return args_str, file_paths

    
    def on_submit(self):
        # Retrieve the arguments and file paths as a tuple
        args_str, file_paths = self.get_arguments()
        success = True

        # Handle file uploads
        for file_arg, local_path in file_paths.items():
            if local_path:
                remote_path = f"/tmp/{file_arg}"
                if not self.upload_file_to_remote(local_path, remote_path):
                    success = False
                    break

        if success:
            self.accept()


    def convert_line_endings(self, local_path):
        """Convert Windows line endings to Unix/Linux line endings."""
        with open(local_path, 'r') as file:
            content = file.read()
        return content.replace('\r\n', '\n')

    
    def upload_file_to_remote(self, local_path, remote_path):
        try:
            # Convert line endings
            converted_content = self.convert_line_endings(local_path)

            # Create a temporary file
            with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp_file:
                tmp_file.write(converted_content)
                tmp_file_path = tmp_file.name

            # Upload the temporary file
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.host, username=self.username, password=self.password)

                with ssh.open_sftp() as sftp:
                    sftp.put(tmp_file_path, remote_path)

            # Clean up the temporary file
            os.remove(tmp_file_path)

            return True
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error uploading file: {e}")
            return False


    @staticmethod
    def parse_script_for_args(script_path):
        args_metadata = {}
        file_metadata = {}
        try:
            with open(script_path, 'r') as script_file:
                parse_args, parse_files = False, False
                for line in script_file:
                    if line.startswith("#!"):
                        continue  # Skip shebang line
                    if line.strip() == '# ARGS':
                        parse_args = True
                        continue
                    if line.strip() == '# STARTFILES':
                        parse_files = True
                        continue
                    if line.strip() == '# ENDFILES':
                        parse_files = False
                        continue
                    if line.strip() == '# ENDARGS':
                        parse_args = False
                        continue
                    if parse_args and line.startswith('#'):
                        parts = line[1:].strip().split(" ", 1)
                        if len(parts) == 2:
                            arg, desc = parts
                            args_metadata[arg] = desc.strip('"')
                    elif parse_files and line.startswith('#'):
                        parts = line[1:].strip().split(" ", 1)
                        if len(parts) == 2:
                            file_arg, desc = parts
                            file_metadata[file_arg] = desc.strip('"')
        except Exception as e:
            QMessageBox.warning(None, "Error", f"Error reading script: {e}")
        return args_metadata, file_metadata

    
    def has_arguments(self):
        return bool(self.args_metadata) or bool(self.file_metadata)

CONFIG_DIR = ".config"
CONFIG_FILE = os.path.join(CONFIG_DIR, "drones.json")

def save_config(drones):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, 'w') as file:
        json.dump(drones, file, indent=4)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as file:
            return json.load(file)
    return {}

class WaitingDialog(QDialog):
    def __init__(self, message, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Please Wait")
        self.setModal(True)

        layout = QVBoxLayout(self)
        label = QLabel(message, self)
        layout.addWidget(label)

class PythonSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#ff79c6"))  # Pink color for keywords
        keywords = ["def", "class", "import", "from", "as", "if", "elif", "else", "while", "for", "try", "except", "with"]

        self.highlighting_rules = [(r'\b' + keyword + r'\b', keyword_format) for keyword in keywords]

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)
                
class JsonSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)

        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#f1fa8c"))

        number_format = QTextCharFormat()
        number_format.setForeground(QColor("#bd93f9"))

        boolean_format = QTextCharFormat()
        boolean_format.setForeground(QColor("#ffb86c"))

        self.highlighting_rules = [
            (r'"[^"\\]*(\\.[^"\\]*)*"', string_format),
            (r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b', number_format),
            (r'\b(true|false)\b', boolean_format)
        ]

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)
        self.setCurrentBlockState(0)


class BashSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#ff79c6"))
        keywords = ["if", "then", "else", "fi", "for", "while", "do", "done", "echo", "exit"]

        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6272a4"))
        comment_format.setFontItalic(True)

        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#f1fa8c"))

        self.highlighting_rules = [(r'\b' + keyword + r'\b', keyword_format) for keyword in keywords]
        self.highlighting_rules += [
            (r'#.*', comment_format),
            (r'".*?"', string_format),
            (r"'.*?'", string_format)
        ]

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            expression = QRegExp(pattern)
            index = expression.indexIn(text)
            while index >= 0:
                length = expression.matchedLength()
                self.setFormat(index, length, format)
                index = expression.indexIn(text, index + length)
        self.setCurrentBlockState(0)

class DroneConfigDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Configure Drone')

        self.layout = QFormLayout(self)

        self.host_input = QLineEdit(self)
        self.username_input = QLineEdit(self)
        self.password_input = QLineEdit(self)

        self.layout.addRow('Host:', self.host_input)
        self.layout.addRow('Username:', self.username_input)
        self.layout.addRow('Password:', self.password_input)

        self.submit_button = QPushButton('Save', self)
        self.submit_button.setCursor(Qt.PointingHandCursor)
        self.submit_button.clicked.connect(self.accept)
        self.layout.addRow(self.submit_button)

    def get_details(self):
        return self.host_input.text(), self.username_input.text(), self.password_input.text()

class SSHThread(QThread):
    update_output = pyqtSignal(str)

    def __init__(self, host, username, password, full_command, is_script_path=True):
        super().__init__()
        self.host = host
        self.username = username
        self.password = password
        self.full_command = full_command
        self.is_script_path = is_script_path
        self.ssh = None
        self.running = False
            
    def convert_line_endings(self, local_path):
        """Convert Windows line endings to Unix/Linux line endings."""
        with open(local_path, 'r') as file:
            content = file.read()
        return content.replace('\r\n', '\n')
    
    def transfer_script(self, local_path):
        """Transfers the script to the remote machine after converting line endings."""
        script_content = self.convert_line_endings(local_path)
        filename = os.path.basename(local_path)
        remote_path = f"/tmp/{filename}"

        with self.ssh.open_sftp() as sftp:
            with sftp.file(remote_path, 'w') as remote_file:
                remote_file.write(script_content)
        
        self.ssh.exec_command(f"chmod +x {remote_path}")
        return remote_path

    def run(self):
        self.running = True
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.ssh.connect(self.host, username=self.username, password=self.password)

            if self.is_script_path:
                script_path = self.full_command[0].split()[0] 
                command_args = ' '.join(self.full_command[0].split()[1:])
                remote_script_path = self.transfer_script(script_path)
                
                # Construct the full command python & bash
                command_to_run = f"{remote_script_path} {command_args}"
            else:
                # Json payloads
                command_to_run = self.full_command
            stdin, stdout, stderr = self.ssh.exec_command(command_to_run, get_pty=True)
            
            while self.running:
                if stdout.channel.recv_ready():
                    output = stdout.channel.recv(4096).decode('utf-8')
                    self.update_output.emit(output)

                if stderr.channel.recv_stderr_ready():
                    output = stderr.channel.recv_stderr(4096).decode('utf-8')
                    self.update_output.emit(output)

                self.msleep(100)  # Sleep for a short time to avoid bricking cpu :)

        except Exception as e:
            self.update_output.emit(f"SSH Connection Error: {str(e)}")
        finally:
            if self.ssh:
                self.ssh.close()


    def stop(self):
        self.running = False
        if self.ssh:
            try:
                if self.pid:
                    kill_command = f"kill {self.pid}"
                    self.ssh.exec_command(kill_command)
            except Exception as e:
                pass
            finally:
                self.ssh.close()

class SearchableComboBox(QComboBox):
    def __init__(self, parent=None):
        super(SearchableComboBox, self).__init__(parent)
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.NoInsert)
        self.completer().setCompletionMode(QComboBox.PopupCompletion)
        self.filterString = ""
        self.items = []

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Backspace:
            self.filterString = self.filterString[:-1]
        else:
            self.filterString += event.text()

        self.updateFilter()

        super(SearchableComboBox, self).keyPressEvent(event)

    def updateFilter(self):
        self.clear()
        for item in self.items:
            if self.filterString.lower() in item.lower():
                self.addItem(item)

    def populateItems(self, items):
        self.items = items
        self.updateFilter()

class TmuxSessionDialog(QDialog):
    def __init__(self, sessions, parent=None):
        super(TmuxSessionDialog, self).__init__(parent)
        self.setWindowTitle("Select Tmux Session")
        self.selected_session = None
        self.sessions = sessions

        layout = QVBoxLayout(self)

        # Label
        layout.addWidget(QLabel("Select a tmux session:"))

        # Combo box for tmux sessions
        self.session_combo = QComboBox(self)
        self.session_combo.addItems(sessions)
        layout.addWidget(self.session_combo)

        # Submit button
        self.submit_button = QPushButton("Connect", self)
        self.submit_button.setCursor(Qt.PointingHandCursor)
        self.submit_button.clicked.connect(self.on_submit)
        layout.addWidget(self.submit_button)

    def on_submit(self):
        self.selected_session = self.session_combo.currentText()
        self.accept()

    def get_selected_session(self):
        self.exec_()
        return self.selected_session

class NMBRunnerThread(QThread):
    output_signal = pyqtSignal(str)

    def __init__(self, command):
        super().__init__()
        self.command = command

    def run(self):
        process = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                self.output_signal.emit(output.strip())

class N2PArgsDialog(QDialog):
    def __init__(self, parent=None):
        super(N2PArgsDialog, self).__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setSpacing(10)
        self.layout.setContentsMargins(10, 10, 10, 10)

        # Create widgets for each argument
        self.username_edit = QLineEdit(self)
        self.password_edit = QLineEdit(self)
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.client_id_edit = QLineEdit(self)
        self.report_id_edit = QLineEdit(self)
        self.scope_edit = QComboBox(self)
        self.scope_edit.addItems(["", "internal", "external"])

        # Directory field with Browse button
        self.directory_layout = QHBoxLayout()
        self.directory_edit = QLineEdit(self)
        self.directory_browse_button = QPushButton("Browse")
        self.directory_browse_button.clicked.connect(self.browse_directory)
        self.directory_layout.addWidget(self.directory_edit)
        self.directory_layout.addWidget(self.directory_browse_button)

        # Screenshot Directory field with Browse button
        self.screenshot_dir_layout = QHBoxLayout()
        self.screenshot_dir_edit = QLineEdit(self)
        self.screenshot_dir_browse_button = QPushButton("Browse")
        self.screenshot_dir_browse_button.clicked.connect(self.browse_screenshot_directory)
        self.screenshot_dir_layout.addWidget(self.screenshot_dir_edit)
        self.screenshot_dir_layout.addWidget(self.screenshot_dir_browse_button)

        self.target_plextrac_edit = QComboBox(self)
        self.target_plextrac_edit.addItems(["report"])
        self.non_core_check = QCheckBox("Non-core custom fields", self)

        # Add widgets to the layout
        self.layout.addWidget(QLabel("Username"))
        self.layout.addWidget(self.username_edit)
        self.layout.addWidget(QLabel("Password"))
        self.layout.addWidget(self.password_edit)
        self.layout.addWidget(QLabel("Client ID"))
        self.layout.addWidget(self.client_id_edit)
        self.layout.addWidget(QLabel("Report ID"))
        self.layout.addWidget(self.report_id_edit)
        self.layout.addWidget(QLabel("Scope"))
        self.layout.addWidget(self.scope_edit)
        self.layout.addWidget(QLabel("Evidence Directory"))
        self.layout.addLayout(self.directory_layout)
        self.layout.addWidget(QLabel("Screenshot Directory"))
        self.layout.addLayout(self.screenshot_dir_layout)
        self.layout.addWidget(QLabel("Target Plextrac"))
        self.layout.addWidget(self.target_plextrac_edit)
        self.layout.addWidget(self.non_core_check)

        # Add a button box
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        self.layout.addWidget(button_box)

        self.apply_custom_styles()

    def apply_custom_styles(self):
        self.setStyleSheet("""
        QDialog {
            background-color: #282a36;
            border-radius: 8px;
        }
        QLabel {
            color: #f8f8f2;
        }
        QLineEdit, QComboBox, QPushButton, QCheckBox {
            background-color: #44475a;
            border-radius: 5px;
            padding: 5px;
            border: 1px solid #6272a4;
            color: #f8f8f2;
        }
        QLineEdit {
            padding-left: 10px;
        }
        QPushButton {
            min-height: 30px;
            border: none;
        }
        QPushButton:hover {
            background-color: #6272a4;
        }
        QPushButton:pressed {
            background-color: #50fa7b;
        }
        QDialogButtonBox {
            button-layout: 2;
        }
        """)


    def browse_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.directory_edit.setText(directory)

    def browse_screenshot_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Screenshot Directory")
        if directory:
            self.screenshot_dir_edit.setText(directory)


    def get_arguments(self):
        # Return the entered arguments
        return {
            'username': self.username_edit.text(),
            'password': self.password_edit.text(),
            'clientID': self.client_id_edit.text(),
            'reportID': self.report_id_edit.text(),
            'scope': self.scope_edit.currentText(),
            'directory': self.directory_edit.text(),
            'targettedplextrac': self.target_plextrac_edit.currentText(),
            'screenshot_dir': self.screenshot_dir_edit.text(),
            'noncore': self.non_core_check.isChecked(),
        }

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_module_path = None
        self.temp_file = None
        self.setWindowTitle("Bulletproof Solutions Testing Interface")
        self.setGeometry(100, 100, 800, 600)
        self.threads = []

        self.layout = QVBoxLayout()
        self.central_widget = QWidget()
        self.central_widget.setLayout(self.layout)
        self.setCentralWidget(self.central_widget)

        self.tab_widget = QTabWidget(self)
        self.layout.addWidget(self.tab_widget)

        self.tab_widget.tabCloseRequested.connect(self.close_tab)

        # Menu Bar Init
        self.menu_bar = self.menuBar()

        self.file_menu = self.menu_bar.addMenu("File")
        self.open_file_action = QAction("Open File", self)
        self.open_file_action.triggered.connect(self.open_file)
        self.file_menu.addAction(self.open_file_action)


        self.drone_menu = self.menu_bar.addMenu("Config")
        self.module_menu = self.menu_bar.addMenu("Modules")
        self.terminal_menu = self.menu_bar.addMenu("Terminal")

        # Module menu bar
        self.configure_module_action = QAction("Create New", self)
        self.configure_module_action.triggered.connect(self.create_module)
        self.module_menu.addAction(self.configure_module_action)

        # Terminal menu bar 
        self.configure_terminal_action = QAction("Open Terminal", self)
        self.configure_terminal_action.triggered.connect(self.open_terminal_ssh)
        self.terminal_menu.addAction(self.configure_terminal_action)

        # Configure Drone Action
        self.configure_drone_action = QAction("Configure New BSTG", self)
        self.configure_drone_action.triggered.connect(self.configure_drone)  
        self.drone_menu.addAction(self.configure_drone_action)

        # Add an action for SSH key configuration
        self.configure_ssh_key_action = QAction("Add SSH Key", self)
        self.configure_ssh_key_action.triggered.connect(self.add_ssh_key)
        self.drone_menu.addAction(self.configure_ssh_key_action)

        # Tmux session attach
        self.connect_tmux_action = QAction("Connect to Tmux Session", self)
        self.connect_tmux_action.triggered.connect(self.on_connect_tmux_triggered)
        self.terminal_menu.addAction(self.connect_tmux_action)

        # Reporting menu - n2p
        self.report_menu = self.menu_bar.addMenu("Reports")
        self.create_report_action = QAction("Create Report", self)
        self.create_report_action.triggered.connect(self.create_report)
        self.report_menu.addAction(self.create_report_action)

        self.report_findings_action = QAction("Report Findings", self)
        self.report_findings_action.triggered.connect(self.report_findings_execution)
        self.report_menu.addAction(self.report_findings_action)


        # Drone selection layout
        self.droneSelectionLayout = QHBoxLayout()
        self.drone_selector = QComboBox(self)
        self.drone_search = QLineEdit(self)
        self.drone_search.setPlaceholderText("Filter BSTG...")
        self.drone_search.textChanged.connect(self.filter_drones)
        self.droneSelectionLayout.addWidget(self.drone_selector)
        self.droneSelectionLayout.addWidget(self.drone_search)
        self.layout.addLayout(self.droneSelectionLayout)

        # Load and populate drones after drone_selector is created
        self.drones = load_config()
        self.populate_drones()

        # Module editor
        self.module_editor_tab = QWidget()
        self.module_editor_layout = QVBoxLayout(self.module_editor_tab)
        self.module_editor = QPlainTextEdit()
        self.module_editor.textChanged.connect(self.handle_module_edit)
        self.module_editor_layout.addWidget(self.module_editor)
        self.save_button = QPushButton("Save Module")
        self.save_button.setCursor(Qt.PointingHandCursor)
        self.save_button.clicked.connect(self.save_module)
        self.module_editor_layout.addWidget(self.save_button)
        self.tab_widget.addTab(self.module_editor_tab, "Module Editor")

        # File Transfer Tab
        self.file_transfer_tab = QWidget()
        self.file_transfer_layout = QVBoxLayout(self.file_transfer_tab)

        # Upload section
        self.upload_layout = QHBoxLayout()
        self.upload_file_label = QLabel("Upload File:")
        self.upload_file_path = QLineEdit()
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_file)
        self.upload_to_label = QLabel("To:")
        self.upload_remote_path = QLineEdit("/path/on/drone")
        self.upload_button = QPushButton("Upload")
        self.upload_button.clicked.connect(self.upload_file)
        self.upload_layout.addWidget(self.upload_file_label)
        self.upload_layout.addWidget(self.upload_file_path)
        self.upload_layout.addWidget(self.browse_button)
        self.upload_layout.addWidget(self.upload_to_label)
        self.upload_layout.addWidget(self.upload_remote_path)
        self.upload_layout.addWidget(self.upload_button)

        self.file_transfer_layout.addLayout(self.upload_layout)

        # Download section
        self.download_layout = QHBoxLayout()
        self.download_file_label = QLabel("Download File:")
        self.download_file_path = QLineEdit("/path/on/drone")
        self.download_to_label = QLabel("To:")
        self.download_local_path = QLineEdit()
        self.download_browse_button = QPushButton("Browse")
        self.download_browse_button.clicked.connect(self.browse_save_location)
        self.download_button = QPushButton("Download")
        self.download_button.clicked.connect(self.download_file)
        self.download_layout.addWidget(self.download_file_label)
        self.download_layout.addWidget(self.download_file_path)
        self.download_layout.addWidget(self.download_to_label)
        self.download_layout.addWidget(self.download_local_path)
        self.download_layout.addWidget(self.download_browse_button)
        self.download_layout.addWidget(self.download_button)

        self.file_transfer_layout.addLayout(self.download_layout)

        # Add the file transfer tab to the tab widget
        self.tab_widget.addTab(self.file_transfer_tab, "File Transfer")

        # Module selection layout
        self.moduleSelectionLayout = QHBoxLayout()
        self.module_label = QLabel("Choose a module to run:")
        self.moduleSelectionLayout.addWidget(self.module_label)

        self.moduleComboBox = QComboBox(self)
        self.populate_module_combobox() # Refresh modules
        self.moduleComboBox.currentIndexChanged.connect(self.module_selected)

        self.module_search = QLineEdit(self)
        self.module_search.setPlaceholderText("Filter modules...")
        self.module_search.textChanged.connect(self.filter_modules)

        self.moduleSelectionLayout.addWidget(self.moduleComboBox)
        self.moduleSelectionLayout.addWidget(self.module_search)

        self.module_button = QPushButton("Execute Module", self)
        self.module_button.setCursor(Qt.PointingHandCursor)
        self.module_button.clicked.connect(self.execute_module)
        self.moduleSelectionLayout.addWidget(self.module_button)

        self.layout.addLayout(self.moduleSelectionLayout)

        # View Logs Tab
        self.logs_tab = QWidget()
        self.logs_layout = QVBoxLayout(self.logs_tab)

        # Refresh Button
        self.refresh_logs_button = QPushButton("Refresh Logs")
        self.refresh_logs_button.setCursor(Qt.PointingHandCursor)
        self.refresh_logs_button.clicked.connect(self.populate_log_sessions_list)
        self.logs_layout.addWidget(self.refresh_logs_button)

        self.log_sessions_combo = QComboBox()
        self.logs_layout.addWidget(self.log_sessions_combo)
        self.log_sessions_combo.currentIndexChanged.connect(self.load_log_content)

        self.log_content_area = QTextEdit()
        self.log_content_area.setReadOnly(True)
        self.logs_layout.addWidget(self.log_content_area)

        self.tab_widget.addTab(self.logs_tab, "View Logs")
        self.populate_log_sessions_list()

        self.screenshot_button = QPushButton("Take Screenshot of Log")
        self.screenshot_button.setCursor(Qt.PointingHandCursor)
        self.screenshot_button.clicked.connect(self.gather_screenshots)
        self.logs_layout.addWidget(self.screenshot_button)

        # Delete Logs Button
        self.delete_logs_button = QPushButton("Delete Logs")
        self.delete_logs_button.setCursor(Qt.PointingHandCursor)
        self.delete_logs_button.setObjectName("DeleteLogsButton")
        self.delete_logs_button.clicked.connect(self.delete_logs)
        self.logs_layout.addWidget(self.delete_logs_button)

        # Home tab
        self.home_tab = QWidget()
        self.home_layout = QGridLayout(self.home_tab)
        self.add_home_cards()
        self.tab_widget.insertTab(0, self.home_tab, "Home")

        # Add NMB tab
        self.setup_nmb_tab()

        # hide/show tabs based on active tab
        self.tab_widget.currentChanged.connect(self.on_tab_changed)


    def create_report(self):
        self.execute_script_in_tab("create_report_script.py", "Create Report")

    def report_findings_execution(self):
        # Open the dialog to get arguments
        args_dialog = N2PArgsDialog(self)
        if args_dialog.exec_() == QDialog.Accepted:
            args = args_dialog.get_arguments()

            # Prepare the command
            command = ["python", "n2p_ng.py"]
            for arg, value in args.items():
                if arg != 'noncore' and value:
                    command.extend([f"--{arg}", value])

            # Check and append the --noncore argument separately since its the only unique one
            if args['noncore']:
                command.append('--noncore')

            # Execute in a new tab
            self.execute_n2p_in_tab(command, "Nessus2plextrac-ng")


    def execute_n2p_in_tab(self, command, tab_name):
        # Create a new tab
        tab = QTextEdit()
        tab.setReadOnly(True)
        tab.is_custom_tab = True

        # Execute the script
        process = QProcess(tab)
        process.setProcessChannelMode(QProcess.MergedChannels)
        process.readyReadStandardOutput.connect(lambda: self.read_process_output(process, tab))
        
        # Separate the command into the program and arguments
        program = command[0]
        arguments = command[1:]
        process.start(program, arguments)

        # Add tab to the widget
        index = self.tab_widget.addTab(tab, tab_name)

        # Add close button to the tab
        self.add_close_button_to_tab(tab, index)


    def read_process_output(self, process, text_edit):
        text_edit.append(process.readAllStandardOutput().data().decode())

    def add_close_button_to_tab(self, tab, index):
        close_button = QPushButton()
        close_button.setIcon(self.style().standardIcon(QStyle.SP_DockWidgetCloseButton))
        close_button.setStyleSheet(closeButtonStyle)
        close_button.setFixedSize(16, 16)
        close_button.setToolTip("Close Tab")
        close_button.setProperty('tab_widget', tab)
        close_button.clicked.connect(self.close_tab_from_button)
        self.tab_widget.tabBar().setTabButton(index, QTabBar.RightSide, close_button)


    def open_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Supported Files (*.csv *.json *.html);; CSV Files (*.csv);;JSON Files (*.json);;HTML Files (*.html)", options=options)
        if file_name:
            tab = QWidget()
            tab.is_custom_tab = True
            layout = QVBoxLayout(tab)

            # Check file extension and render content accordingly
            if file_name.lower().endswith('.csv'):
                # Use pandas to read CSV and display in a QTableWidget
                df = pd.read_csv(file_name)
                table = self.create_table_from_dataframe(df)
                layout.addWidget(table)
            elif file_name.lower().endswith('.json'):
                # Display JSON in a QTextEdit with pretty formatting
                with open(file_name, 'r') as file:
                    content = file.read()
                    try:
                        # Parse and pretty-print JSON
                        parsed_json = json.loads(content)
                        pretty_json = json.dumps(parsed_json, indent=4, sort_keys=True)
                    except json.JSONDecodeError:
                        # In case of JSON decode error, use original content
                        pretty_json = content

                text_edit = QTextEdit()
                text_edit.setPlainText(pretty_json)
                text_edit.setFont(QFont("Courier", 10))
                layout.addWidget(text_edit)
            elif file_name.lower().endswith('.html'):
                # Display HTML in a QWebEngineView
                web_view = QWebEngineView()
                web_view.load(QUrl.fromLocalFile(os.path.abspath(file_name)))
                layout.addWidget(web_view)

            self.tab_widget.addTab(tab, os.path.basename(file_name))
            # Add close button to the tab
            close_button = QPushButton()
            close_button.setIcon(self.style().standardIcon(QStyle.SP_DockWidgetCloseButton))
            close_button.setStyleSheet(closeButtonStyle)
            close_button.setFixedSize(16, 16)
            close_button.setToolTip("Close Tab")
            close_button.setProperty('tab_widget', tab)
            close_button.clicked.connect(self.close_tab_from_button)

            self.tab_widget.tabBar().setTabButton(self.tab_widget.indexOf(tab), QTabBar.RightSide, close_button)
        
    def create_table_from_dataframe(self, df):
        table = QTableWidget()
        table.setRowCount(df.shape[0])
        table.setColumnCount(df.shape[1])
        table.setHorizontalHeaderLabels(df.columns)

        for i, row in df.iterrows():
            for j, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                table.setItem(i, j, item)

        return table
    

    def save_module(self):
        if not self.current_module_path or not self.temp_file:
            QMessageBox.warning(self, "Error", "No module loaded.")
            return

        try:
            with open(self.current_module_path, 'w') as file, open(self.temp_file.name, 'r') as temp_file:
                file.write(temp_file.read())

            QMessageBox.information(self, "Success", "Module saved successfully.")

            # Close and delete the temporary file
            self.temp_file.close()
            os.remove(self.temp_file.name)
            self.temp_file = None

        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to save module: {e}")

   
    def load_module_into_editor(self, module_path):
        self.current_module_path = module_path
        try:
            with open(module_path, 'r') as file:
                content = file.read()

            # Create a temporary file
            self.temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w+')
            self.temp_file.write(content)
            self.temp_file.flush()

            self.module_editor.setPlainText(content)
            self.set_syntax_highlighter(module_path)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to load module: {e}")


    def handle_module_edit(self):
        self.save_to_temp_file()

    def save_to_temp_file(self):
        if hasattr(self, 'temp_file') and self.temp_file:
            try:
                self.temp_file.seek(0)
                self.temp_file.truncate()
                self.temp_file.write(self.module_editor.toPlainText())
                self.temp_file.flush()
            except Exception as e:
                print(f"Error saving to temp file: {e}")


    def setup_nmb_tab(self):
        self.argument_fields = {}
        self.nmb_tab = QWidget()
        self.nmb_layout = QVBoxLayout(self.nmb_tab)

        # Mode selection setup
        self.mode_label = QLabel("Mode:")
        self.mode_combobox = QComboBox()
        self.mode_combobox.addItems(["deploy", "external", "internal", "monitor", "export", "web", "mobsf", "immuniweb", "create", "launch", "pause", "resume", "regen"])
        self.nmb_layout.addWidget(self.mode_label)
        self.nmb_layout.addWidget(self.mode_combobox)

        # Initialize mode arguments mapping
        self.initialize_mode_arguments()

        # Connect mode combobox change signal
        self.mode_combobox.currentIndexChanged.connect(self.update_argument_fields)

        self.argument_layout = QFormLayout() 
        self.nmb_layout.addLayout(self.argument_layout) 
        # Execute button
        self.execute_nmb_button = QPushButton("Execute NMB")
        self.execute_nmb_button.setObjectName("ExecuteNMBButton")
        self.execute_nmb_button.clicked.connect(self.execute_nmb)
        self.nmb_layout.addWidget(self.execute_nmb_button)

        # Output area
        self.nmb_output = QTextEdit()
        self.nmb_output.setReadOnly(True)
        self.nmb_layout.addWidget(self.nmb_output)

        # Add NMB tab to the main tab widget
        self.tab_widget.addTab(self.nmb_tab, "NMB")
        self.update_argument_fields()

    def initialize_mode_arguments(self):
        self.mode_arguments = {
            "deploy": {
                "client-name": "Text",
                "targets-file": "File",
                "scope": ["core", "nc", "custom"],
                "exclude-file": "File",
                "discovery": "Checkbox",
                "guess": "Checkbox",
                "eyewitness": "Checkbox"
            },
            "create": {
                "client-name": "Text",
                "scope": ["core", "nc", "custom"],
                "exclude-file": "File",
                "targets-file": "File",
                "discovery": "Checkbox"
            },
            "launch": {
                "client-name": "Text"
            },
            "pause": {
                "client-name": "Text"
            },
            "resume": {
                "client-name": "Text"
            },
            "monitor": {
                "client-name": "Text"
            },
            "export": {
                "client-name": "Text"
            },
            "internal": {
                "csv-file": "File",
                "local": "Checkbox",
                "guess": "Checkbox",
                "eyewitness": "Checkbox"
            },
            "external": {
                "csv-file": "File",
                "local": "Checkbox",
                "guess": "Checkbox",
                "eyewitness": "Checkbox"
            },
            "web": {
                "burp-user-file": "File",
                "burp-pass-file": "File",
                "targets": "File",
                "burp-url": "Text",
                "reattach": "Checkbox"
            },
            "mobsf": {
                "mobsf-url": "Text",
                "scan-type": ["apk", "ipa"],
                "app-name": "Text"
            },
            "immuniweb": {
                "immuni-scan-type": ["apk", "ipa"],
                "immuni-app-name": "Text",
                "force": "Checkbox"
            },
            "regen": {
                # No arguments required for regen mode
            }
        }

    def update_argument_fields(self):
        selected_mode = self.mode_combobox.currentText()
        required_args = self.mode_arguments.get(selected_mode, [])

        # Clear existing fields
        self.clear_argument_fields()

        # Check if required_args is a dictionary or a list
        if isinstance(required_args, dict):
            # Handle dictionary of arguments with types
            for arg, arg_type in required_args.items():
                self.add_argument_field(arg, arg_type)
        elif isinstance(required_args, list):
            # Handle list of arguments (all considered as text input)
            for arg in required_args:
                self.add_argument_field(arg, "Text")

    def clear_argument_fields(self):
        while self.argument_layout.count():
            item = self.argument_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.argument_fields.clear()
    
    def nmb_browse_file(self, arg):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.argument_fields[arg].setText(file_path)

    def add_argument_field(self, arg, arg_type):
        label = QLabel(f"{arg.replace('_', ' ').capitalize()}:")
        if arg_type == "Text":
            input_field = QLineEdit()
            self.argument_layout.addRow(label, input_field)
        elif arg_type == "File":
            file_layout = QHBoxLayout()

            input_field = QLineEdit()
            browse_button = QPushButton("Browse")
            browse_button.clicked.connect(lambda _, a=arg: self.nmb_browse_file(a))

            file_layout.addWidget(input_field)
            file_layout.addWidget(browse_button)

            combined_widget = QWidget() 
            combined_widget.setLayout(file_layout)

            self.argument_layout.addRow(label, combined_widget) 
        elif arg_type == "Checkbox":
            input_field = QCheckBox()
            self.argument_layout.addRow(label, input_field)
        elif isinstance(arg_type, list):  # for dropdowns
            input_field = QComboBox()
            input_field.addItems(arg_type)
            self.argument_layout.addRow(label, input_field)
        else:
            return  # Unsupported type
        self.argument_fields[arg] = input_field


    def execute_nmb(self):
        host, username, password = self.get_current_drone_connection()

        # Construct command as a list of arguments
        mode = self.mode_combobox.currentText()
        command_args = ["python", "nmb.py", "-m", mode, "-u", username, "-p", password, "-d", host]

        # Add other arguments from the form
        for arg, widget in self.argument_fields.items():
            if isinstance(widget, QLineEdit):
                value = widget.text().strip()
                if value:
                    command_args.extend(["--" + arg, value])
            elif isinstance(widget, QCheckBox) and widget.isChecked():
                command_args.append("--" + arg)
            elif isinstance(widget, QComboBox):
                value = widget.currentText()
                if value:
                    command_args.extend(["--" + arg, value])

        # Clear existing output
        self.nmb_output.clear()

        # Create and start the thread
        self.nmb_thread = NMBRunnerThread(command_args)
        self.nmb_thread.output_signal.connect(self.update_output)
        self.nmb_thread.start()


    def update_output(self, text):
        self.nmb_output.append(text)


    def populate_log_sessions_list(self):
        self.log_sessions_combo.clear()
        log_dir = os.path.join("logs")
        if os.path.exists(log_dir):
            for session in sorted(os.listdir(log_dir)):
                self.log_sessions_combo.addItem(session)

    def load_log_content(self, index):
        log_dir = os.path.join("logs")
        session_name = self.log_sessions_combo.itemText(index)
        log_file_path = os.path.join(log_dir, session_name, "BSTI.log")

        if os.path.exists(log_file_path):
            with open(log_file_path, 'r') as file:
                self.log_content_area.setText(file.read())
        else:
            self.log_content_area.clear()

    def delete_logs(self):
        confirmation = QMessageBox.question(self, "Delete Logs", "Are you sure you want to delete all logs?",
                                            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if confirmation == QMessageBox.Yes:
            log_dir = os.path.join("logs")
            try:
                for session in os.listdir(log_dir):
                    session_path = os.path.join(log_dir, session)
                    for log_file in os.listdir(session_path):
                        os.remove(os.path.join(session_path, log_file))
                    os.rmdir(session_path)
                self.populate_log_sessions_list()  # Refresh the log sessions list
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to delete logs: {e}")

    def add_ssh_key(self):
        # Let the user select a drone
        drone_id = self.drone_selector.currentText()
        if not drone_id:
            QMessageBox.warning(self, "No Drone Selected", "Please select a drone first.")
            return

        # Let the user select an SSH key file
        ssh_key_path, _ = QFileDialog.getOpenFileName(self, "Select SSH Key", "", "SSH Key Files (*.pub)")
        if not ssh_key_path:
            return  # User canceled or did not select a file

        host, username, password = self.drones[drone_id]

        # Function to upload the SSH key
        def upload_ssh_key(ssh_key_path, host, username, password):
            try:
                with paramiko.SSHClient() as ssh:
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, username=username, password=password)

                    # Read the SSH public key
                    with open(ssh_key_path, 'r') as key_file:
                        ssh_key = key_file.read().strip()

                    # Upload the SSH key
                    ssh.exec_command(f"echo '{ssh_key}' >> ~/.ssh/authorized_keys")

                QMessageBox.information(self, "Success", "SSH Key added successfully.")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to add SSH Key: {str(e)}")

        # Run the upload process
        upload_ssh_key(ssh_key_path, host, username, password)

    def connect_to_tmux_session(self, session_name):
        drone_id = self.drone_selector.currentText()
        if not drone_id:
            QMessageBox.warning(self, "No Drone Selected", "Please select a drone first.")
            return

        host, username, _ = self.drones[drone_id]
        if sys.platform == "win32":
            # Windows (using PowerShell)
            command = f"start powershell ssh {username}@{host} -t 'tmux attach -t \"{session_name}\"'"
        elif sys.platform.startswith("linux") or sys.platform == "darwin":
            # Linux or macOS
            command = f"gnome-terminal -- ssh {username}@{host} -t 'tmux attach -t \"{session_name}\"'"

        try:
            subprocess.run(command, shell=True)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to open terminal: {e}")

    def on_connect_tmux_triggered(self):
        drone_id = self.drone_selector.currentText()
        if not drone_id:
            QMessageBox.warning(self, "No Drone Selected", "Please select a drone first.")
            return
        host, username, password = self.drones[drone_id]
        sessions = self.fetch_tmux_sessions(host, username, password)

        if not sessions:
            return

        # Show dialog to select a tmux session
        dialog = TmuxSessionDialog(sessions, self)
        selected_session = dialog.get_selected_session()
        
        if selected_session:
            self.connect_to_tmux_session(selected_session)

    def fetch_tmux_sessions(self, host, username, password):
        try:
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, username=username, password=password)
                stdin, stdout, stderr = ssh.exec_command("tmux list-sessions -F '#S'")
                sessions = stdout.read().decode('utf-8').strip()
                if not sessions:
                    QMessageBox.information(self, "No Tmux Sessions", "No active tmux sessions found on this BSTG.")
                    return None
                return sessions.split('\n')
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to fetch tmux sessions: {str(e)}")
            return None

    def open_terminal_ssh(self):
        drone_id = self.drone_selector.currentText()
        if not drone_id:
            QMessageBox.warning(self, "No Drone Selected", "Please select a drone first.")
            return

        host, username, password = self.get_current_drone_connection()
        if not host:
            QMessageBox.warning(self, "No Host Found", "The selected drone does not have a valid host address.")
            return
        
        if sys.platform == "win32":
            # Windows (using PowerShell)
            terminal_command = f"start powershell ssh {username}@{host}"
        elif sys.platform.startswith("linux"):
            # Linux
            terminal_command = f"gnome-terminal -- ssh {username}@{host}"
        elif sys.platform == "darwin":
            # macOS
            terminal_command = f"osascript -e 'tell application \"Terminal\" to do script \"ssh {username}@{host}\"'"
        else:
            QMessageBox.warning(self, "Unsupported Platform", "This feature is not supported on your operating system.")
            return
        try:
            subprocess.run(terminal_command, shell=True)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to open terminal: {e}")

    def create_module(self):
        modules_dir = "modules"
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getSaveFileName(self, "Create New Module", 
                                                modules_dir, "All Files (*);;Python Files (*.py);;Shell Scripts (*.sh);;JSON Files (*.json)", 
                                                options=options)
        if filename:
            # Ensure the modules directory exists
            os.makedirs(modules_dir, exist_ok=True)

            content = ""
            if filename.endswith(".py"):
                content = "#!/usr/bin/env python3\n"
                content += "# ARGS\n# ARG1 \"Example_description_with_underscores\"\n# ENDARGS\n# AUTHOR: \n\n"
            elif filename.endswith(".sh"):
                content = "#!/bin/bash\n"
                content += "# ARGS\n# ARG1 \"Example_description_with_underscores\"\n# ENDARGS\n# AUTHOR: \n\n"
            elif filename.endswith(".json"):
                content = json.dumps({
                    "grouped": True,
                    "tabs": [
                        {"name": "Window_name_1", "command": "echo 'test'"},
                        {"name": "Window 1", "command": "echo 'Tab 1' && sleep 3600"},
                        {"name": "Window 3", "command": "echo 'Tab 2' && sleep 3600"}
                    ]
                }, indent=4)

            # Create a new file with the initial content
            with open(filename, 'w') as file:
                file.write(content)

            # Refresh module list and load the new module into the module editor
            self.moduleComboBox.clear()
            self.populate_module_combobox()
            index = self.moduleComboBox.findText(os.path.basename(filename))
            if index >= 0:
                self.moduleComboBox.setCurrentIndex(index)


    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if file_path:
            self.upload_file_path.setText(file_path)

    def browse_save_location(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.download_local_path.setText(directory)

    def is_valid_remote_path(self, host, username, password, path):
        try:
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, username=username, password=password)

                # Command to check if the path is a directory
                stdin, stdout, stderr = ssh.exec_command(f"test -d '{path}' && echo exists")
                result = stdout.read().decode().strip()

                return result == "exists"
        except Exception as e:
            QMessageBox.warning(self, "SSH Error", str(e))
            return False

    def upload_file(self):
        dialog = WaitingDialog("Uploading file, please wait...", self)
        dialog.show()
        QApplication.processEvents()
        local_path = self.upload_file_path.text()
        remote_path = self.upload_remote_path.text()
        # Use existing drone connection details
        host, username, password = self.get_current_drone_connection()
        if not self.is_valid_remote_path(host, username, password, remote_path):
            QMessageBox.warning(self, "Invalid Path", "The specified remote path is invalid.")
            dialog.close()
            return
        if self.scp_transfer(host, username, password, local_path, remote_path, upload=True):
            QMessageBox.information(self, "Success", "File successfully uploaded.")
        dialog.close()

    def download_file(self):
        dialog = WaitingDialog("Downloading file, please wait...", self)
        dialog.show()
        QApplication.processEvents()
        remote_path = self.download_file_path.text()
        local_path = self.download_local_path.text() # need to fix for windows
        # Use existing drone connection details
        host, username, password = self.get_current_drone_connection()
        if self.scp_transfer(host, username, password, remote_path, local_path, upload=False):
            QMessageBox.information(self, "Success", "File successfully downloaded.")
        dialog.close()

    def scp_transfer(self, host, username, password, local_path, remote_path, upload):
        try:
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, username=username, password=password)
                with SCPClient(ssh.get_transport()) as scp:
                    if upload:
                        scp.put(local_path, remote_path)
                    else:
                        scp.get(remote_path, local_path)
            return True
        except Exception as e:
            QMessageBox.warning(self, "Transfer Error", str(e))
            return False

    def get_current_drone_connection(self):
        drone_id = self.drone_selector.currentText()
        host, username, password = self.drones[drone_id]
        return host, username, password


    def filter_drones(self, text):
        self.drone_selector.clear()
        for drone_id in self.drones:
            if text.lower() in drone_id.lower():
                self.drone_selector.addItem(drone_id)

    def filter_modules(self, text):
        self.moduleComboBox.clear()
        modules_dir = "modules"
        for filename in os.listdir(modules_dir):
            if filename.endswith(('.sh', '.py', '.json')) and text.lower() in filename.lower():
                self.moduleComboBox.addItem(filename)
        
    def add_home_cards(self):
        card1 = QPushButton("BSTG Nessus")
        card1.setObjectName("CardButton")
        card1.setCursor(Qt.PointingHandCursor)
        card1.clicked.connect(self.open_current_drone_nessus)
        self.home_layout.addWidget(card1, 0, 0)

        card2 = QPushButton("Plextrac")
        card2.setObjectName("CardButton")
        card2.setCursor(Qt.PointingHandCursor)  
        card2.clicked.connect(lambda: self.on_card_click("https://report.kevlar.bulletproofsi.net/login"))
        self.home_layout.addWidget(card2, 0, 1)

    def on_card_click(self, url):
        QDesktopServices.openUrl(QUrl(url))

    def open_current_drone_nessus(self):
        host, username, password = self.get_current_drone_connection()
        if host:
            url = f"https://{host}:8834"
            self.on_card_click(url)
        else:
            QMessageBox.warning(self, "No Connection", "No current drone connection found.")

            
    def set_syntax_highlighter(self, module_path):
        if module_path.endswith('.sh'):
            self.syntax_highlighter = BashSyntaxHighlighter(self.module_editor.document())
        elif module_path.endswith('.json'):
            self.syntax_highlighter = JsonSyntaxHighlighter(self.module_editor.document())
        elif module_path.endswith('.py'):
            self.syntax_highlighter = PythonSyntaxHighlighter(self.module_editor.document())

   
    def populate_module_combobox(self):
        modules_dir = "modules"
        if not os.path.exists(modules_dir):
            print("Modules directory not found")
            return

        for filename in os.listdir(modules_dir):
            if filename.endswith(('.sh', '.py', '.json')):
                self.moduleComboBox.addItem(filename)
        
    def on_tab_changed(self, index):
        nmb_tab_index = 4 # assumes NMB is index 4. Adjust as needed for other tabs
        is_nmb_tab_selected = self.tab_widget.currentIndex() == nmb_tab_index

        current_tab = self.tab_widget.widget(index)
        is_custom_tab = hasattr(current_tab, 'is_custom_tab') and current_tab.is_custom_tab

        # Determine visibility for module selection layout
        should_hide_modules = is_nmb_tab_selected or is_custom_tab
        self.module_label.setVisible(not should_hide_modules)
        self.moduleComboBox.setVisible(not should_hide_modules)
        self.module_search.setVisible(not should_hide_modules)
        self.module_button.setVisible(not should_hide_modules)

        # Drone selection layout visibility is not affected by NMB tab
        # It should only be hidden when a custom tab is selected
        should_hide_drones = is_custom_tab
        for i in range(self.droneSelectionLayout.count()): 
            widget = self.droneSelectionLayout.itemAt(i).widget()
            if widget is not None:
                widget.setVisible(not should_hide_drones)

        
    def populate_drones(self):
        for drone_id in self.drones:
            self.drone_selector.addItem(drone_id)

    def configure_drone(self):
        dialog = DroneConfigDialog(self)
        if dialog.exec_():
            host, username, password = dialog.get_details()
            if host and username and password:
                drone_id = f"{username}@{host}"
                
                # Check if the drone ID already exists in the config
                if drone_id in self.drones:
                    QMessageBox.warning(self, "Configuration Exists", 
                                        "This BSTG configuration already exists.")
                else:
                    # Add new drone configuration
                    self.drones[drone_id] = (host, username, password)
                    self.drone_selector.addItem(drone_id)
                    save_config(self.drones)


    def close_current_tab(self, index):
        self.close_tab(index)

    def close_tab(self, index):
        tab = self.tab_widget.widget(index)
        if tab is not None:
            if hasattr(tab, 'is_ssh_tab') and tab.is_ssh_tab:
                # Handle SSH tab specific logic
                if hasattr(tab, 'ssh_thread'):
                    tab.ssh_thread.stop()
                    tab.ssh_thread.wait()
            elif hasattr(tab, 'is_custom_tab') and tab.is_custom_tab:
                pass # do nothing here since file will just get closed
            self.tab_widget.removeTab(index)
        else:
            print(f"Tab at index {index} is not an SSH tab and cannot be closed.")

    def close_tab_from_button(self):
        button = self.sender()
        if button and button.property('tab_widget'):
            tab = button.property('tab_widget')
            index = self.tab_widget.indexOf(tab)
            self.close_tab(index)

    def add_ssh_tab(self, host, username, password, command, is_script_path=True, group_name="", group_color=None):
        tab = QTextEdit()
        tab.setReadOnly(True)
        if group_color:
            tab.setStyleSheet(f"background-color: {group_color};")

        tab.is_ssh_tab = True

        # Prepare for logging
        session_id = f"{username}@{host}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        log_dir = os.path.join("logs", session_id)
        os.makedirs(log_dir, exist_ok=True)
        log_file_path = os.path.join(log_dir, "BSTI.log")

        # Setup SSH Thread
        tab.ssh_thread = SSHThread(host, username, password, command, is_script_path)
        tab.ssh_thread.update_output.connect(lambda output: self.handle_ssh_output(output, tab, log_file_path))
        tab.ssh_thread.start()
        self.threads.append(tab.ssh_thread)

        tab_name = f"{group_name} ({username}@{host})" if group_name else f"{username}@{host}"
        index = self.tab_widget.addTab(tab, tab_name)
        # Create a close button for the tab
        close_button = QPushButton()
        close_button.setCursor(Qt.PointingHandCursor)
        close_button.setIcon(self.style().standardIcon(QStyle.SP_DockWidgetCloseButton))  # Or use a custom icon
        close_button.setStyleSheet(closeButtonStyle)
        close_button.setFixedSize(16, 16)
        close_button.setToolTip("Close Tab")
        close_button.setProperty('tab_widget', tab)
        close_button.clicked.connect(self.close_tab_from_button)

        self.tab_widget.tabBar().setTabButton(self.tab_widget.indexOf(tab), QTabBar.RightSide, close_button)

        return tab


    def handle_ssh_output(self, output, tab, log_file_path):
        try:
            with open(log_file_path, 'a', encoding='utf-8') as log_file:
                log_file.write(output + '\n')
        except Exception as e:
            print("Error writing to log file:", e)

        # Update the UI with the buffered output
        tab.append(output)

    def remove_thread(self, thread):
        self.threads.remove(thread)
        
    def module_selected(self, index):
        if index >= 0:
            selected_module = self.moduleComboBox.itemText(index)
            if selected_module:
                module_path = os.path.join("modules", selected_module)
                self.load_module_into_editor(module_path)


    def test_drone_connection(self, host, username, password):
        """Tests the SSH connection to the drone."""
        try:
            with paramiko.SSHClient() as ssh:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(host, username=username, password=password, timeout=5)
                # Connection successful
                return True
        except Exception as e:
            # Connection failed
            QMessageBox.warning(self, "Connection Failed", f"Failed to connect to the {host} BSTG - Error: {e}")
            return False

    def execute_module(self):
        if not self.drone_selector.currentText():
            QMessageBox.warning(self, "No Drone Selected", "Please configure and select a drone first.")
            return

        selected_module = self.moduleComboBox.currentText()
        if not selected_module:
            QMessageBox.warning(self, "No Module Selected", "Please select a module first.")
            return
        self.current_module = selected_module

        # Use temporary file if available, otherwise use the original file
        module_path = self.temp_file.name if self.temp_file else os.path.join("modules", selected_module)

        drone_id = self.drone_selector.currentText()
        host, username, password = self.drones[drone_id]

        if not self.test_drone_connection(host, username, password):
            return

        if selected_module.endswith('.json'):
            with open(module_path, 'r') as file:
                module_data = json.load(file)
                group_color = module_data.get("color", None)
                if module_data.get("grouped", False):
                    for tab_info in module_data.get("tabs", []):
                        group_name = tab_info.get("name", "")
                        self.open_tab_group(tab_info["command"], False, group_name, group_color)
            return

        elif selected_module.endswith(('.py', '.sh')):
            args_dialog = CommandLineArgsDialog(module_path, host, username, password, self)
            args = ""
            file_paths = {}
            if args_dialog.has_arguments():
                if args_dialog.exec_() == QDialog.Accepted:
                    args, file_paths = args_dialog.get_arguments()
            full_command = (f"{module_path} {args}", file_paths)
            self.add_ssh_tab(host, username, password, full_command, is_script_path=True)

    def open_tab_group(self, command, is_script_path=True, group_name=None, group_color=None):
        drone_id = self.drone_selector.currentText()
        host, username, password = self.drones[drone_id]
        self.add_ssh_tab(host, username, password, command, is_script_path, group_name, group_color)

            
    def closeEvent(self, event):
        for thread in self.threads:
            if thread.isRunning():
                thread.stop()
        super().closeEvent(event)


    def gather_screenshots(self):
        def strip_ansi_codes(text):
            ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
            return ansi_escape.sub('', text)
        
        def consolidate_linebreaks(text):
            # Replace two or more consecutive linebreaks with a single linebreak
            return re.sub(r'\n{2,}', '\n', text)

        output = self.log_content_area.toPlainText()
        try:
            #module_comment = f"# Module executed: {self.current_module}" if hasattr(self, 'current_module') else ""
        
            cleaned_output = html.escape(consolidate_linebreaks(strip_ansi_codes(output)))

            css = """
            body {
                background-color: #1e1e1e; /* Dark background color */
                padding: 20px;
                font-family: 'Consolas', 'Courier New', monospace;
                color: #dcdcdc;  /* Light grey text color */
                line-height: 1.4; /* Adjust line height for better readability */
                border: 1px solid #333; /* Add a border for a distinct terminal look */
                border-radius: 4px; /* Slightly round the corners */
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.5); /* Subtle shadow for depth */
            }

            pre {
                white-space: pre-wrap;       /* Wrap text */
                word-wrap: break-word;       /* Break the word at the edge */
            }

            /* Optional: Add a background texture for a more nuanced look */
            body::after {
                content: '';
                position: absolute;
                top: 0; right: 0; bottom: 0; left: 0;
                z-index: -1;
                opacity: 0.1; /* Adjust opacity for subtlety */
            }
            """


            # Create a temporary HTML file containing only the cleaned output
            html_content = f"""
            <html>
            <head>
            <style>
            {css}
            </style>
            </head>
            <body>
            <pre>{cleaned_output}</pre>
            </body>
            </html>
            """
            # Create an instance of WebShot
            if sys.platform == "win32":
                shot = WebShot(
                    quality=100,
                    config=Config(
                        wkhtmltopdf=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe",
                        wkhtmltoimage=r"C:\Program Files\wkhtmltopdf\bin\wkhtmltoimage.exe",
                    ),
                )
            else:
                shot = WebShot(
                    quality=100
                )

            screenshot_dir = "screenshots"

            os.makedirs(screenshot_dir, exist_ok=True)  # Ensure the directory exists

            # Specify the output file path based on the session name
            session_name = self.log_sessions_combo.currentText()
            output_path = os.path.join(screenshot_dir, f"{session_name}.png")

            # Save the screenshot
            shot.create_pic(html=html_content, css=css, output=output_path)
            QMessageBox.information(self, "Screenshot Saved", f"Screenshot saved as {output_path}")
        
        except Exception:
            QMessageBox.information(self, "Error", "Unable to capture screenshot")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(DRACULA_STYLESHEET)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec_())
