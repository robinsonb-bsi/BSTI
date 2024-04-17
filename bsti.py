# BSTI
# version: 1.1
# Authors: Connor Fancy

import sys
import os
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QCompleter, QMenu, QInputDialog, QDialogButtonBox, QTableWidget, QTableWidgetItem, QCheckBox, QLabel, QAction, QTabBar, QStyle, QPlainTextEdit, QMainWindow, QGridLayout, QHBoxLayout, QTabWidget, QTextEdit, QPushButton, QVBoxLayout, QWidget, QFileDialog, QLabel, QDialog, QLineEdit, QFormLayout, QMessageBox, QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal, QUrl, QRegExp, Qt, QProcess
from PyQt5.QtGui import QTextCursor, QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QDesktopServices
from PyQt5.QtWebKitWidgets import QWebView
from PyQt5.QtGui import QTextCharFormat, QColor
import paramiko
from scp import SCPClient
import tempfile
import json
import datetime
import subprocess
from htmlwebshot import WebShot, Config
import html
import re
import threading
import signal
import hashlib
import warnings
import shlex
import autopep8
import time
import platform
warnings.filterwarnings("ignore", category=DeprecationWarning, 
                        message=".*sipPyTypeDict.*") # hushes annoying errors for now temp solution


STYLESHEET_FOR_TEXTEDIT = """
    QTextEdit {
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 12pt;
        color: #f8f8f2;
        background-color: #44475a;
        padding: 5px;
        border: 1px solid #6272a4;
    }
"""

LABEL_STYLESHEET = """
    QLabel {
        font-family: 'Arial';
        font-size: 14pt;
        color: #f8f8f2;
        background-color: #44475a;
        padding: 5px;
        border: 1px solid #6272a4;
    }
"""

CLOSE_BUTTON_STYLE = """
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

class DiagnosticThread(QThread):
    diagnosticsUpdated = pyqtSignal(str, str)

    def __init__(self, host, username, password):
        super().__init__()
        self.host = host
        self.username = username
        self.password = password
        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def run(self):
        try:
            self.ssh_client.connect(self.host, username=self.username, password=self.password)
            while True:
                stdin, stdout, stderr = self.ssh_client.exec_command("top -b -n 1")
                top_output = stdout.read().decode('utf-8')

                response = subprocess.Popen(["ping", self.host], stdout=subprocess.PIPE)
                ping_output, _ = response.communicate()

                self.diagnosticsUpdated.emit(top_output, ping_output.decode('utf-8'))

                self.sleep(1)

        except Exception as e:
            self.diagnosticsUpdated.emit("Connection Error", "Offline")

        finally:
            if self.ssh_client:
                self.ssh_client.close()

    def stop(self):
        self.terminate()
        if self.ssh_client:
            self.ssh_client.close()

class CommandLineArgsDialog(QDialog):
    def __init__(self, script_path, host, username, password, parent=None):
        super().__init__(parent)
        self.host = host
        self.username = username
        self.password = password
        self.nessus_finding = None

        self.setWindowTitle('Enter Command-Line Arguments')

        layout = QVBoxLayout(self)

        # Parse the script for arguments, file requirements, and Nessus finding
        self.args_metadata, self.file_metadata, self.nessus_finding = self.parse_script_for_args(script_path)
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

        return args_str, file_paths, self.nessus_finding

    
    def on_submit(self):
        # Retrieve the arguments and file paths as a tuple
        args_str, file_paths, self.nessus_finding = self.get_arguments()
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
        nessus_finding = None
        try:
            with open(script_path, 'r') as script_file:
                parse_args, parse_files, parse_nessus = False, False, False
                for line in script_file:
                    if line.startswith("#!"):
                        continue  # Skip shebang line
                    if line.strip() == '# ARGS':
                        parse_args = True
                        continue
                    if line.strip() == '# ENDARGS':
                        parse_args = False
                        continue
                    if line.strip() == '# STARTFILES':
                        parse_files = True
                        continue
                    if line.strip() == '# ENDFILES':
                        parse_files = False
                        continue
                    if line.strip() == '# NESSUSFINDING':
                        parse_nessus = True
                        continue
                    if line.strip() == '# ENDNESSUS':
                        parse_nessus = False
                        continue
                    if parse_nessus:
                        nessus_finding = line.strip()
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
        return args_metadata, file_metadata, nessus_finding


    
    def has_arguments(self):
        return bool(self.args_metadata) or bool(self.file_metadata)

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

class InteractiveSshThread(QThread):
    output = pyqtSignal(str)

    def __init__(self, hostname, username, password, parent=None):
        super(InteractiveSshThread, self).__init__(parent)
        self.hostname = hostname
        self.username = username
        self.password = password
        self.command = None
        self.aliases = {
            "invoke-ls": "ls -lah",
            "invoke-top": "top -n 1",
            "invoke-ps": "ps aux",
            "invoke-nmap": "nmap -sV",
        }

    def run(self):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.hostname, username=self.username, password=self.password)
            channel = client.invoke_shell()

            # Explicitly start Bash shell - zsh has formatting issues
            channel.send("bash\n")

            while True:
                    if self.command is not None:
                        command_parts = self.command.split()
                        base_command = command_parts[0]
                        additional_args = ' '.join(command_parts[1:])

                        if base_command in self.aliases:
                            processed_command = self.aliases[base_command] + ' ' + additional_args
                        elif base_command.startswith("invoke-"):
                            self.output.emit(f"Error: Unknown command '{base_command}'\n")
                            processed_command = ""
                        else:
                            processed_command = self.command
                        
                        if processed_command:
                            channel.send(processed_command + '\n')
                        self.command = None

                    if channel.recv_ready():
                        line = channel.recv(1024).decode('utf-8')
                        self.output.emit(line)
                    else:
                        time.sleep(0.1)
        except:
            pass
    def send_command(self, command):
        self.command = command

class PromptLineEdit(QLineEdit):
    def __init__(self, prompt=">>> ", parent=None):
        super().__init__(parent)
        self.prompt = prompt
        self.setText(self.prompt)
        self.setCursorPosition(len(self.prompt))  

    def focusInEvent(self, event):
        if self.text() == self.prompt:
            self.setCursorPosition(len(self.prompt))  
        QLineEdit.focusInEvent(self, event)

    def keyPressEvent(self, event):
        if self.text() == self.prompt:
            self.setText('')
        QLineEdit.keyPressEvent(self, event)

    def focusOutEvent(self, event):
        if self.text().strip() == "":
            self.setText(self.prompt)
            self.setCursorPosition(len(self.prompt))  
        QLineEdit.focusOutEvent(self, event)


class TerminalWidget(QWidget):
    def __init__(self, hostname, username, password):
        super().__init__()
        self.ssh_thread = InteractiveSshThread(hostname, username, password)
        self.ssh_thread.output.connect(self.append_output)
        self.ssh_thread.start()
        self.commandHistory = []
        self.historyIndex = -1
        self.initUI()

    def initUI(self):
        self.layout = QVBoxLayout(self)
        self.textEdit = QTextEdit()
        self.lineEdit = PromptLineEdit()

        self.textEdit.setStyleSheet("background-color: black; color: white;")
        self.lineEdit.setStyleSheet("background-color: black; color: white;")
        font = QFont("Consolas", 10)
        self.textEdit.setFont(font)
        self.lineEdit.setFont(font)

        completer = QCompleter(list(self.ssh_thread.aliases.keys()))
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.lineEdit.setCompleter(completer)

        self.layout.addWidget(self.textEdit)
        self.layout.addWidget(self.lineEdit)

        self.lineEdit.returnPressed.connect(self.onReturnPressed)

    def onReturnPressed(self):
        command = self.lineEdit.text()
        if command.startswith(self.lineEdit.prompt):
            command = command[len(self.lineEdit.prompt):]  # Remove the prompt from the command
        self.commandHistory.append(command)
        self.historyIndex = len(self.commandHistory) - 1
        self.ssh_thread.send_command(command)
        self.lineEdit.clear()
        self.lineEdit.setText(self.lineEdit.prompt)
        self.lineEdit.setCursorPosition(len(self.lineEdit.prompt))

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Up, Qt.Key_Down):
            if self.commandHistory:
                if event.key() == Qt.Key_Up and self.historyIndex > 0:
                    self.historyIndex -= 1
                elif event.key() == Qt.Key_Down and self.historyIndex < len(self.commandHistory) - 1:
                    self.historyIndex += 1
                self.lineEdit.setText(self.commandHistory[self.historyIndex])

    def strip_ansi_codes(self, text):
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        stripped_text = ansi_escape.sub('', text)
        # Trim leading and trailing whitespace and normalize new lines
        stripped_text = stripped_text.strip().replace('\r\n', '\n').replace('\r', '\n')
        return stripped_text


    def append_output(self, data):
        plain_text = self.strip_ansi_codes(data)
        self.textEdit.append(plain_text)

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
                    clean_output = self.strip_ansi_codes(output)
                    self.update_output.emit(clean_output)

                if stderr.channel.recv_stderr_ready():
                    output = stderr.channel.recv_stderr(4096).decode('utf-8')
                    clean_output = self.strip_ansi_codes(output)
                    self.update_output.emit(clean_output)

                self.msleep(100)   # Sleep for a short time to avoid bricking cpu :)

        except Exception as e:
            self.update_output.emit(f"SSH Connection Error: {str(e)}")
        finally:
            if self.ssh:
                self.ssh.close()

    def strip_ansi_codes(self, text):
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        stripped_text = ansi_escape.sub('', text)
        # Trim leading and trailing whitespace and normalize new lines
        stripped_text = stripped_text.strip().replace('\r\n', '\n').replace('\r', '\n')
        return stripped_text


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
        self.process = None
        self._pause_requested = threading.Event()

    def run(self):
        if sys.platform == 'win32':
            self.process = subprocess.Popen(self.command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            self.process = subprocess.Popen(self.command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        while True:
            if self._pause_requested.is_set():
                self.pause_process()
                break
            output = self.process.stdout.readline()
            if output == '' and self.process.poll() is not None:
                break
            if output:
                self.output_signal.emit(output.strip())

    def pause(self):
        self._pause_requested.set()

    def pause_process(self):
        if sys.platform == 'win32':
            self.process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            self.process.send_signal(signal.SIGINT)

class N2PArgsDialog(QDialog):
    def __init__(self, parent=None, default_client_id="", default_report_id=""):
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

        self.client_id_edit.setText(default_client_id)
        self.report_id_edit.setText(default_report_id)

        self.scope_edit = QComboBox(self)
        self.scope_edit.addItems(["", "internal", "external", "web", "surveillance"])

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

class CredentialsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("Enter Plextrac Credentials")

        layout = QFormLayout(self)
        self.usernameLineEdit = QLineEdit(self)
        self.passwordLineEdit = QLineEdit(self)
        self.passwordLineEdit.setEchoMode(QLineEdit.Password)

        layout.addRow("Username:", self.usernameLineEdit)
        layout.addRow("Password:", self.passwordLineEdit)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel, self)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addRow(self.buttons)

    def getCredentials(self):
        return self.usernameLineEdit.text(), self.passwordLineEdit.text()

class CustomTableWidget(QTableWidget):
    gatherFindingsSignal = pyqtSignal(str)
    def __init__(self, parent=None, dataframe=None):
        super().__init__(parent)
        self.dataframe = dataframe
        self.setupTable()

    def setupTable(self):
        if self.dataframe is not None:
            self.setColumnCount(self.dataframe.shape[1])
            self.setHorizontalHeaderLabels(self.dataframe.columns)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)

    def contextMenuEvent(self, event):
        menu = QMenu(self)
        gatherAction = menu.addAction("Extract hosts")
        action = menu.exec_(self.mapToGlobal(event.pos()))
        if action == gatherAction:
            self.gatherFindings()

    def gatherFindings(self):
        selected_row = self.currentRow()
        if selected_row < 0:
            return  # No row selected
        finding_name_column = self.columnIndex("Name")
        if finding_name_column < 0:
            QMessageBox.warning(self, "Error", "Finding Name column not found.")
            return
        finding_name = self.item(selected_row, finding_name_column).text()
        self.gatherFindingsSignal.emit(finding_name)

    def columnIndex(self, column_name):
        for i in range(self.columnCount()):
            if self.horizontalHeaderItem(i).text() == column_name:
                return i
        return -1

class ZeusWorker(QThread):
    output_signal = pyqtSignal(str)

    def __init__(self, command_args):
        super().__init__()
        self.command_args = command_args

    def run(self):
        try:
            # Ensure stderr is also redirected to stdout
            process = subprocess.Popen(self.command_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            final_output = ''
            # Live capture of output instead of waiting for process to complete
            for line in process.stdout:
                final_output += line
                self.output_signal.emit(line)  # Emit signal for every line to update the GUI in real time
            process.stdout.close()
            process.wait()
        except Exception as e:
            final_output = f"Failed to run Zeus: {str(e)}"
            self.output_signal.emit(final_output)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.current_module_path = None
        self.temp_file = None
        self.nessus_finding_name = None
        self.socks_ssh_process = None
        self.portforward_ssh_process = None
        self.df = None
        self.client_id = None
        self.report_id = None
        self.nessus_findings_map = {}
        self.setWindowTitle("Bulletproof Solutions Testing Interface")
        self.setGeometry(100, 100, 2200, 1200)
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

        # Delete a bstg
        self.delete_drone_action = QAction("Delete BSTG", self)
        self.delete_drone_action.triggered.connect(self.delete_drone)
        self.drone_menu.addAction(self.delete_drone_action)

        # Tmux session attach
        self.connect_tmux_action = QAction("Connect to Tmux Session", self)
        self.connect_tmux_action.triggered.connect(self.on_connect_tmux_triggered)
        self.terminal_menu.addAction(self.connect_tmux_action)

        # Socks proxy setup
        self.connect_to_socks_action = QAction("Start SOCKS Proxy", self)
        self.connect_to_socks_action.triggered.connect(self.open_socks_ssh)
        self.terminal_menu.addAction(self.connect_to_socks_action)

        # Local port forward setup
        self.connect_to_portforward_action = QAction("Start Local Port Forward", self)
        self.connect_to_portforward_action.triggered.connect(self.open_portforward_ssh)
        self.terminal_menu.addAction(self.connect_to_portforward_action)

        # Stop SOCKS proxy setup
        self.stop_socks_proxy_action = QAction("Stop SOCKS Proxy", self)
        self.stop_socks_proxy_action.triggered.connect(self.stop_socks_proxy)
        self.terminal_menu.addAction(self.stop_socks_proxy_action)

        # Stop Local port forward setup
        self.stop_portforward_action = QAction("Stop Local Port Forward", self)
        self.stop_portforward_action.triggered.connect(self.stop_portforward)
        self.terminal_menu.addAction(self.stop_portforward_action)

        # Reporting menu - n2p
        self.report_menu = self.menu_bar.addMenu("Reports")
        self.create_report_action = QAction("Create Report", self)
        self.create_report_action.triggered.connect(self.create_report)
        self.report_menu.addAction(self.create_report_action)

        # Plugin manager button
        self.plugin_manager_action = QAction("Plugin Manager", self)
        self.plugin_manager_action.triggered.connect(self.run_plugin_manager)
        self.report_menu.addAction(self.plugin_manager_action)

        # Import findings into plextrac
        self.report_findings_action = QAction("Upload Findings to Plextrac", self)
        self.report_findings_action.triggered.connect(self.report_findings_execution)
        self.report_menu.addAction(self.report_findings_action)

        # Help menu for docs
        self.help_menu = self.menu_bar.addMenu("Help")
        self.help_menu_action = QAction("View Documentation", self)
        self.help_menu_action.triggered.connect(self.open_documentation)
        self.help_menu.addAction(self.help_menu_action)


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

        # Add Lint button
        self.lint_button = QPushButton("Auto-Format Python Module")
        self.lint_button.clicked.connect(self.apply_autopep8)
        self.module_editor_layout.addWidget(self.lint_button)

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

        # Add NMB tab
        self.setup_nmb_tab()

        # New! added zeus tab
        self.setup_zeus_tab()

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
        self.drone_selector.currentIndexChanged.connect(self.on_drone_selected)
        self.home_tab = QWidget()
        self.home_layout = QGridLayout(self.home_tab)

        # Initialize the UI components in the correct order
        self.init_diagnostics_ui()
        self.init_file_transfer_ui()
        self.add_home_cards()

        self.tab_widget.insertTab(0, self.home_tab, "Home")

        # hide/show tabs based on active tab
        self.tab_widget.currentChanged.connect(self.on_tab_changed)


    def setup_zeus_tab(self):
        self.zeus_tab = QWidget()
        self.zeus_layout = QVBoxLayout(self.zeus_tab)

        # Argument Layout
        self.zeus_argument_layout = QFormLayout()

        # Required Arguments
        self.target_url_input = QLineEdit()
        self.target_url_input.setPlaceholderText("Enter target URL (e.g., http://localhost:5000)")
        self.project_folder_input = QLineEdit()
        self.project_folder_input.setPlaceholderText("Enter project folder name")

        # Optional Arguments
        self.login_config_input = QLineEdit()
        self.login_config_input.setPlaceholderText("Path to login config file (optional)")
        self.login_config_button = QPushButton("Browse...")
        self.login_config_button.clicked.connect(self.browse_login_config)

        self.proxy_input = QLineEdit()
        self.proxy_input.setText("squid.kevlar.bulletproofsi.net:3128")

        # Layout for login config with button
        self.login_config_layout = QHBoxLayout()
        self.login_config_layout.addWidget(self.login_config_input)
        self.login_config_layout.addWidget(self.login_config_button)

        # Adding rows to the form
        self.zeus_argument_layout.addRow("Target URL:", self.target_url_input)
        self.zeus_argument_layout.addRow("Project Folder:", self.project_folder_input)
        self.zeus_argument_layout.addRow("Login Config File:", self.login_config_layout) 
        self.zeus_argument_layout.addRow("Proxy (optional):", self.proxy_input)

        self.zeus_layout.addLayout(self.zeus_argument_layout)

        # Buttons Layout
        self.zeus_buttons_layout = QHBoxLayout()
        self.zeus_run_button = QPushButton("Run Zeus")
        self.zeus_run_button.setCursor(Qt.PointingHandCursor)
        self.zeus_run_button.clicked.connect(self.execute_zeus)
        self.zeus_buttons_layout.addWidget(self.zeus_run_button)
        self.zeus_layout.addLayout(self.zeus_buttons_layout)

        # Output Area
        self.zeus_output = QTextEdit()
        self.zeus_output.setReadOnly(True)
        self.zeus_layout.addWidget(self.zeus_output)

        # Add Zeus tab to the main tab widget
        self.tab_widget.addTab(self.zeus_tab, "Zeus")


    def execute_zeus(self):
        self.zeus_output.clear()
        target_url = self.target_url_input.text().strip()
        project_folder = self.project_folder_input.text().strip()
        login_config = self.login_config_input.text().strip()
        proxy = self.proxy_input.text().strip()

        if not target_url or not project_folder:
            QMessageBox.warning(self, "Parameter Error", "Please provide both a target URL and a project folder.")
            return

        # Determine the correct binary based on the OS
        os_type = platform.system().lower()
        if os_type == "windows":
            zeus_executable = "ZEUS.exe"
        else:
            zeus_executable = "./zeus"

        # Check if the Zeus executable exists
        if not os.path.exists(zeus_executable):
            QMessageBox.warning(self, "Feature Not Implemented", "The Zeus binary does not exist on this system. This feature is not yet implemented.")
            return

        command_args = [zeus_executable, target_url, '--project-folder', project_folder]
        if login_config:
            command_args.extend(['--login-config', login_config])
        if proxy:
            command_args.extend(['--proxy', proxy])

        # Create and start the worker thread
        self.zeus_worker = ZeusWorker(command_args)
        self.zeus_worker.output_signal.connect(self.update_zeus_output)
        self.zeus_worker.start()


    def browse_login_config(self):
        fname = QFileDialog.getOpenFileName(self, 'Open file', '', "YAML files (*.yaml *.yml)")
        if fname[0]:
            self.login_config_input.setText(fname[0])


    def update_zeus_output(self, text):
        self.zeus_output.moveCursor(QTextCursor.End)
        self.zeus_output.insertPlainText(text)
        self.zeus_output.moveCursor(QTextCursor.End)


    def delete_drone(self):
        config = load_config()
        if not config:
            QMessageBox.information(self, "Information", "No BSTG configurations available.")
            return

        # Let the user select which BSTG to delete
        bstgs = list(config.keys())
        bstg, ok = QInputDialog.getItem(self, "Delete BSTG", "Select BSTG:", bstgs, 0, False)

        if ok and bstg:
            del config[bstg]
            save_config(config)
            QMessageBox.information(self, "Success", f"{bstg} configuration deleted.")
            self.populate_drones()  # Repopulate the drone selector with updated list

    def init_term_UI(self):
        host, username, password = self.get_current_drone_connection()
        terminalWidget = TerminalWidget(host, username, password)
        tab_index = self.tab_widget.addTab(terminalWidget, f"{username}@{host}")
        
        # Add close button to the terminal tab
        self.add_close_button_to_tab(terminalWidget, tab_index)

        self.tab_widget.setCurrentIndex(tab_index)

    def open_terminal_ssh(self):
        self.init_term_UI()

    def open_documentation(self):
        tab = QWidget()
        tab.is_custom_tab = True
        layout = QVBoxLayout(tab)
        documentation_file = os.path.join("wiki", "docs.html")
        web_view = QWebView()
        web_view.load(QUrl.fromLocalFile(os.path.abspath(documentation_file)))
        layout.addWidget(web_view)
        tab_index = self.tab_widget.addTab(tab, "Wiki")
        # Add close button to the tab
        close_button = QPushButton()
        close_button.setIcon(self.style().standardIcon(QStyle.SP_DockWidgetCloseButton))
        close_button.setStyleSheet(CLOSE_BUTTON_STYLE)
        close_button.setFixedSize(16, 16)
        close_button.setToolTip("Close Tab")
        close_button.setProperty('tab_widget', tab)
        close_button.clicked.connect(self.close_tab_from_button)

        self.tab_widget.tabBar().setTabButton(self.tab_widget.indexOf(tab), QTabBar.RightSide, close_button)
        self.tab_widget.setCurrentIndex(tab_index)

    def create_report(self):
        # Open the custom dialog
        dialog = CredentialsDialog(self)
        if dialog.exec() == QDialog.Accepted:
            username, password = dialog.getCredentials()

            # Build and execute the command
            command = f"python n2p_ng.py -u {username} -p '{password}' -t report --create"
            try:
                if sys.platform == "win32":
                    # For Windows, modify the command to keep PowerShell open
                    powershell_command = f'start powershell -Command "{command}; Read-Host -Prompt \'Press Enter to exit\'"'
                    subprocess.Popen(powershell_command, shell=True)
                else:
                    # For Unix/Linux, open a new terminal window
                    subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', command])

            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to execute the command: {e}")

    def parse_output(self, output):
        # Regular expressions to find Client ID and Report ID
        client_id_pattern = r"Client ID: (\S+)"
        report_id_pattern = r"Report ID: (\S+)"

        client_id_match = re.search(client_id_pattern, output)
        report_id_match = re.search(report_id_pattern, output)

        client_id = client_id_match.group(1) if client_id_match else ""
        report_id = report_id_match.group(1) if report_id_match else ""

        return client_id, report_id

    def apply_autopep8(self):
        try:
            current_module_type = self.get_current_module_type()

            if current_module_type == 'python':
                current_code = self.module_editor.toPlainText()
                formatted_code = autopep8.fix_code(current_code)
                self.module_editor.setPlainText(formatted_code)
                QMessageBox.information(self, "autopep8", "Formatting applied successfully.")
            else:
                QMessageBox.warning(self, "autopep8", "This feature is only available for Python modules.")
        except Exception as e:
            QMessageBox.warning(self, "autopep8", f"An error occurred: {e}")

    def get_current_module_type(self):
        current_filename = self.moduleComboBox.currentText()

        if current_filename.endswith('.py'):
            return 'python'
        elif current_filename.endswith('.sh'):
            return 'bash'
        elif current_filename.endswith('.json'):
            return 'json'
        else:
            return 'unknown'


    def run_plugin_manager(self):
        csv_file, _ = QFileDialog.getOpenFileName(self, "Select CSV File", "", "CSV Files (*.csv)")
        if not csv_file:
            return
        
        csv_file_escaped = shlex.quote(csv_file)
        python_command = f"python plugin_manager.py -f {csv_file_escaped}"

        try:
            if sys.platform == "win32":
                ps_command = f"Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoExit', '-Command', \"{python_command}\""
                subprocess.Popen(['powershell', '-Command', ps_command], shell=True)
            else:
                subprocess.Popen(['gnome-terminal', '--', 'bash', '-c', python_command])
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to execute the command: {e}")

    def report_findings_execution(self):
        # Open the dialog to get arguments, pre-filling client and report ID
        report_file = "report_info.txt"
        if os.path.exists(report_file):
            with open(report_file, "r") as file:
                output = file.read()

            # Parse output for Client ID and Report ID
            client_id, report_id = self.parse_output(output)
            self.client_id = client_id
            self.report_id = report_id
            QMessageBox.information(self, "Information", 
                            f"Client ID ({self.client_id}) and Report ID ({self.report_id}) have been pre-filled based on your latest report generation.")
            
        args_dialog = N2PArgsDialog(parent=self, default_client_id=self.client_id, default_report_id=self.report_id)
        if args_dialog.exec_() == QDialog.Accepted:
            args = args_dialog.get_arguments()

            # Prepare the command
            command = ["python", "n2p_ng.py"]
            for arg, value in args.items():
                if arg != 'noncore' and value:
                    command.extend([f"--{arg}", value])

            # Check and append the --noncore argument separately
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

        # switch focus
        self.tab_widget.setCurrentIndex(index)


    def read_process_output(self, process, text_edit):
        text_edit.append(process.readAllStandardOutput().data().decode())

    def add_close_button_to_tab(self, tab, index):
        close_button = QPushButton()
        close_button.setIcon(self.style().standardIcon(QStyle.SP_DockWidgetCloseButton))
        close_button.setStyleSheet(CLOSE_BUTTON_STYLE)
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
                df = pd.read_csv(file_name)
                self.df = df
                if self.is_nessus_csv(df):
                    self.parse_nessus_csv(df, layout)
                else:
                    table = self.create_table_from_dataframe(df)
                    layout.addWidget(table)
            elif file_name.lower().endswith('.json'):
                with open(file_name, 'r') as file:
                    content = file.read()
                    try:
                        parsed_json = json.loads(content)
                        pretty_json = json.dumps(parsed_json, indent=4, sort_keys=True)
                    except json.JSONDecodeError:
                        pretty_json = content

                text_edit = QTextEdit()
                text_edit.setPlainText(pretty_json)
                text_edit.setFont(QFont("Courier", 10))
                layout.addWidget(text_edit)
            elif file_name.lower().endswith('.html'):
                try:
                    web_view = QWebView()
                    web_view.load(QUrl.fromLocalFile(os.path.abspath(file_name)))
                    layout.addWidget(web_view)
                except Exception as e:
                    print("ERROR:", e) 

            self.tab_widget.addTab(tab, os.path.basename(file_name))
            close_button = QPushButton()
            close_button.setIcon(self.style().standardIcon(QStyle.SP_DockWidgetCloseButton))
            close_button.setStyleSheet(CLOSE_BUTTON_STYLE)
            close_button.setFixedSize(16, 16)
            close_button.setToolTip("Close Tab")
            close_button.setProperty('tab_widget', tab)
            close_button.clicked.connect(self.close_tab_from_button)

            self.tab_widget.tabBar().setTabButton(self.tab_widget.indexOf(tab), QTabBar.RightSide, close_button)
        
    def is_nessus_csv(self, dataframe):
        # Check if the CSV is a Nessus file (by looking for specific column names)
        nessus_columns = ['Plugin ID', 'CVE', 'Risk', 'Host', 'Description']
        return any(column in dataframe.columns for column in nessus_columns)

    def parse_nessus_csv(self, dataframe, layout):
        self.nessus_table = CustomTableWidget(self, dataframe)
        self.nessus_table.gatherFindingsSignal.connect(self.gatherSimilarFindings)
        layout.addWidget(self.nessus_table)

        risk_filter = QComboBox()
        risk_filter.addItems(['All', 'Critical', 'High', 'Medium', 'Low', 'Informational'])
        risk_filter.currentTextChanged.connect(lambda: self.apply_nessus_filter(dataframe, risk_filter.currentText()))
        layout.addWidget(risk_filter)

        self.populate_table(self.nessus_table, dataframe)

    def apply_nessus_filter(self, dataframe, risk_level):
        # Normalize and filter the dataframe
        normalized_risk = dataframe['Risk'].str.lower().str.strip()
        if risk_level.lower() != 'all':
            filtered_df = dataframe[normalized_risk == risk_level.lower()]
        else:
            filtered_df = dataframe

        self.populate_table(self.nessus_table, filtered_df)

    def populate_table(self, table, dataframe):
        # Set row count
        table.setRowCount(dataframe.shape[0])

        # Populate the table
        for i, (index, row) in enumerate(dataframe.iterrows()):
            for j, value in enumerate(row):
                item = QTableWidgetItem(str(value))
                table.setItem(i, j, item)

        table.resizeColumnsToContents()

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
    

    def gatherSimilarFindings(self, finding_name):
        similar_findings = self.df[self.df['Name'] == finding_name]
        hosts = similar_findings['Host'].unique()

        # Suggest a default file name
        suggested_filename = f'{finding_name}_targets.txt'

        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", suggested_filename, "Text Files (*.txt)", options=options)

        # Check if the user provided a file path
        if file_path:
            with open(file_path, 'w') as file:
                for host in hosts:
                    file.write(host + '\n')
            QMessageBox.information(self, "Findings Gathered", f"Similar findings have been gathered into {file_path}.")
        else:
            QMessageBox.warning(self, "File Save Cancelled", "The operation was cancelled and no file was saved.")
        
    
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

        self.buttons_layout = QHBoxLayout()
        # Run button
        self.execute_nmb_button = QPushButton("Run")
        self.execute_nmb_button.setCursor(Qt.PointingHandCursor)
        self.execute_nmb_button.setObjectName("ExecuteNMBButton")
        self.execute_nmb_button.clicked.connect(self.execute_nmb)
        self.buttons_layout.addWidget(self.execute_nmb_button)

        # Pause button
        self.pause_button = QPushButton("Pause", self)
        self.pause_button.setCursor(Qt.PointingHandCursor)
        self.pause_button.clicked.connect(self.on_pause_clicked)
        self.buttons_layout.addWidget(self.pause_button)

        # Add the buttons layout to the main layout
        self.nmb_layout.addLayout(self.buttons_layout)

        # Output area
        self.nmb_output = QTextEdit()
        self.nmb_output.setReadOnly(True)
        self.nmb_layout.addWidget(self.nmb_output)

        # Add NMB tab to the main tab widget
        self.tab_widget.addTab(self.nmb_tab, "NMB")
        self.update_argument_fields()

    def add_controls(self):
        self.pause_button = QPushButton("Pause", self)
        self.pause_button.clicked.connect(self.on_pause_clicked)

    def on_pause_clicked(self):
        try:
            if self.nmb_thread:
                self.nmb_thread.pause()
                self.nmb_output.append("NMB paused.")
        except AttributeError:
            QMessageBox.warning(self, "Error", "NMB is not running")
        else:
            QMessageBox.information(self, "State Saved", "The save state signal has been sent.")


    def initialize_mode_arguments(self):
        self.mode_arguments = {
            "deploy": {
                "client-name": "Text",
                "targets-file": "File",
                "scope": ["core", "nc", "custom"],
                "exclude-file": "File",
                "discovery": "Checkbox",
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
                "eyewitness": "Checkbox"
            },
            "external": {
                "csv-file": "File",
                "local": "Checkbox",
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
                "app-name": "File"
            },
            "immuniweb": {
                "immuni-scan-type": ["apk", "ipa"],
                "immuni-app-name": "File",
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
        self.execute_nmb_button.setDisabled(True)
        self.nmb_output.clear() 
        host, username, password = self.get_current_drone_connection()

        mode = self.mode_combobox.currentText()
        command_args = ["python", "nmb.py", "-m", mode, "-u", username, "-p", password, "-d", host]

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

        self.nmb_thread = NMBRunnerThread(command_args)
        self.nmb_thread.output_signal.connect(self.update_output)
        self.nmb_thread.finished.connect(self.on_thread_complete)
        self.nmb_thread.start()

    def on_thread_complete(self):
        self.execute_nmb_button.setEnabled(True)
        self.nmb_output.append("NMB process completed.")

    def update_output(self, text):
        self.nmb_output.append(text)


    def populate_log_sessions_list(self):
        self.log_sessions_combo.clear()
        log_dir = os.path.join("logs")
        excluded_dirs = ["nmb"]  

        if os.path.exists(log_dir):
            for session in sorted(os.listdir(log_dir)):
                if os.path.isdir(os.path.join(log_dir, session)) and session not in excluded_dirs:
                    self.log_sessions_combo.addItem(session)

        # Add NMB_output.log to the combo box if it exists
        nmb_log_file_path = os.path.join("logs", "nmb", "NMB_output.log")
        if os.path.exists(nmb_log_file_path):
            self.log_sessions_combo.addItem("NMB_output.log")

    def load_log_content(self, index):
        log_dir = os.path.join("logs")
        session_name = self.log_sessions_combo.itemText(index)
        bsti_log_file_path = os.path.join(log_dir, session_name, "BSTI.log")
        nmb_log_file_path = os.path.join("logs", "nmb", "NMB_output.log")

        log_content = ""

        # Load content from BSTI.log if it exists
        if os.path.exists(bsti_log_file_path):
            with open(bsti_log_file_path, 'r') as file:
                log_content += file.read()

        # Load content from NMB_output.log if it exists
        if session_name == "NMB_output.log" and os.path.exists(nmb_log_file_path):
            with open(nmb_log_file_path, 'r') as file:
                if log_content:
                    log_content += "----------------------------------------"
                log_content += file.read()

        if log_content:
            self.log_content_area.setText(log_content)
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
                    if os.path.isdir(session_path):
                        for log_file in os.listdir(session_path):
                            os.remove(os.path.join(session_path, log_file))
                        os.rmdir(session_path)
                    elif session == "nmb_output.log":
                        os.remove(session_path)
                self.populate_log_sessions_list() 
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

    def open_socks_ssh(self):
        drone_id = self.drone_selector.currentText()
        if not drone_id:
            QMessageBox.warning(self, "No Drone Selected", "Please select a drone first.")
            return

        host, username, password = self.get_current_drone_connection()
        if not host:
            QMessageBox.warning(self, "No Host Found", "The selected drone does not have a valid host address.")
            return

        port, ok = QInputDialog.getText(self, "Enter Port", "Enter SOCKS Proxy Port:")
        if not ok or not port.isdigit():
            QMessageBox.warning(self, "No Port Provided", "You must provide a valid port number.")
            return

        terminal_command = self.construct_ssh_command(host, username, f"-D {port}")
        self.execute_terminal_command(terminal_command, "socks")

    def open_portforward_ssh(self):
        drone_id = self.drone_selector.currentText()
        if not drone_id:
            QMessageBox.warning(self, "No Drone Selected", "Please select a drone first.")
            return

        host, username, password = self.get_current_drone_connection()
        if not host:
            QMessageBox.warning(self, "No Host Found", "The selected drone does not have a valid host address.")
            return

        port, ok = QInputDialog.getText(self, "Enter Port", "Enter Port Forwarding Port:")
        if not ok or not port.isdigit():
            QMessageBox.warning(self, "No Port Provided", "You must provide a valid port number.")
            return

        terminal_command = self.construct_ssh_command(host, username, f"-L {port}:localhost:{port}")
        self.execute_terminal_command(terminal_command, "portforward")


    def construct_ssh_command(self, host, username, options):
        return ["ssh", f"{options}", "-N", f"{username}@{host}"]

    def execute_terminal_command(self, terminal_command, tunnel_type):
        if terminal_command is None:
            return

        process = QProcess(self)
        process.setProcessChannelMode(QProcess.MergedChannels)
        process.started.connect(self.on_process_started)
        process.finished.connect(lambda exitCode, exitStatus: self.on_process_finished(exitCode, exitStatus, process))

        try:
            process.start(terminal_command[0], terminal_command[1:])
            if tunnel_type == "socks":
                self.socks_ssh_process = process
            elif tunnel_type == "portforward":
                self.portforward_ssh_process = process
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to start process: {e}")

    def on_process_started(self):
        QMessageBox.information(self, "SSH Tunnel", "SSH tunnel is now established...")

    def on_process_finished(self, exitCode, exitStatus, process):
        output = process.readAll().data().decode()
        if exitCode == 0:
            QMessageBox.information(self, "SSH Tunnel", "SSH tunnel closed.")
        else:
            QMessageBox.warning(self, "SSH Tunnel", f"SSH tunnel closed unexpectedly: {output}")

    def stop_socks_proxy(self):
        if self.socks_ssh_process and self.socks_ssh_process.state() != QProcess.NotRunning:
            self.socks_ssh_process.kill()
            QMessageBox.information(self, "SOCKS Proxy", "SOCKS proxy has been stopped.")
        else:
            QMessageBox.information(self, "SOCKS Proxy", "No active SOCKS proxy to stop.")

    def stop_portforward(self):
        if self.portforward_ssh_process and self.portforward_ssh_process.state() != QProcess.NotRunning:
            self.portforward_ssh_process.kill()
            QMessageBox.information(self, "Port Forward", "Local port forward has been stopped.")
        else:
            QMessageBox.information(self, "Port Forward", "No active local port forward to stop.")


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
                content += "# ARGS\n# ARG1 \"Example description\"\n# ENDARGS\n# AUTHOR: \n\n"
            elif filename.endswith(".sh"):
                content = "#!/bin/bash\n"
                content += "# ARGS\n# ARG1 \"Example description\"\n# ENDARGS\n# AUTHOR: \n\n"
            elif filename.endswith(".json"):
                content = json.dumps({
                    "grouped": True,
                    "tabs": [
                        {"name": "Windowname 1", "command": "echo 'test'"},
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
        remote_dir = self.upload_remote_path.text()

        # Extract the filename from the local path
        remote_filename = os.path.basename(local_path)
        # Combine the remote directory and filename
        remote_full_path = os.path.join(remote_dir, remote_filename).replace('\\', '/')
        
        # Use existing drone connection details
        host, username, password = self.get_current_drone_connection()
        if not self.is_valid_remote_path(host, username, password, remote_dir):
            QMessageBox.warning(self, "Invalid Path", "The specified remote path is invalid.")
            dialog.close()
            return

        try:
            if self.scp_transfer(host, username, password, remote_full_path, local_path, upload=True):
                QMessageBox.information(self, "Success", "File successfully uploaded.")
        except Exception as e:
            print(e)

        dialog.close()


    def download_file(self):
        dialog = WaitingDialog("Downloading file, please wait...", self)
        dialog.show()
        QApplication.processEvents()
        
        remote_path = self.download_file_path.text()
        local_path = self.download_local_path.text()

        # Normalize the local path for Windows
        local_path = os.path.normpath(local_path)

        # Use existing drone connection details
        host, username, password = self.get_current_drone_connection()
        if self.scp_transfer(host, username, password, remote_path, local_path, upload=False):
            QMessageBox.information(self, "Success", "File successfully downloaded.")
        else:
            QMessageBox.warning(self, "Error", "Failed to download the file.")

        dialog.close()

    def scp_transfer(self, host, username, password, remote_path, local_path, upload):
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
        except FileNotFoundError:
            print(f"File not found: {local_path}")
            return False
        except Exception as e:
            print(f"General Transfer Error: {e}")
            return False


    def get_current_drone_connection(self):
        try:
            drone_id = self.drone_selector.currentText()
            host, username, password = self.drones[drone_id]
            return host, username, password
        except KeyError:
            return None, None, None


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
        
    def on_drone_selected(self):
        if self.diagnostics_thread and self.diagnostics_thread.isRunning():
            self.diagnostics_thread.stop()

        host, username, password = self.get_current_drone_connection()
        if host:
            self.diagnostics_thread = DiagnosticThread(host, username, password)
            self.diagnostics_thread.diagnosticsUpdated.connect(self.update_diagnostics)
            self.diagnostics_thread.start()

    def init_diagnostics_ui(self):
        # Create a container for diagnostics
        self.diagnostics_container = QWidget()
        self.diagnostics_layout = QVBoxLayout(self.diagnostics_container)


        # System Status Display
        self.top_output_display = QTextEdit()
        self.top_output_display.setReadOnly(True)
        self.top_output_display.setStyleSheet(STYLESHEET_FOR_TEXTEDIT)

        # Network Status Label
        self.online_status_label = QLabel("Checking status...")
        self.online_status_label.setStyleSheet(LABEL_STYLESHEET)

        # Add widgets to diagnostics layout
        self.diagnostics_layout.addWidget(self.top_output_display)
        self.diagnostics_layout.addWidget(self.online_status_label)

        # Add the diagnostics container to the main layout
        self.home_layout.addWidget(self.diagnostics_container, 1, 0, 1, 2)


        host, username, password = self.get_current_drone_connection()
        self.diagnostics_thread = DiagnosticThread(host, username, password)
        self.diagnostics_thread.diagnosticsUpdated.connect(self.update_diagnostics)
        self.diagnostics_thread.start()
        self.home_layout.addWidget(self.diagnostics_container, 1, 0)

    def init_file_transfer_ui(self):
        # File Transfer setup
        self.file_transfer_container = QWidget()
        self.file_transfer_layout = QVBoxLayout(self.file_transfer_container)

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


        self.home_layout.addWidget(self.file_transfer_container, 1, 1)

    def update_diagnostics(self, top_output, ping_output):
        if top_output == "Connection Error":
            error_html = "<h3 style='color: #ff5555;'>System Status:</h3><pre>Connection Error: Unable to fetch system status.</pre>"
            self.top_output_display.setHtml(error_html)
            self.online_status_label.setText("<h3 style='color: #ff5555;'>BSTG Connection Status:</h3><p>Offline</p>")
        else:
            top_output_html = f"<h3 style='color: #8be9fd;'>System Status:</h3><pre>{top_output}</pre>"
            self.top_output_display.setHtml(top_output_html)

            online_status = "Online" if "time=" in ping_output else "Offline"
            online_status_html = f"<h3 style='color: #8be9fd;'>BSTG Connection Status:</h3><p>{online_status}</p>"
            self.online_status_label.setText(online_status_html)


    def add_home_cards(self):
        # Add cards for quick actions or information
        self.card_container = QWidget()
        self.card_layout = QGridLayout(self.card_container)

        card1 = QPushButton("BSTG Nessus")
        card1.setObjectName("CardButton")
        card1.setCursor(Qt.PointingHandCursor)
        card1.clicked.connect(self.open_current_drone_nessus)

        card2 = QPushButton("Plextrac")
        card2.setObjectName("CardButton")
        card2.setCursor(Qt.PointingHandCursor)
        card2.clicked.connect(lambda: self.on_card_click("https://report.kevlar.bulletproofsi.net/login"))

        # Add cards to the layout
        self.card_layout.addWidget(card1, 0, 0)
        self.card_layout.addWidget(card2, 0, 1)

        # Add the card container to the main layout
        self.home_layout.addWidget(self.card_container, 0, 0, 1, 2)

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
        nmb_tab_index = 2 # assumes NMB is index 2. Adjust as needed for other tabs
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
        self.drone_selector.clear()
        self.drones = load_config()
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

                    QMessageBox.information(self, "Configuration Saved", 
                                            f"Configuration for '{drone_id}' has been successfully saved.")


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

    def add_ssh_tab(self, host, username, password, command, is_script_path=True, nessus_finding_name=None, group_name="", group_color=None):        
        tab = QTextEdit()
        tab.setReadOnly(True)
        if group_color:
            tab.setStyleSheet(f"background-color: {group_color};")

        tab.is_ssh_tab = True

        # Prepare for logging
        session_id = f"{username}@{host}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
        # Store the Nessus finding name associated with this session ID
        if nessus_finding_name:
            self.nessus_findings_map[session_id] = nessus_finding_name

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
        close_button.setStyleSheet(CLOSE_BUTTON_STYLE)
        close_button.setFixedSize(16, 16)
        close_button.setToolTip("Close Tab")
        close_button.setProperty('tab_widget', tab)
        close_button.clicked.connect(self.close_tab_from_button)

        self.tab_widget.tabBar().setTabButton(self.tab_widget.indexOf(tab), QTabBar.RightSide, close_button)
        self.tab_widget.setCurrentIndex(index)
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
        try:
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

            if selected_module.endswith(('.py', '.sh')):
                args = ""
                nessus_finding_name = None
                file_paths = []

                args_dialog = CommandLineArgsDialog(module_path, host, username, password, self)
                if args_dialog.has_arguments():
                    if args_dialog.exec_() == QDialog.Accepted:
                        args, file_paths, nessus_finding_name = args_dialog.get_arguments()
                        if nessus_finding_name:
                            nessus_finding_name = nessus_finding_name.strip('# ').lower()

                full_command = (f"{module_path} {args}".strip(), file_paths)
                self.add_ssh_tab(host, username, password, full_command, is_script_path=True, nessus_finding_name=nessus_finding_name)

        except Exception:
            pass # catch all since errors are not handled here

    def open_tab_group(self, command, is_script_path=True, group_name=None, group_color=None):
        drone_id = self.drone_selector.currentText()
        host, username, password = self.drones[drone_id]
        self.add_ssh_tab(host, username, password, command, is_script_path, group_name, group_color)

            
    def closeEvent(self, event):
        for thread in self.threads:
            if thread.isRunning():
                thread.stop()
        super().closeEvent(event)


    def gather_screenshots(self, nessus_finding_name=None):
        def strip_ansi_codes(text):
            ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
            return ansi_escape.sub('', text)
        
        def consolidate_linebreaks(text):
            # Replace two or more consecutive linebreaks with a single linebreak
            return re.sub(r'\n{2,}', '\n', text)

        output = self.log_content_area.toPlainText()
        try:
        
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

            default_filename = "screenshot.png"
            if nessus_finding_name:
                default_filename = nessus_finding_name + ".png"
            else:
                session_name = self.log_sessions_combo.currentText()
                nessus_finding_name = self.nessus_findings_map.get(session_name)
                if nessus_finding_name:
                    default_filename = hashlib.md5(nessus_finding_name.encode()).hexdigest() + ".png"
                else:
                    default_filename = f"{session_name}.png"

            # Ask user to select save location
            options = QFileDialog.Options()
            options |= QFileDialog.DontUseNativeDialog
            save_path, _ = QFileDialog.getSaveFileName(self, "Save Screenshot", default_filename, "PNG Files (*.png)", options=options)

            if save_path:  # Check if a path was selected
                output_path = save_path if save_path.endswith('.png') else save_path + '.png'

                # Save the screenshot
                shot.create_pic(html=html_content, css=css, output=output_path)
                QMessageBox.information(self, "Screenshot Saved", f"Screenshot saved as {output_path}")
            else:
                QMessageBox.information(self, "Cancelled", "Screenshot save cancelled.")

            self.nessus_findings_map.pop(session_name, None)

        except Exception as e:
            QMessageBox.information(self, "Error", f"Unable to capture screenshot: {e}")

if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        app.setStyleSheet(DRACULA_STYLESHEET)
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec_())
    except:
        pass # don't handle the exceptions here
