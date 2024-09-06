# BSTI
# version: 1.2
# Authors: Connor Fancy

import csv
import sys
import os
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QTreeView, QToolBar, QVBoxLayout, QSlider, QFileSystemModel, QProgressBar, QStatusBar, QHeaderView, QGraphicsPixmapItem, QGroupBox, QCompleter, QListWidget, QSizePolicy, QSplitter, QMenu, QInputDialog, QDialogButtonBox, QTableWidget, QTableWidgetItem, QCheckBox, QLabel, QAction, QTabBar, QStyle, QPlainTextEdit, QMainWindow, QGridLayout, QHBoxLayout, QTabWidget, QTextEdit, QPushButton, QVBoxLayout, QWidget, QFileDialog, QLabel, QDialog, QLineEdit, QFormLayout, QMessageBox, QComboBox)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, QUrl, QRegExp, Qt, QProcess, QEvent, QPoint, QRectF, QSizeF
from PyQt5.QtGui import QTextCursor, QFont, QSyntaxHighlighter, QTextCharFormat, QColor, QDesktopServices, QPainter, QStandardItemModel
from PyQt5.QtGui import QTextCharFormat, QColor, QStandardItem, QPixmap, QTextDocument
from PyQt5.QtWidgets import (QGraphicsView, QGraphicsScene, QGraphicsItem, QGraphicsLineItem, 
                             QGraphicsTextItem, QGraphicsEllipseItem, QGraphicsRectItem, QGraphicsDropShadowEffect, QVBoxLayout, QWidget, QMenu, QAction, QInputDialog)
from PyQt5.QtCore import Qt, QPoint, QPointF, QLineF
from PyQt5.QtGui import QPen, QBrush, QColor, QLinearGradient, QImage
import paramiko
import requests
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
import py7zr
import zipfile
from io import StringIO

from mobsf.mobsf import Mobber
from mobsf.validator import XMLScreenshotTool


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
        self.scope_edit.addItems(["", "internal", "external", "web", "mobile" "surveillance"])

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

    def __init__(self, command_args, working_directory):
        super().__init__()
        self.command_args = command_args
        self.working_directory = working_directory

    def run(self):
        try:
            process = subprocess.Popen(self.command_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, cwd=self.working_directory)
            final_output = ''
            for line in process.stdout:
                final_output += line
                self.output_signal.emit(line)
            process.stdout.close()
            process.wait()
        except Exception as e:
            final_output = f"Failed to run Zeus: {str(e)}"
            self.output_signal.emit(final_output)


class MobSFConnectionCheckThread(QThread):
    connection_status = pyqtSignal(bool)

    def __init__(self, url):
        super().__init__()
        self.url = url

    def run(self):
        # Validate the MobSF URL in a separate thread
        is_connected = self.validate_mobsf_url(self.url)
        self.connection_status.emit(is_connected)

    def validate_mobsf_url(self, url):
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200 and "MobSF" in response.text:
                return True
            return False
        except requests.exceptions.RequestException:
            return False



class MobSFScanThread(QThread):
    progress = pyqtSignal(str)  # Signal for updating progress
    result_ready = pyqtSignal(list)  # Signal for sending results back to the main window

    def __init__(self, mobsf_url, app_path):
        super().__init__()
        self.mobsf_url = mobsf_url
        self.app_path = app_path

    def run(self):
        try:
            self.progress.emit("Starting scan...")

            # Initialize Mobber and run scan
            mobber = Mobber(mobsf_url=self.mobsf_url, app_path=self.app_path)
            self.progress.emit("Scan in progress...")

            # Run the scan
            scan_results = mobber.scan_file()
            if scan_results:
                self.progress.emit("Scan completed. Generating report...")
                mobber.generate_report()
                self.progress.emit("Report generated. Generating scorecard...")
                mobber.generate_scorecard()
                self.progress.emit("Scorecard generated.")

                # Extract and emit findings
                findings = mobber.parse_results()
                self.result_ready.emit(findings)
            else:
                self.progress.emit("Scan failed.")
        except Exception as e:
            self.progress.emit(f"Error occurred: {str(e)}")
          
          

class CommandNode(QGraphicsRectItem):
    def __init__(self, title, command, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.title = title
        self.command = command
        self.setRect(0, 0, 150, 80)  # Adjusted size
        self.setPen(QPen(QColor("#6272a4"), 2))
        
        # Gradient background
        gradient = QLinearGradient(0, 0, 0, 80)
        gradient.setColorAt(0, QColor("#44475a"))
        gradient.setColorAt(1, QColor("#343746"))
        self.setBrush(QBrush(gradient))
        
        # Add a shadow effect
        self.setGraphicsEffect(QGraphicsDropShadowEffect(blurRadius=10, color=QColor(0, 0, 0, 150), offset=QPointF(3, 3)))
        
        # Text
        self.text_item = QGraphicsTextItem(self.title, self)
        font = QFont("Arial", 10, QFont.Bold)
        self.text_item.setFont(font)
        self.text_item.setDefaultTextColor(QColor("#f8f8f2"))
        self.text_item.setPos(15, 25)  # Centered within the node

        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.ItemIsSelectable)  # Make the node selectable
        self.setFlag(QGraphicsItem.ItemIsFocusable)  # Make the node focusable

    def hoverEnterEvent(self, event):
        tooltip = f"Command: {self.command}"
        self.setToolTip(tooltip)
        self.setBrush(QBrush(QColor("#6272a4")))  # Change color on hover
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        gradient = QLinearGradient(0, 0, 0, 80)
        gradient.setColorAt(0, QColor("#44475a"))
        gradient.setColorAt(1, QColor("#343746"))
        self.setBrush(QBrush(gradient))  # Restore original color
        super().hoverLeaveEvent(event)

    def mouseDoubleClickEvent(self, event):
        # Trigger command editing on double-click
        editor = QInputDialog()
        new_command, ok = editor.getText(None, 'Edit Command', 'Enter the new command:', QLineEdit.Normal, self.command)
        if ok:
            self.command = new_command
            # Update the text item to reflect the change
            self.text_item.setPlainText(self.title + "\n" + new_command)
        super().mouseDoubleClickEvent(event)


class WorkflowEditor(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #282a36; color: #f8f8f2;")
        self.layout = QVBoxLayout(self)

        self.graphics_view = QGraphicsView()
        self.graphics_view.setStyleSheet("background-color: #44475a; border: 1px solid #6272a4;")
        self.scene = QGraphicsScene(self)
        self.graphics_view.setScene(self.scene)
        self.layout.addWidget(self.graphics_view)

        self.graphics_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.graphics_view.customContextMenuRequested.connect(self.show_context_menu)

        self.nodes = []  # To keep track of nodes in the correct order

    def add_command(self, title, command):
        node = CommandNode(title, command)
        node.setFlag(QGraphicsItem.ItemIsSelectable)  # Ensure node is selectable
        self.scene.addItem(node)
        self.nodes.append(node)
        self.update_node_positions()

    def show_context_menu(self, position: QPoint):
        menu = QMenu()
        
        add_action = QAction("Add Command", self)
        add_action.triggered.connect(self.add_command_dialog)
        menu.addAction(add_action)

        # Determine if we clicked on a node
        item = self.scene.itemAt(self.graphics_view.mapToScene(position), self.graphics_view.transform())
        
        if isinstance(item, CommandNode):
            # Right-clicked on a node
            move_up_action = QAction("Move Up", self)
            move_up_action.triggered.connect(lambda: self.move_node(item, -1))
            menu.addAction(move_up_action)
            
            move_down_action = QAction("Move Down", self)
            move_down_action.triggered.connect(lambda: self.move_node(item, 1))
            menu.addAction(move_down_action)

            delete_action = QAction("Delete Node", self)
            delete_action.triggered.connect(lambda: self.delete_node(item))
            menu.addAction(delete_action)

        menu.exec_(self.graphics_view.viewport().mapToGlobal(position))

    def add_command_dialog(self):
        title, ok = QInputDialog.getText(self, 'Add Command', 'Enter command title:')
        if ok and title:
            command, ok = QInputDialog.getText(self, 'Add Command', 'Enter the command:')
            if ok and command:
                self.add_command(title, command)

    def save_workflow(self):
        workflow_data = []
        for item in self.nodes:  # Use self.nodes to get order
            workflow_data.append({"title": item.title, "command": item.command})
        return {"commands": workflow_data}

    def load_workflow_from_file(self, workflow_data):
        self.scene.clear()  # Clear current nodes
        self.nodes = []
        for command in workflow_data.get('commands', []):
            self.add_command(command["title"], command["command"])  # Add in the order from JSON

    def move_node(self, node, direction):
        index = self.nodes.index(node)
        new_index = index + direction
        if 0 <= new_index < len(self.nodes):
            # Swap nodes in the list
            self.nodes[index], self.nodes[new_index] = self.nodes[new_index], self.nodes[index]
            # Reposition nodes based on the updated list
            self.update_node_positions()

    def update_node_positions(self):
        # Reposition nodes according to their order in self.nodes list
        for i, node in enumerate(self.nodes):
            node.setPos(50, 100 * i)  # Adjust positioning as needed

    def delete_node(self, node):
        self.scene.removeItem(node)
        self.nodes.remove(node)
        self.update_node_positions()


  
class CommandThread(QThread):
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, commands, log_file):
        super().__init__()
        self.commands = commands
        self.log_file = log_file

    def run(self):
        try:
            # Open the log file in append mode
            with open(self.log_file, 'a') as log_file:
                for command in self.commands:
                    # Log the command being executed
                    log_file.write(f"Executing: {command}\n")
                    # Run the command
                    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = process.communicate()

                    # Decode output
                    stdout_text = stdout.decode()
                    stderr_text = stderr.decode()

                    # Write stdout and stderr to the log file
                    if stdout_text:
                        log_file.write(stdout_text)
                    if stderr_text:
                        log_file.write(stderr_text)

                    # Emit signals to update the GUI
                    if stdout_text:
                        self.output_signal.emit(stdout_text)
                    if stderr_text:
                        self.error_signal.emit(stderr_text)
                    
        except Exception as e:
            self.error_signal.emit(f"Exception: {e}")




class DownloadThread(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    
    def __init__(self, url, download_path, parent=None):
        super().__init__(parent)
        self.url = url
        self.download_path = download_path

    def run(self):
        try:
            response = requests.get(self.url, stream=True)
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0

            # Define tools directory in current working directory
            tools_dir = os.path.join(os.getcwd(), 'tools')
            os.makedirs(tools_dir, exist_ok=True)
            self.download_path = os.path.join(tools_dir, os.path.basename(self.download_path))

            with open(self.download_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        file.write(chunk)
                        downloaded_size += len(chunk)
                        progress = int(downloaded_size / total_size * 100)
                        self.progress.emit(progress)
            
            # Handle different file types
            if self.download_path.endswith('.zip'):
                self.extract_zip(self.download_path)
            elif self.download_path.endswith('.7z'):
                self.extract_7z(self.download_path)
            else:
                # Make the binary executable if it's not an archive
                self.make_executable(self.download_path)
                
            self.finished.emit("Download completed successfully!")
        except Exception as e:
            self.finished.emit(f"Error: {str(e)}")

    def extract_zip(self, file_path):
        try:
            # Extract to a directory named after the file base name, with special handling for 'jadx.zip'
            if file_path.endswith('jadx-1.5.0.zip'):
                extract_dir = os.path.join(os.path.dirname(file_path), 'jadx')
            else:
                extract_dir = os.path.join(os.path.dirname(file_path), os.path.basename(file_path).replace('.zip', ''))
            
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)

            if platform.system() != 'Windows':
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        self.make_executable(file_path)

            # Delete the zip file after extraction
            os.remove(self.download_path)
        except Exception as e:
            self.finished.emit(f"Extraction Error: {str(e)}")

    def extract_7z(self, file_path):
        try:
            # Extract to a directory named after the file base name
            extract_dir = os.path.join(os.path.dirname(file_path), os.path.basename(file_path).replace('.7z', ''))
            os.makedirs(extract_dir, exist_ok=True)
            
            with py7zr.SevenZipFile(file_path, mode='r') as archive:
                archive.extractall(path=extract_dir)

            if platform.system() != 'Windows':
                for root, dirs, files in os.walk(extract_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        self.make_executable(file_path)

            # Delete the 7z file after extraction
            os.remove(self.download_path)
        except Exception as e:
            self.finished.emit(f"Extraction Error: {str(e)}")

    def make_executable(self, file_path):
        if platform.system() != 'Windows':
            os.chmod(file_path, 0o755)


class BinaryDownloadWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.initUI()

    def initUI(self):
        self.layout = QVBoxLayout()

        # Title label
        self.info_label = QLabel("Download Addons")
        self.info_label.setStyleSheet("font-size: 18px; font-weight: bold; color: #50fa7b;")
        self.layout.addWidget(self.info_label)

        # Platform selection
        self.platform_combo = QComboBox()
        self.platform_combo.addItems(["Select Platform", "Windows", "Linux"])
        self.layout.addWidget(self.platform_combo)

        # Form layout for addon download buttons
        self.form_layout = QFormLayout()
        self.layout.addLayout(self.form_layout)

        # Add buttons for each addon
        self.addon1_button = QPushButton("Download Zeus")
        self.addon2_button = QPushButton("Download apk-mitmv2")
        self.download_apktool_button = QPushButton("Download apktool")
        self.download_jadx_button = QPushButton("Download Jadx")
        self.download_drozer_button = QPushButton("Download Drozer-agent APK")

        self.form_layout.addRow(self.addon1_button)
        self.form_layout.addRow(self.addon2_button)
        self.form_layout.addRow(self.download_apktool_button)
        self.form_layout.addRow(self.download_jadx_button)
        self.form_layout.addRow(self.download_drozer_button)

        # Create a progress bar and label to show download progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #44475a;
                border-radius: 5px;
                background: #282a36;
            }
            QProgressBar::chunk {
                background: #bd93f9;
                width: 20px;
            }
        """)
        self.layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("font-size: 14px; color: #ff5555;")
        self.layout.addWidget(self.status_label)

        self.setLayout(self.layout)

        # Connect buttons to download methods
        self.addon1_button.clicked.connect(self.download_addon1)
        self.addon2_button.clicked.connect(self.download_addon2)
        self.download_apktool_button.clicked.connect(self.download_apktool)
        self.download_jadx_button.clicked.connect(self.download_jadx)
        self.download_drozer_button.clicked.connect(self.download_drozer)

    def get_platform_url(self, base_url):
        platform = self.platform_combo.currentText()
        if platform == "Windows":
            return base_url.replace("linux", "windows")
        elif platform == "Linux":
            return base_url
        else:
            self.status_label.setText("Please select a valid platform.")
            return None

    def download_addon1(self):
        url = self.get_platform_url('https://github.com/fancyc-bsi/ZEUS/releases/download/v0.1.0/zeus_linux_x64.7z')
        if url:
            self.start_download(url, 'zeus.7z')

    def download_addon2(self):
        url = self.get_platform_url('https://github.com/mavedirra-01/apk-mitmv2/releases/download/v1.0.0/apk-mitm-linux')
        if url:
            download_path = 'apk-mitm-windows.exe' if self.platform_combo.currentText() == "Windows" else 'apk-mitm-linux'
            self.start_download(url, download_path)
            
    def download_apktool(self):
        url = self.get_platform_url('https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar')
        if url:
            self.start_download(url, 'apktool.jar')

    def download_jadx(self):
        url = 'https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip'
        self.start_download(url, 'jadx-1.5.0.zip')

    def download_drozer(self):
        url = 'https://github.com/WithSecureLabs/drozer-agent/releases/download/3.1.0/drozer-agent.apk'
        self.start_download(url, 'drozer-agent.apk')

    def start_download(self, url, download_path):
        if not url:
            return
        
        self.download_thread = DownloadThread(url, download_path)
        self.download_thread.progress.connect(self.update_progress)
        self.download_thread.finished.connect(self.download_finished)
        self.download_thread.start()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def download_finished(self, message):
        self.status_label.setText(message)

        
        

class ScreenshotEditorTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        
        # Button to select the directory
        self.select_dir_button = QPushButton("Select Screenshot Directory")
        self.select_dir_button.clicked.connect(self.select_directory)
        self.layout.addWidget(self.select_dir_button)

        # QGraphicsView and Scene
        self.view = QGraphicsView()
        self.scene = QGraphicsScene()
        self.view.setScene(self.scene)
        self.layout.addWidget(self.view)
        
        # Navigation Buttons
        self.navigation_layout = QHBoxLayout()
        self.prev_button = QPushButton("Previous")
        self.prev_button.clicked.connect(self.show_prev_image)
        self.navigation_layout.addWidget(self.prev_button)
        
        self.next_button = QPushButton("Next")
        self.next_button.clicked.connect(self.show_next_image)
        self.navigation_layout.addWidget(self.next_button)
        
        self.layout.addLayout(self.navigation_layout)
        
        # Crop, Finalize, Draw Mode, and Save Buttons
        self.crop_button = QPushButton("Enter Crop Mode")
        self.crop_button.clicked.connect(self.toggle_crop_mode)
        self.layout.addWidget(self.crop_button)
        
        self.finalize_button = QPushButton("Finalize Crop")
        self.finalize_button.clicked.connect(self.finalize_crop)
        self.finalize_button.setDisabled(True)
        self.layout.addWidget(self.finalize_button)
        
        self.draw_mode_button = QPushButton("Enter Draw Mode")
        self.draw_mode_button.clicked.connect(self.toggle_draw_mode)
        self.layout.addWidget(self.draw_mode_button)
        
        self.save_button = QPushButton("Save Image")
        self.save_button.clicked.connect(self.save_image)
        self.layout.addWidget(self.save_button)
        
        # Rectangle Tool Slider
        self.rect_size_slider = QSlider(Qt.Horizontal)
        self.rect_size_slider.setMinimum(1)
        self.rect_size_slider.setMaximum(10)
        self.rect_size_slider.setValue(2)
        self.rect_size_slider.setTickPosition(QSlider.TicksBelow)
        self.rect_size_slider.setTickInterval(1)
        self.rect_size_slider.setToolTip("Rectangle Border Width")
        self.rect_size_slider.valueChanged.connect(self.update_rect_border_width)
        
        self.layout.addWidget(QLabel("Rectangle Border Width:"))
        self.layout.addWidget(self.rect_size_slider)
        
        # Initialize variables
        self.current_pixmap_item = None
        self.start_pos = None
        self.rect_item = None
        self.selected_item = None
        self.image_files = []
        self.current_index = 0
        self.crop_mode = False
        self.draw_mode = False
        self.moving_mode = False
        
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setRenderHint(QPainter.SmoothPixmapTransform)
        
        # Connect mouse events for drawing and moving rectangles
        self.view.mousePressEvent = self.mouse_press_event
        self.view.mouseMoveEvent = self.mouse_move_event
        self.view.mouseReleaseEvent = self.mouse_release_event

    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Screenshot Directory")
        if directory:
            self.image_files = [os.path.join(directory, f) for f in os.listdir(directory)
                                if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
            if self.image_files:
                self.current_index = 0
                self.load_image(self.image_files[self.current_index])

    def load_image(self, file_path):
        pixmap = QPixmap(file_path)
        self.display_image(pixmap)
        
    def display_image(self, pixmap):
        self.scene.clear()
        self.current_pixmap_item = QGraphicsPixmapItem(pixmap)
        self.scene.addItem(self.current_pixmap_item)
        
    def show_prev_image(self):
        if self.image_files:
            self.current_index = (self.current_index - 1) % len(self.image_files)
            self.load_image(self.image_files[self.current_index])

    def show_next_image(self):
        if self.image_files:
            self.current_index = (self.current_index + 1) % len(self.image_files)
            self.load_image(self.image_files[self.current_index])
    
    def mouse_press_event(self, event):
        if event.button() == Qt.LeftButton:
            pos = self.view.mapToScene(event.pos())
            if self.draw_mode or self.crop_mode:
                self.start_pos = pos
                self.rect_item = QGraphicsRectItem(QRectF())
                self.rect_item.setPen(QPen(Qt.red if self.draw_mode else Qt.blue, self.rect_size_slider.value()))  # Drawing or crop mode color
                self.scene.addItem(self.rect_item)
            elif self.moving_mode:
                self.selected_item = self.item_at_pos(pos)
                if self.selected_item:
                    self.start_pos = pos
                    self.selected_item.setZValue(1)  # Bring the item to the front

    def mouse_move_event(self, event):
        if self.start_pos:
            pos = self.view.mapToScene(event.pos())
            if self.rect_item:
                rect = QRectF(self.start_pos, pos).normalized()
                self.rect_item.setRect(rect)
            elif self.moving_mode and self.selected_item:
                if isinstance(self.selected_item, QGraphicsRectItem):
                    self.selected_item.setPos(self.selected_item.pos() + pos - self.start_pos)
                    self.start_pos = pos

    def mouse_release_event(self, event):
        if self.start_pos:
            pos = self.view.mapToScene(event.pos())
            if self.crop_mode and self.rect_item:
                rect = QRectF(self.start_pos, pos).normalized()
                self.rect_item.setRect(rect)
            self.start_pos = None
            if not self.crop_mode:  # Only reset rect_item if not in crop mode
                self.rect_item = None
            self.selected_item = None

    
    def toggle_crop_mode(self):
        self.crop_mode = not self.crop_mode
        self.draw_mode = False
        self.moving_mode = False
        if self.crop_mode:
            self.crop_button.setText("Exit Crop Mode")
            self.finalize_button.setEnabled(True)
            self.draw_mode_button.setEnabled(False)
        else:
            self.crop_button.setText("Enter Crop Mode")
            self.finalize_button.setDisabled(True)
            self.draw_mode_button.setEnabled(True)
            self.rect_item = None  # Reset only if exiting crop mode
        self.view.setCursor(Qt.CrossCursor if self.crop_mode else Qt.ArrowCursor)



    
    def finalize_crop(self):
        try:

            if self.crop_mode and self.rect_item:
                rect = self.rect_item.rect().toRect()


                if not rect.isEmpty():
                    # Get pixmap
                    pixmap = self.current_pixmap_item.pixmap()
                    pixmap_rect = pixmap.rect()

                    if not rect.intersects(pixmap_rect):
                        return

                    # Ensure the rectangle is within pixmap bounds
                    rect = rect.intersected(pixmap_rect)
                    cropped_pixmap = pixmap.copy(rect)

                    # Remove old pixmap item
                    self.scene.removeItem(self.current_pixmap_item)

                    # Add new pixmap item
                    self.current_pixmap_item = QGraphicsPixmapItem(cropped_pixmap)
                    self.scene.addItem(self.current_pixmap_item)

                    # Update scene rect to fit new image size
                    self.view.setSceneRect(self.current_pixmap_item.pixmap().rect())

                # Reset rectangle item
                self.rect_item = None
                self.toggle_crop_mode()
        except Exception as e:
            print(f"Error in finalize_crop: {e}")



    def toggle_draw_mode(self):
        self.draw_mode = not self.draw_mode
        self.crop_mode = False
        self.moving_mode = False
        if self.draw_mode:
            self.draw_mode_button.setText("Exit Draw Mode")
        else:
            self.draw_mode_button.setText("Enter Draw Mode")
        self.view.setCursor(Qt.CrossCursor if self.draw_mode else Qt.ArrowCursor)

    def update_rect_border_width(self):
        if self.rect_item:
            self.rect_item.setPen(QPen(Qt.red if self.draw_mode else Qt.blue, self.rect_size_slider.value()))
    
    def save_image(self):
        if self.current_pixmap_item:
            file_path, _ = QFileDialog.getSaveFileName(self, "Save Image", "", "PNG Files (*.png);;JPEG Files (*.jpg *.jpeg)")
            if file_path:
                pixmap = self.current_pixmap_item.pixmap().copy()
                painter = QPainter(pixmap)
                pen_color = Qt.red if self.draw_mode else Qt.blue
                for item in self.scene.items():
                    if isinstance(item, QGraphicsRectItem):
                        pen = QPen(pen_color, self.rect_size_slider.value())
                        painter.setPen(pen)
                        painter.drawRect(item.rect())
                painter.end()
                pixmap.save(file_path)

    def item_at_pos(self, pos):
        # Find and return the item under the given position
        items = self.scene.items(pos)
        for item in items:
            if isinstance(item, QGraphicsRectItem):
                return item
        return None
    
    

class XmlHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super(XmlHighlighter, self).__init__(document)
        
        # Dracula theme colors
        self.xml_tag_format = QTextCharFormat()
        self.xml_tag_format.setForeground(QColor("#ff79c6"))  # Pinkish color for tags

        self.xml_attribute_format = QTextCharFormat()
        self.xml_attribute_format.setForeground(QColor("#8be9fd"))  # Cyan for attributes

        self.xml_value_format = QTextCharFormat()
        self.xml_value_format.setForeground(QColor("#f1fa8c"))  # Yellow for values

        self.xml_comment_format = QTextCharFormat()
        self.xml_comment_format.setForeground(QColor("#6272a4"))  # Purple-gray for comments
        self.xml_comment_format.setFontItalic(True)

        # Regex patterns
        self.tag_pattern = re.compile(r'<\/?\w+')
        self.attribute_pattern = re.compile(r'\s+\w+\s*=')
        self.value_pattern = re.compile(r'\"[^\"]*\"')
        self.comment_pattern = re.compile(r'<!--[^-]*-->')

    def highlightBlock(self, text):
        for pattern, _format in [(self.tag_pattern, self.xml_tag_format),
                                 (self.attribute_pattern, self.xml_attribute_format),
                                 (self.value_pattern, self.xml_value_format),
                                 (self.comment_pattern, self.xml_comment_format)]:
            for match in pattern.finditer(text):
                start, end = match.span()
                self.setFormat(start, end - start, _format)


class ValidatorRunner(QThread):
    output_received = pyqtSignal(str)
    finished = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, xml_file, output_dir, parent=None):
        super().__init__(parent)
        self.xml_file = xml_file
        self.output_dir = output_dir

    def run(self):
        # Capture stdout
        old_stdout = sys.stdout
        new_stdout = StringIO()
        sys.stdout = new_stdout

        try:
            # Instantiate and run the engine method of XMLScreenshotTool
            tool = XMLScreenshotTool(self.xml_file, 'validator.json', self.output_dir)
            tool.process_screenshots()

            # Emit the output line by line
            new_stdout.seek(0)
            for line in new_stdout:
                if line.strip():  # Emit only non-empty lines
                    self.output_received.emit(line.strip())

            # Emit a final message to indicate completion
            self.finished.emit()
        except Exception as e:
            # Restore original stdout in case of an exception
            sys.stdout = old_stdout
            # Emit error message
            self.error_occurred.emit(str(e))
        finally:
            # Restore original stdout
            sys.stdout = old_stdout



class APKLeaksThread(QThread):
    result_signal = pyqtSignal(str)

    def __init__(self, apk_file, parent=None):
        super().__init__(parent)
        self.apk_file = apk_file
        self.args = None

    def run(self):
        from apkleaks.cli import run_apkleaks

        output_file = None 
        pattern_file = None
        json_output = True

        try:
            output_file_path = run_apkleaks(
                self.apk_file,
                output=output_file,
                pattern=pattern_file,
                args=self.args,
                json_output=json_output
            )
            
            # Read the results from the output file
            if output_file_path and os.path.exists(output_file_path):
                with open(output_file_path, 'r') as file:
                    results = file.read()
            else:
                results = "No results available or output file not found."
            
        except Exception as e:
            results = f"An error occurred: {str(e)}"
        
        self.result_signal.emit(results)


class ExplorerSubTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)

        # File selection button
        self.select_apk_button = QPushButton("Select APK")
        self.select_apk_button.clicked.connect(self.select_apk)
        self.style_button(self.select_apk_button)
        self.layout.addWidget(self.select_apk_button)

        # Decompile button
        self.decompile_button = QPushButton("Decompile APK")
        self.decompile_button.clicked.connect(self.decompile_selected_apk)
        self.decompile_button.setEnabled(False)
        self.style_button(self.decompile_button)
        self.layout.addWidget(self.decompile_button)

        # File tree view
        self.tree_view = QTreeView()
        self.style_tree_view(self.tree_view)
        self.layout.addWidget(self.tree_view)
        self.layout.setStretch(2, 1)  # Full stretch for the tree view
        self.tree_view.header().setSectionResizeMode(QHeaderView.Stretch)

        # QFileSystemModel for directory structure
        self.file_system_model = QFileSystemModel()
        self.file_system_model.setReadOnly(False)
        self.tree_view.setModel(self.file_system_model)
        self.tree_view.doubleClicked.connect(self.open_file_editor)

        # Thread setup for decompiling APK
        self.decompile_thread = None
        self.selected_apk_path = None

        # Status label
        self.status_label = QLabel("Status: Ready")
        self.style_status_label(self.status_label)
        self.layout.addWidget(self.status_label)

    def style_button(self, button):
        button.setCursor(Qt.PointingHandCursor)
        button.setStyleSheet("""
            QPushButton {
                background-color: #6272a4;
                color: #f8f8f2;
                border-radius: 5px;
                padding: 5px 10px;
                font-weight: bold;
            }
            QPushButton:disabled {
                background-color: #44475a;
                color: #8b8b8b;
            }
            QPushButton:hover {
                background-color: #7b82c4;
            }
            QPushButton:pressed {
                background-color: #52588e;
            }
        """)

    def style_tree_view(self, tree_view):
        tree_view.setStyleSheet("""
            QTreeView {
                background-color: #282a36;
                color: #f8f8f2;
                font-family: 'Courier New';
                font-size: 12pt;
                border: 1px solid #44475a;
            }
            QTreeView::item:hover {
                background-color: #44475a;
            }
            QTreeView::item:selected {
                background-color: #6272a4;
            }
        """)

    def style_status_label(self, label):
        label.setStyleSheet("""
            QLabel {
                font-size: 14pt;
                font-weight: bold;
                color: #f8f8f2;
                padding: 5px;
                background-color: #44475a;
                border-radius: 5px;
            }
        """)

    def update_status(self, message, color="#44475a"):
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"""
            QLabel {{
                font-size: 14pt;
                font-weight: bold;
                color: #f8f8f2;
                padding: 5px;
                background-color: {color};
                border-radius: 5px;
            }}
        """)

    def select_apk(self):
        apk_path, _ = QFileDialog.getOpenFileName(self, "Select APK File", "", "APK Files (*.apk)")
        if apk_path:
            self.selected_apk_path = apk_path
            self.decompile_button.setEnabled(True)
            self.select_apk_button.setText(f"Selected: {os.path.basename(apk_path)}")
            self.update_status(f"Status: {os.path.basename(apk_path)} selected", "#5e8b7e")  # green

    def decompile_selected_apk(self):
        if self.selected_apk_path:
            self.update_status("Status: Decompiling...", "#ffb86c")  # orange
            apk_name = os.path.splitext(os.path.basename(self.selected_apk_path))[0]
            output_dir = os.path.join("decompiled", apk_name)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            self.start_decompile(self.selected_apk_path, output_dir)
            self.decompile_button.setText("Decompiling...")


    def on_decompilation_complete(self, output_dir):
        self.display_decompiled_files(output_dir)
        self.decompile_button.setEnabled(True)
        self.decompile_button.setText("Decompile APK")
        self.update_status("Status: Decompilation Complete", "#50fa7b")  # green

    def display_decompiled_files(self, output_dir):
        # Set the root path to the output directory
        if os.path.exists(output_dir):
            self.file_system_model.setRootPath(output_dir)
            self.tree_view.setRootIndex(self.file_system_model.index(output_dir))
            self.status_label.setText("Status: Showing Decompiled Code")
        else:
            self.update_status("Status: Decompiled code not found", "#ff5555")  # red


    def start_decompile(self, apk_path, output_dir):
        # Detect the OS
        if platform.system() == "Windows":
            # Path to apktool and jadx for Windows
            apktool_path = os.path.join('tools', 'apktool.jar')
            jadx_path = os.path.join('tools', 'jadx', 'bin', 'jadx.bat')
        else:
            # Path to apktool and jadx for Linux/Mac
            apktool_path = os.path.join('tools', 'apktool.jar')
            jadx_path = os.path.join('tools', 'jadx', 'bin', 'jadx')

        # Check if apktool exists
        if not os.path.isfile(apktool_path):
            QMessageBox.warning(
                self,
                "Missing APKTool",
                "The file 'apktool.jar' is missing. Please use the 'addons' option in the top bar to download it.",
                QMessageBox.Ok
            )
            return

        # Check if jadx exists
        if not os.path.isfile(jadx_path):
            QMessageBox.warning(
                self,
                "Missing Jadx",
                "The Jadx binary is missing. Please use the 'addons' option in the top bar to download it.",
                QMessageBox.Ok
            )
            return

        # Start the decompilation process
        self.decompile_button.setEnabled(False)
        self.decompile_thread = DecompileThread(apk_path, output_dir, apktool_path, jadx_path)
        self.decompile_thread.decompiled.connect(self.on_decompilation_complete)
        self.decompile_thread.start()

    def open_file_editor(self, index):
        file_path = self.file_system_model.filePath(index)
        if os.path.isfile(file_path):
            editor = FileEditorDialog(file_path)
            editor.exec_()



class DecompileThread(QThread):
    decompiled = pyqtSignal(str)

    def __init__(self, apk_path, output_dir, apktool_path, jadx_path):
        super().__init__()
        self.apk_path = apk_path
        self.output_dir = output_dir
        self.apktool_path = apktool_path
        self.jadx_path = jadx_path

    def run(self):
        # Decompile Smali using apktool
        smali_output_dir = os.path.join(self.output_dir, 'apktool')
        os.makedirs(smali_output_dir, exist_ok=True)
        subprocess.run(
            ['java', '-jar', self.apktool_path, 'd', self.apk_path, '-o', smali_output_dir, '-f'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Decompile Java using jadx
        java_output_dir = os.path.join(self.output_dir, 'jadx')
        os.makedirs(java_output_dir, exist_ok=True)
        subprocess.run(
            [self.jadx_path, '-d', java_output_dir, self.apk_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        self.decompiled.emit(self.output_dir)



class FileEditorDialog(QDialog):
    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self.setWindowTitle(f"Editing: {os.path.basename(file_path)}")
        self.resize(1200, 800)  # Set default size for the editor

        # Setup the text editor
        self.text_edit = QTextEdit(self)
        with open(file_path, 'r') as file:
            self.text_edit.setText(file.read())

        # Setup the save button
        save_button = QPushButton("Save", self)
        save_button.clicked.connect(self.save_changes)

        # Setup the dialog layout
        layout = QVBoxLayout(self)
        layout.addWidget(self.text_edit)
        layout.addWidget(save_button)

    def save_changes(self):
        # Save the changes to the file
        with open(self.file_path, 'w') as file:
            file.write(self.text_edit.toPlainText())
        self.accept()



class DrozerThread(QThread):
    output_signal = pyqtSignal(str)

    def __init__(self, command):
        super().__init__()
        self.command = command

    def run(self):
        """Execute the Drozer command in a separate thread."""
        try:
            process = subprocess.Popen(self.command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            # Combine stdout and stderr and decode to strings
            output = stdout.decode() + stderr.decode()

            # Convert ANSI escape codes to HTML
            formatted_output = self.ansi_to_html(output)

            # Emit the formatted output
            self.output_signal.emit(formatted_output)
        except Exception as e:
            self.output_signal.emit(f"Error: {str(e)}")

    def ansi_to_html(self, text):
        """Converts ANSI color codes to HTML span tags for QTextEdit display."""
        ansi_to_html_map = {
            '\033[91m': '<span style="color:#ff5555;">',  # Red
            '\033[92m': '<span style="color:#50fa7b;">',  # Green
            '\033[93m': '<span style="color:#f1fa8c;">',  # Yellow
            '\033[94m': '<span style="color:#6272a4;">',  # Blue
            '\033[95m': '<span style="color:#bd93f9;">',  # Magenta
            '\033[0m': '</span>'  # Reset
        }

        for ansi, html in ansi_to_html_map.items():
            text = text.replace(ansi, html)

        # Replace newline with <br> for HTML display
        text = text.replace('\n', '<br>')
        return f"<pre>{text}</pre>"  # Use <pre> to preserve spacing





class ConnectionHeartbeat(QThread):
    status_signal = pyqtSignal(bool)

    def __init__(self, check_function):
        super().__init__()
        self.check_function = check_function
        self.running = True

    def run(self):
        """Periodically check the connection status."""
        while self.running:
            connected = self.check_function()
            self.status_signal.emit(connected)
            QThread.sleep(5)  # Check every 5 seconds

    def stop(self):
        """Stop the heartbeat check."""
        self.running = False


class DrozerTab:
    def __init__(self, parent):
        self.parent = parent
        self.package = ""
        self.drozer_commands = []
        self.command_help = {}
        self.screenshot_path = "output_screenshot.png"
        self.heartbeat = ConnectionHeartbeat(self.check_drozer_connection)
        self.heartbeat.status_signal.connect(self.update_status_bar)
        self.heartbeat.start()
        self.load_drozer_commands()
        self.setup_drozer_tab()
        self.apply_dracula_theme()

    def load_drozer_commands(self):
        """Load Drozer commands and their help text from a JSON file."""
        json_path = os.path.join("json", "drozer_commands.json")
        try:
            with open(json_path, "r") as file:
                data = json.load(file)
                self.drozer_commands = ["Select a command..."] + [cmd["command"] for cmd in data.get("commands", [])]
                self.command_help = {cmd["command"]: cmd["help"] for cmd in data.get("commands", [])}
        except FileNotFoundError:
            self.drozer_commands = ["Select a command..."]
            self.command_help = {}
            print("Warning: 'drozer_commands.json' file not found. Using default commands.")
        except json.JSONDecodeError:
            self.drozer_commands = ["Select a command..."]
            self.command_help = {}
            print("Error: Failed to decode 'drozer_commands.json'. Using default commands.")

    def execute_drozer_command(self):
        """Execute the selected Drozer command with placeholder prompts."""
        selected_command = self.command_combobox.currentText()
        if selected_command == "Select a command...":
            self.output_area.append("Please select a valid command.")
            return

        # Find placeholders in the command (e.g., {package}, {uri}, etc.)
        placeholders = re.findall(r'\{(.*?)\}', selected_command)
        replacements = {}

        # Replace {package} if it's set
        if "package" in placeholders and not self.package:
            self.output_area.append("Please set the package before executing a command.")
            return
        replacements['package'] = self.package

        # Prompt the user to fill in values for other placeholders (e.g., {uri}, {ip}, {port})
        for placeholder in placeholders:
            if placeholder != 'package':  # Skip package as it's handled
                value, ok = QInputDialog.getText(self.drozer_tab, f"Enter {placeholder}",
                                                 f"Please provide a value for {placeholder}:")
                if ok and value:
                    replacements[placeholder] = value
                else:
                    self.output_area.append(f"Execution canceled: No value provided for {placeholder}.")
                    return

        # Replace placeholders with actual values in the command
        command = selected_command.format(**replacements)
        full_command = f"drozer console connect -c 'run {command}'"

        # Clear the output area before running the next command
        self.output_area.clear()
        self.output_area.append(f"Executing: {full_command}")

        # Run the command in a separate thread
        self.drozer_thread = DrozerThread(full_command)
        self.drozer_thread.output_signal.connect(self.handle_command_output)
        self.drozer_thread.start()

    def setup_drozer_tab(self):
        """Create the layout for the Drozer connection tab."""
        self.drozer_tab = QWidget()
        self.drozer_layout = QVBoxLayout(self.drozer_tab)

        # Status Bar
        self.status_bar = QStatusBar()
        self.status_label = QLabel("Checking connection...")
        self.status_bar.addWidget(self.status_label)
        self.drozer_layout.addWidget(self.status_bar)

        # Create group for package selection
        package_group = QGroupBox("Package Selection")
        package_layout = QFormLayout()

        self.package_input = QLineEdit()
        self.package_input.setPlaceholderText("Enter target package (e.g., com.example.app)")
        package_layout.addRow("Target Package:", self.package_input)

        self.set_package_button = QPushButton("Set Package")
        self.set_package_button.clicked.connect(self.set_package)
        package_layout.addRow(self.set_package_button)

        package_group.setLayout(package_layout)
        self.drozer_layout.addWidget(package_group)

        # Create group for command selection
        command_group = QGroupBox("Drozer Command")
        command_layout = QVBoxLayout()

        self.command_combobox = QComboBox()
        self.command_combobox.addItems(self.drozer_commands)
        self.command_combobox.currentIndexChanged.connect(self.update_command_help)
        command_layout.addWidget(self.command_combobox)

        self.command_help_text = QTextEdit()
        self.command_help_text.setReadOnly(True)
        command_layout.addWidget(self.command_help_text)

        self.execute_button = QPushButton("Execute Command")
        self.execute_button.clicked.connect(self.execute_drozer_command)
        command_layout.addWidget(self.execute_button)

        command_group.setLayout(command_layout)
        self.drozer_layout.addWidget(command_group)

        # Output area
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.drozer_layout.addWidget(self.output_area)

        # Screenshot button
        self.screenshot_button = QPushButton("Take Screenshot of Output")
        self.screenshot_button.clicked.connect(self.select_screenshot_path)
        self.drozer_layout.addWidget(self.screenshot_button)

        self.parent.subtab_widget.addTab(self.drozer_tab, "Drozer")

    def apply_dracula_theme(self):
        """Apply the Dracula theme to the widgets."""
        theme_colors = {
            "background": "#282a36",
            "text": "#f8f8f2",
            "button_bg": "#44475a",
            "button_text": "#f8f8f2",
            "highlight": "#bd93f9"
        }
        
        self.drozer_tab.setStyleSheet(f"""
            QWidget {{
                background-color: {theme_colors['background']};
                color: {theme_colors['text']};
            }}
            QPushButton {{
                background-color: {theme_colors['button_bg']};
                color: {theme_colors['button_text']};
                border: 1px solid {theme_colors['highlight']};
            }}
            QPushButton:hover {{
                background-color: {theme_colors['highlight']};
            }}
            QLineEdit {{
                background-color: {theme_colors['button_bg']};
                color: {theme_colors['text']};
                border: 1px solid {theme_colors['highlight']};
            }}
            QTextEdit {{
                background-color: {theme_colors['button_bg']};
                color: {theme_colors['text']};
                border: 1px solid {theme_colors['highlight']};
            }}
            QComboBox {{
                background-color: {theme_colors['button_bg']};
                color: {theme_colors['text']};
                border: 1px solid {theme_colors['highlight']};
            }}
        """)

    def check_drozer_connection(self):
        """Check if Drozer is connected."""
        try:
            # Placeholder command to check connection status
            result = subprocess.run("drozer console connect -c 'run some_command'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0
        except Exception as e:
            print(f"Error checking Drozer connection: {e}")
            return False

    def update_status_bar(self, connected):
        """Update the status bar with the connection status."""
        if connected:
            self.status_label.setText("Drozer is connected.")
            self.status_label.setStyleSheet("color: #50fa7b;")  # Green
        else:
            self.status_label.setText("Drozer is not connected.")
            self.status_label.setStyleSheet("color: #ff5555;")  # Red

    def update_command_help(self):
        """Update the command help text based on the selected command."""
        selected_command = self.command_combobox.currentText()
        help_text = self.command_help.get(selected_command, "No help available for this command.")
        self.command_help_text.setPlainText(help_text)

    def set_package(self):
        """Set the selected package for Drozer commands."""
        self.package = self.package_input.text().strip()
        if self.package:
            self.output_area.append(f"Package set to: {self.package}")
        else:
            self.output_area.append("Please enter a valid package name.")


    def handle_command_output(self, output):
        """Handle the output from the Drozer command."""
        self.output_area.append(output)  # Append the HTML-formatted text
        self.output_area.ensureCursorVisible()  # Ensure new output is scrolled into view


    def select_screenshot_path(self):
        """Allow user to select the file path for the screenshot."""
        file_path, _ = QFileDialog.getSaveFileName(self.drozer_tab, "Save Screenshot As", self.screenshot_path,
                                                   "PNG Images (*.png);;All Files (*)")
        if file_path:
            self.screenshot_path = file_path
            self.take_screenshot()

    def take_screenshot(self):
        """Take a screenshot of the output area."""
        if not os.path.exists(os.path.dirname(self.screenshot_path)):
            os.makedirs(os.path.dirname(self.screenshot_path))
        screenshot = self.output_area.grab()
        screenshot.save(self.screenshot_path)
        self.output_area.append(f"Screenshot saved as '{self.screenshot_path}'.")

    def closeEvent(self, event):
        """Ensure to stop the heartbeat thread when closing the tab."""
        self.heartbeat.stop()
        self.heartbeat.wait()
        super().closeEvent(event)




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
        self.validator_thread = None
        self.report_id = None
        self.nessus_findings_map = {}
        self.setWindowTitle("BSTI")
      
        screen = QApplication.primaryScreen()
        screen_geometry = screen.geometry()
        available_geometry = screen.availableGeometry()
        taskbar_height = screen_geometry.height() - available_geometry.height()
        self.setGeometry(0, 0, available_geometry.width(), available_geometry.height() - taskbar_height)
        self.threads = []
        
        # mobsf -> normalized
        self.severity_map = {
            "High": "Medium",
            "Warning": "Low",
            "Info": "Informational"
        }

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
        
        # Download binaries menu
        self.binary_menu = self.menu_bar.addMenu("Addons")
        self.binary_menu_action = QAction("Download additional tools")
        self.binary_menu_action.triggered.connect(self.open_binary_download_menu)
        self.binary_menu.addAction(self.binary_menu_action)

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

        # added zeus tab
        self.setup_zeus_tab()
        
        # Mobile testing tab
        self.setup_mobile_testing_tab()
        
        # Adding the Screenshot Editor tab
        self.screenshot_editor_tab = ScreenshotEditorTab()
        # self.tab_widget.addTab(self.screenshot_editor_tab, "Screenshot Editor") hiding for now #FIXME
        self.screenshot_editor_tab.is_custom_tab = True

        
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
        
    def open_binary_download_menu(self):
        download_widget = BinaryDownloadWidget()
        
        download_widget.is_custom_tab = True
        tab_index = self.tab_widget.addTab(download_widget, "Download Addons")
        
        # Add close button to the download tab
        self.add_close_button_to_tab(download_widget, tab_index)

        self.tab_widget.setCurrentIndex(tab_index)
        
        
        
    def setup_mobile_testing_tab(self):
        # load mapping from mobsf names to pluginIDS
        self.plugin_id_mapping = {} 
        self.load_plugin_id_mapping("mobsf.json")
        
        # Load common false positives from file
        self.load_common_false_positives("false_positives.txt")

        # Create the mobile pentesting tab
        self.mobile_tab = QWidget()
        self.mobile_tab.is_custom_tab = True
        self.mobile_layout = QVBoxLayout(self.mobile_tab)

        # Create a subtab widget
        self.subtab_widget = QTabWidget(self.mobile_tab)
        self.mobile_layout.addWidget(self.subtab_widget)

        # Automated Testing Subtab
        self.automated_tab = QWidget()
        self.automated_layout = QVBoxLayout(self.automated_tab)

        # File selection group box
        file_group = QGroupBox("File Selection")
        file_group_layout = QFormLayout()
        self.file_selection_label = QLabel("Choose IPA/APK file:")
        self.file_selection_button = QPushButton("Browse...")
        self.file_selection_button.clicked.connect(self.select_file)
        self.selected_file_label = QLabel("No file selected")

        # Improve font readability
        font = self.file_selection_label.font()
        font.setPointSize(12)
        self.file_selection_label.setFont(font)
        self.file_selection_button.setFont(font)
        self.selected_file_label.setFont(font)

        file_group_layout.addRow(self.file_selection_label, self.file_selection_button)
        file_group_layout.addRow(self.selected_file_label)
        file_group.setLayout(file_group_layout)
        self.automated_layout.addWidget(file_group)

        # MobSF connection group box
        mobsf_group = QGroupBox("MobSF Connection")
        mobsf_group_layout = QFormLayout()
        self.mobsf_label = QLabel("MobSF Instance URL:")
        self.mobsf_url_input = QLineEdit()
        self.mobsf_url_input.setPlaceholderText("Enter MobSF instance URL")

        self.load_saved_mobsf_url()

        self.connect_mobsf_button = QPushButton("Start Scan")
        self.connect_mobsf_button.clicked.connect(self.run_mobsf_scan)

        # Improve font readability
        self.mobsf_label.setFont(font)
        self.mobsf_url_input.setFont(font)
        self.connect_mobsf_button.setFont(font)

        mobsf_group_layout.addRow(self.mobsf_label, self.mobsf_url_input)
        mobsf_group_layout.addRow(self.connect_mobsf_button)

        # Add status bar
        self.status_label = QLabel()
        self.status_label.setFont(QFont('Arial', 12, QFont.Bold))  # Bold font
        self.status_label.setStyleSheet("color: #ff5555;")  # Red color for visibility
        self.status_label.setText("Scanner: Ready")

        mobsf_group_layout.addRow(self.status_label)
        mobsf_group.setLayout(mobsf_group_layout)
        self.automated_layout.addWidget(mobsf_group)

        # Results table widget
        results_widget = QWidget()
        results_layout = QVBoxLayout(results_widget)

        # Create and style the results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(3)
        self.results_table.setHorizontalHeaderLabels(["Finding", "Severity", "Common False Positive"])

        # Apply Dracula theme styles
        self.results_table.setStyleSheet("""
            QTableWidget {
                background-color: #282a36;
                color: #f8f8f2;
            }
            QHeaderView::section {
                background-color: #44475a;
                color: #f8f8f2;
            }
            QTableWidget::item {
                border: 1px solid #44475a;
            }
            QTableWidget::item:selected {
                background-color: #6272a4;
            }
        """)

        # Ensure the results table expands to fill available space
        self.results_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.results_table.horizontalHeader().setStretchLastSection(True)

        # Set all columns to stretch to fill available space
        for i in range(self.results_table.columnCount()):
            self.results_table.horizontalHeader().setSectionResizeMode(i, QHeaderView.Stretch)

        # Add the results table to the results widget
        results_layout.addWidget(self.results_table)

        # Add the results widget to the layout
        self.automated_layout.addWidget(results_widget)

        # Bottom bar for exporting and resetting
        bottom_bar = QHBoxLayout()

        self.export_button = QPushButton("Export Report")
        self.export_button.clicked.connect(self.export_report)
        bottom_bar.addWidget(self.export_button)

        self.reset_button = QPushButton("Reset Changes")
        self.reset_button.clicked.connect(self.reset_changes)
        bottom_bar.addWidget(self.reset_button)

        # Add the bottom bar to the layout
        self.automated_layout.addLayout(bottom_bar)

        # Set stretch factors to ensure the table uses available space
        self.automated_layout.setStretchFactor(file_group, 0)
        self.automated_layout.setStretchFactor(mobsf_group, 0)
        self.automated_layout.setStretchFactor(results_widget, 1)

        # Adjust row heights dynamically based on content
        self.results_table.resizeRowsToContents()

        # Initialize exclusions set
        self.excluded_items = set()

        # Initialize original data storage
        self.original_data = []

        self.start_mobsf_heartbeat()

        # Add context menu for results table
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self.show_context_menu)

        # Add Automated Testing subtab
        self.subtab_widget.addTab(self.automated_tab, "Automated Testing")

        self.setup_objection_tab()

        self.subtab_widget.addTab(self.objection_tab, "Workflows")
        
        # Add "Decompiler" Subtab
        self.decompiler_tab = QWidget()
        self.decompiler_layout = QVBoxLayout(self.decompiler_tab)

        # Create a plain text edit for displaying XML
        self.xml_display = QTextEdit(self)
        self.xml_display.setReadOnly(True)
        self.xml_display.setStyleSheet("""
            QTextEdit {
                background-color: #282a36;
                color: #f8f8f2;
                font-family: 'Courier New';
                font-size: 12pt;
                border: 1px solid #44475a; 
                padding: 10px;
            }
        """)


        self.decompiler_layout.addWidget(self.xml_display)
        
        self.search_results = []  # List to store search results
        self.current_result_index = -1  # Index of the current search result

        

        # Create a search bar
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search in XML...")
        self.search_bar.setStyleSheet("""
            QLineEdit {
                background-color: #44475a; 
                color: #f8f8f2;
                font-family: 'Courier New';
                font-size: 12pt;
                border: 1px solid #6272a4;
                padding: 5px;
                selection-background-color: #bd93f9;
            }
        """)
        self.search_bar.textChanged.connect(self.highlight_search_text)

        self.decompiler_layout.addWidget(self.search_bar)
        
        # Create navigation buttons for search
        self.prev_button = QPushButton("Previous")
        self.next_button = QPushButton("Next")
        self.prev_button.clicked.connect(self.go_to_previous_result)
        self.next_button.clicked.connect(self.go_to_next_result)

        # Style navigation buttons
        self.prev_button.setStyleSheet("""
            QPushButton {
                background-color: #44475a;
                color: #f8f8f2;
                font-size: 12pt;
                border: 1px solid #6272a4;
                padding: 5px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #6272a4;
            }
        """)
        
        self.next_button.setStyleSheet("""
            QPushButton {
                background-color: #44475a;
                color: #f8f8f2;
                font-size: 12pt;
                border: 1px solid #6272a4;
                padding: 5px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #6272a4;
            }
        """)

        # Add navigation buttons to layout
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.prev_button)
        button_layout.addWidget(self.next_button)
        self.decompiler_layout.addLayout(button_layout)
        
        # Setup validator tab
        self.validator_tab = QWidget()
        self.validator_layout = QVBoxLayout(self.validator_tab)

        # File selection group box for AndroidManifest.xml
        manifest_group = QGroupBox("AndroidManifest.xml Selection")
        manifest_group_layout = QFormLayout()
        self.manifest_label = QLabel("Choose AndroidManifest.xml file:")
        self.manifest_button = QPushButton("Browse...")
        self.manifest_button.clicked.connect(self.select_manifest_file)
        self.selected_manifest_label = QLabel("No file selected")

        # Styling
        font = self.manifest_label.font()
        font.setPointSize(12)
        self.manifest_label.setFont(font)
        self.manifest_button.setFont(font)
        self.selected_manifest_label.setFont(font)

        manifest_group_layout.addRow(self.manifest_label, self.manifest_button)
        manifest_group_layout.addRow(self.selected_manifest_label)
        manifest_group.setLayout(manifest_group_layout)
        self.validator_layout.addWidget(manifest_group)

        # Directory selection group box for output directory
        output_group = QGroupBox("Output Directory Selection")
        output_group_layout = QFormLayout()
        self.output_label = QLabel("Choose Output Directory:")
        self.output_button = QPushButton("Browse...")
        self.output_button.clicked.connect(self.select_output_directory)
        self.selected_output_label = QLabel("No directory selected")

        # Styling
        self.output_label.setFont(font)
        self.output_button.setFont(font)
        self.selected_output_label.setFont(font)

        output_group_layout.addRow(self.output_label, self.output_button)
        output_group_layout.addRow(self.selected_output_label)
        output_group.setLayout(output_group_layout)
        self.validator_layout.addWidget(output_group)
        
        # Add a "Run Validator" button
        self.run_validator_button = QPushButton("Run Validator")
        self.run_validator_button.clicked.connect(self.run_validator)
        self.run_validator_button.setFont(font)
        self.run_validator_button.setStyleSheet("""
            QPushButton {
                background-color: #44475a;
                color: #f8f8f2;
                font-size: 12pt;
                border: 1px solid #6272a4;
                padding: 5px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #6272a4;
            }
        """)
        self.validator_layout.addWidget(self.run_validator_button)
        
        # setup output area validator
        self.validator_output_area = QTextEdit(self.validator_tab)
        self.validator_output_area.setReadOnly(True)
        self.validator_output_area.setStyleSheet("""
            QTextEdit {
                background-color: #282a36;
                color: #f8f8f2;
                font-family: 'Courier New';
                font-size: 12pt;
                border: 1px solid #44475a;
                padding: 10px;
            }
        """)
        self.validator_layout.addWidget(self.validator_output_area)
        
        # Add the new tab to the tab widget
        self.subtab_widget.addTab(self.decompiler_tab, "Inspector")

        # Add Validator Subtab to the mobile pentesting tab
        self.subtab_widget.addTab(self.validator_tab, "Validator")
        
        # Explore tab
        self.setup_explorer_tab()
        
        # Create the APKLeaks subtab
        self.apkleaks_tab = QWidget()
        self.apkleaks_layout = QVBoxLayout(self.apkleaks_tab)

        # File selection group box
        apk_group = QGroupBox("APK File Selection")
        apk_group_layout = QFormLayout()
        self.apk_label = QLabel("Choose APK file:")
        self.apk_button = QPushButton("Browse...")
        self.apk_button.clicked.connect(self.select_apk_file)
        self.selected_apk_label = QLabel("No file selected")

        # Improve font readability
        self.apk_label.setFont(font)
        self.apk_button.setFont(font)
        self.selected_apk_label.setFont(font)

        apk_group_layout.addRow(self.apk_label, self.apk_button)
        apk_group_layout.addRow(self.selected_apk_label)
        apk_group.setLayout(apk_group_layout)
        self.apkleaks_layout.addWidget(apk_group)

        # Start scan button
        self.start_apkleaks_button = QPushButton("Start APKLeaks Scan")
        self.start_apkleaks_button.clicked.connect(self.start_apkleaks_scan)
        self.start_apkleaks_button.setFont(font)
        self.apkleaks_layout.addWidget(self.start_apkleaks_button)

        # Output area
        self.apkleaks_output_area = QTextEdit(self.apkleaks_tab)
        self.apkleaks_output_area.setReadOnly(True)
        self.apkleaks_output_area.setStyleSheet("""
            QTextEdit {
                background-color: #282a36;
                color: #f8f8f2;
                font-family: 'Courier New';
                font-size: 12pt;
                border: 1px solid #44475a;
                padding: 10px;
            }
        """)
        self.apkleaks_layout.addWidget(self.apkleaks_output_area)

        # Status label
        self.apkleaks_status_label = QLabel("Scanner: Ready")
        self.apkleaks_status_label.setFont(QFont('Arial', 12, QFont.Bold))  # Bold font
        self.apkleaks_status_label.setStyleSheet("color: #ff5555;")  # Red color for visibility
        self.apkleaks_layout.addWidget(self.apkleaks_status_label)

    

        # Add APKLeaks subtab to the main tab widget
        self.subtab_widget.addTab(self.apkleaks_tab, "APK Secrets")

        # Add the main tab to the tab widget
        self.drozer_tab_handler = DrozerTab(self)

        self.tab_widget.addTab(self.mobile_tab, "Mobile Pentesting")
        
    def setup_explorer_tab(self):
        self.explorer_tab = ExplorerSubTab()
        self.subtab_widget.addTab(self.explorer_tab, "Decompiler")

    def decompile_apk(self, apk_path):
        apk_name = os.path.splitext(os.path.basename(apk_path))[0]
        output_dir = os.path.join("decompiled", apk_name)
        os.makedirs(output_dir, exist_ok=True)
        self.explorer_tab.start_decompile(apk_path, output_dir)

    def select_apk_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Select APK File", "", "APK Files (*.apk);;All Files (*)", options=options)
        if file_path:
            self.selected_apk_label.setText(file_path)

    def start_apkleaks_scan(self):
        # Get the selected APK file and additional arguments
        apk_file = self.selected_apk_label.text()

        # Validate file selection
        if apk_file == "No file selected":
            self.apkleaks_status_label.setText("Error: No APK file selected.")
            return

        # Disable the scan button and update status
        self.start_apkleaks_button.setEnabled(False)
        self.apkleaks_status_label.setText("Scanning in progress...")

        # Create a new thread to run APKLeaks
        self.apkleaks_thread = APKLeaksThread(apk_file)
        
        # Connect the result signal to update the output area
        self.apkleaks_thread.result_signal.connect(self.display_apkleaks_results)
        
        # Start the thread
        self.apkleaks_thread.start()

    def display_apkleaks_results(self, results):
        # Update the output area with the results
        self.apkleaks_output_area.setPlainText(results)
        self.apkleaks_status_label.setText("Scan complete.")
        # Re-enable the scan button
        self.start_apkleaks_button.setEnabled(True)

        
    def run_validator(self):
        xml_file = self.selected_manifest_label.text()
        output_dir = self.selected_output_label.text()

        if not xml_file or not output_dir:
            self.show_error_message("Please select a valid XML file and output directory.")
            return

        # Clear the output area before running the validator
        self.validator_output_area.clear()

        # Create and start the thread
        self.validator_thread = ValidatorRunner(xml_file, output_dir)
        self.validator_thread.output_received.connect(self.append_output)
        self.validator_thread.finished.connect(self.on_validator_finished)
        self.validator_thread.error_occurred.connect(self.on_validator_error)
        self.validator_thread.start()

    def append_output(self, output):
        self.validator_output_area.append(output)
        self.validator_output_area.moveCursor(QTextCursor.End)




    def on_validator_finished(self):
        self.append_output("Validation complete.")

    def on_validator_error(self, error_message):
        self.append_output(f"Error: {error_message}")

    def show_error_message(self, message):
        QMessageBox.critical(self, "Error", message)

    def show_info_message(self, message):
        QMessageBox.information(self, "Info", message)
        
        
    def select_manifest_file(self):
        file_dialog = QFileDialog()
        file_dialog.setNameFilter("XML files (*.xml)")
        if file_dialog.exec_():
            selected_file = file_dialog.selectedFiles()[0]
            self.selected_manifest_label.setText(selected_file)

    def select_output_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.selected_output_label.setText(directory)

    def go_to_previous_result(self):
        if self.search_results:
            self.current_result_index = (self.current_result_index - 1) % len(self.search_results)
            self.jump_to_result(self.current_result_index)

    def go_to_next_result(self):
        if self.search_results:
            self.current_result_index = (self.current_result_index + 1) % len(self.search_results)
            self.jump_to_result(self.current_result_index)

    def jump_to_result(self, index):
        if self.search_results and 0 <= index < len(self.search_results):
            cursor = self.search_results[index]
            self.xml_display.setTextCursor(cursor)
            self.xml_display.ensureCursorVisible()

            
    def highlight_search_text(self):
        search_text = self.search_bar.text().strip()
        cursor = self.xml_display.textCursor()

        # Reset all previous highlights
        cursor.setPosition(0)
        self.xml_display.selectAll()
        clear_format = QTextCharFormat()
        clear_format.setBackground(QColor("#282a36"))  # Match the background color
        cursor.mergeCharFormat(clear_format)
        cursor.clearSelection()
        self.xml_display.setTextCursor(cursor)

        self.search_results = []  # Clear previous search results
        self.current_result_index = -1  # Reset current result index

        if search_text:
            highlight_format = QTextCharFormat()
            # highlight_format.setBackground(QColor("red"))

            cursor.setPosition(0)
            while True:
                cursor = self.xml_display.document().find(search_text, cursor, QTextDocument.FindWholeWords)
                if cursor.isNull():
                    break
                self.search_results.append(cursor)  # Store cursor positions for results
                cursor.mergeCharFormat(highlight_format)

            if self.search_results:
                self.current_result_index = 0
                self.jump_to_result(self.current_result_index)




    def setup_objection_tab(self):
        self.objection_tab = QWidget()
        self.objection_layout = QVBoxLayout(self.objection_tab)

        # Create horizontal layout for panels
        self.panels_layout = QHBoxLayout()
        
        self.left_panel = QVBoxLayout()
        self.right_panel = QVBoxLayout()

        # Setup Workflow Area
        self.setup_workflow_area()

        # Setup Command Area
        self.setup_command_area()

        # Add panels to the horizontal layout
        self.panels_layout.addLayout(self.left_panel, 1)
        self.panels_layout.addLayout(self.right_panel, 1)

        # Add the panels layout to the main vertical layout
        self.objection_layout.addLayout(self.panels_layout)

        # Status label at the bottom
        self.objection_status_label = QLabel("Emulator Status: Disconnected")
        self.set_status_label_style(False)
        self.objection_layout.addWidget(self.objection_status_label)

    def setup_workflow_area(self):
        workflow_group = QGroupBox("Workflows")
        workflow_layout = QVBoxLayout()

        # Workflow Dropdown
        self.workflow_combo = QComboBox()
        self.load_workflows()
        self.workflow_combo.setStyleSheet("""
            background-color: #44475a;
            color: #f8f8f2;
            border: 1px solid #44475a;
        """)
        self.workflow_combo.currentIndexChanged.connect(self.display_workflow_details)
        workflow_layout.addWidget(self.workflow_combo)

        # Tree view for workflow commands
        self.workflow_editor = WorkflowEditor()
        workflow_layout.addWidget(self.workflow_editor)

        # Button to execute selected workflow
        self.execute_workflow_button = QPushButton("Execute Workflow")
        self.execute_workflow_button.setStyleSheet("""
            background-color: #bd93f9;
            color: #282a36;
            border-radius: 5px;
            padding: 10px;
        """)
        self.execute_workflow_button.clicked.connect(self.execute_selected_workflow)
        workflow_layout.addWidget(self.execute_workflow_button)

        workflow_group.setLayout(workflow_layout)
        self.left_panel.addWidget(workflow_group)


    def setup_command_area(self):
        command_group = QGroupBox("Commands")
        command_layout = QVBoxLayout()

        # Emulator IP and Port configuration
        ip_port_group = QGroupBox("Emulator IP and Port")
        ip_port_layout = QFormLayout()
        self.emulator_ip_input = QLineEdit()
        self.emulator_port_input = QLineEdit()
        default_ip, default_port = self.get_default_adb_device()
        self.emulator_ip_input.setText(default_ip)
        self.emulator_port_input.setText(default_port)
        ip_port_layout.addRow("IP Address:", self.emulator_ip_input)
        ip_port_layout.addRow("Port:", self.emulator_port_input)
        ip_port_group.setLayout(ip_port_layout)
        command_layout.addWidget(ip_port_group)

        # Confirm and Heartbeat button
        self.confirm_heartbeat_button = QPushButton("Confirm Connection")
        self.confirm_heartbeat_button.setStyleSheet("""
            background-color: #50fa7b;
            color: #282a36;
            border-radius: 5px;
            padding: 10px;
            font-weight: bold;
        """)
        self.confirm_heartbeat_button.clicked.connect(self.confirm_and_heartbeat_connection)
        command_layout.addWidget(self.confirm_heartbeat_button)

        # Console output area
        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setStyleSheet("""
            background-color: #282a36;
            color: #f8f8f2;
            font-family: Consolas, monospace;
            border: 1px solid #44475a;
        """)
        command_layout.addWidget(self.console_output)

        # Clear console button
        self.clear_console_button = QPushButton("Clear Console")
        self.clear_console_button.setStyleSheet("""
            background-color: #ff5555;
            color: #282a36;
            border-radius: 5px;
            padding: 10px;
        """)
        self.clear_console_button.clicked.connect(self.clear_console_output)
        command_layout.addWidget(self.clear_console_button)

        command_group.setLayout(command_layout)
        self.right_panel.addWidget(command_group)

    def load_workflows(self):
        workflows_file = os.path.join("commands", "workflows.json")
        if os.path.isfile(workflows_file):
            with open(workflows_file, 'r') as file:
                data = json.load(file)
                workflows = data.get('workflows', {})
                
                # Add a prompt to the combo box
                self.workflow_combo.addItem("Select a workflow ...")
                
                for name in workflows.keys():
                    self.workflow_combo.addItem(name)

    def display_workflow_details(self):
        workflow_name = self.workflow_combo.currentText()
        
        # Check if the user hasn't selected a workflow
        if workflow_name == "Select a workflow ...":
            self.console_output.append("Please select a valid workflow.")
            return
        
        workflows_file = os.path.join("commands", "workflows.json")
        if os.path.isfile(workflows_file):
            with open(workflows_file, 'r') as file:
                data = json.load(file)
                workflow = data.get('workflows', {}).get(workflow_name, {})
                if workflow:
                    self.workflow_editor.load_workflow_from_file(workflow)

    def execute_selected_workflow(self):
        workflow_name = self.workflow_combo.currentText()

        # Check if the user hasn't selected a workflow
        if workflow_name == "Select a workflow ...":
            self.console_output.append("Please select a valid workflow.")
            return

        workflows_file = os.path.join("commands", "workflows.json") # why you define this 3 times fix it 
        if os.path.isfile(workflows_file):
            try:
                with open(workflows_file, 'r') as file:
                    data = json.load(file)
                    workflow = data.get('workflows', {}).get(workflow_name, {})
                    commands = workflow.get('commands', [])
                    
                    # List to store processed commands
                    processed_commands = []

                    for command_dict in commands:
                        command = command_dict.get('command', '')

                        # Identify placeholders like <example_arg>
                        placeholders = re.findall(r'<(.*?)>', command)

                        for placeholder in placeholders:
                            # Prompt the user to fill in the placeholder
                            value, ok = QInputDialog.getText(self, "Input Required",
                                                            f"Please provide a value for '{placeholder}':")
                            if ok and value:
                                # Replace the placeholder with the provided value
                                command = command.replace(f"<{placeholder}>", value)
                            else:
                                self.console_output.append(f"Command execution canceled: missing value for '{placeholder}'.")
                                return

                        processed_commands.append(command)
                    
                    if processed_commands:
                        self.console_output.append(f"Executing workflow: {workflow_name}")
                        log_file = os.path.join("logs", f"{workflow_name.replace(' ', '_')}-workflow.log")
                        self.run_command_in_thread(processed_commands, log_file)
                    else:
                        self.console_output.append("No commands found for the selected workflow.")
            
            except Exception as e:
                self.console_output.append(f"Error loading workflow: {str(e)}")





    def save_workflow_changes(self):
        workflow_name = self.workflow_combo.currentText()
        workflows_file = "commands/workflows.json"
        
        # Save the current workflow
        workflow_data = self.workflow_editor.save_workflow()
        if workflow_data is not None:
            if os.path.isfile(workflows_file):
                try:
                    with open(workflows_file, 'r+') as file:
                        data = json.load(file)
                        data['workflows'][workflow_name] = workflow_data
                        file.seek(0)
                        json.dump(data, file, indent=4)
                        file.truncate()
                except Exception as e:
                    self.console_output.append(f"Error saving workflow changes: {str(e)}")

        

    def run_command_in_thread(self, commands, log_file):
        self.command_thread = CommandThread(commands, log_file)
        self.command_thread.output_signal.connect(self.console_output.append)
        self.command_thread.error_signal.connect(self.console_output.append)
        self.command_thread.start()


    def clear_console_output(self):
        self.console_output.clear()

    

    def get_default_adb_device(self):
        try:
            result = subprocess.check_output(['adb', 'devices']).decode()
            for line in result.splitlines():
                if "\tdevice" in line:
                    parts = line.split()
                    if len(parts) > 0:
                        # Check if it's an emulator (starts with "emulator-")
                        if parts[0].startswith("emulator-"):
                            return parts[0], None  # Emulators typically do not have a port in the output
                        # Check for devices with ip:port format
                        ip_port = parts[0].split(":")
                        if len(ip_port) == 2:
                            return ip_port[0], ip_port[1]
            return None, None  # No valid devices found
        except Exception as e:
            print(f"Error getting default adb device: {e}")
            return None, None


    def confirm_and_heartbeat_connection(self):
        ip = self.emulator_ip_input.text()
        port = self.emulator_port_input.text()
        device_name = f"{ip}:{port}" if ip and port else "emulator-5554"  # Default to a common emulator name if empty
        self.console_output.append(f"Confirming connection to {device_name}...")

        try:
            # Only use adb connect if it's an IP:port combo
            if ':' in device_name:
                result = subprocess.check_output(['adb', 'connect', device_name]).decode()
                self.console_output.append(result)

            result = subprocess.check_output(['adb', 'devices']).decode()
            if any(f"{device_name}\tdevice" in line for line in result.splitlines()):
                self.console_output.append("Connection successful. Starting heartbeat...")
                self.update_emulator_status(True)
                self.start_heartbeat()
            else:
                self.console_output.append("Failed to connect. Please check the IP and Port.")
                self.update_emulator_status(False)
        except Exception as e:
            self.console_output.append(f"Error connecting to emulator: {e}")
            self.update_emulator_status(False)



    def start_heartbeat(self):
        self.heartbeat_timer = QTimer(self)
        self.heartbeat_timer.timeout.connect(self.check_emulator_status)
        self.heartbeat_timer.start(7000)  # 7000 milliseconds = 7 seconds

    def check_emulator_status(self):
        try:
            result = subprocess.check_output(['adb', 'devices']).decode()
            if any(f"{self.emulator_ip_input.text()}:{self.emulator_port_input.text()}\tdevice" in line for line in result.splitlines()):
                self.update_emulator_status(True)
            else:
                self.update_emulator_status(False)
        except Exception as e:
            self.console_output.append(f"Error during heartbeat: {str(e)}")
            self.update_emulator_status(False)

    def set_status_label_style(self, is_connected):
        base_style = "background-color: #282a36; color: {}; font-family: Consolas, monospace; font-weight: bold; font-size: 14px;"
        color = "green" if is_connected else "red"
        self.objection_status_label.setStyleSheet(base_style.format(color))
        self.objection_status_label.setFixedHeight(30) 


    def update_emulator_status(self, is_connected):
        status_text = "Emulator Status: Connected" if is_connected else "Emulator Status: Disconnected"
        self.objection_status_label.setText(status_text)
        self.set_status_label_style(is_connected)
        
    def load_and_display_manifest(self):
        mobber = Mobber(mobsf_url=self.mobsf_url_input.text(), app_path=self.selected_file_path)
        manifest_path = mobber.download_manifest()
        if manifest_path:
            with open(manifest_path, 'r') as file:
                xml_content = file.read()
            
            # Apply the XML highlighter
            self.xml_display.setPlainText(xml_content)
            self.xml_highlighter = XmlHighlighter(self.xml_display.document())
        else:
            self.xml_display.setPlainText("Manifest could not be downloaded.")

    def load_mobsf_url(self):
        """Load the MobSF URL from the mobsf_config.json file."""
        config_file = "mobsf_config.json"
        if os.path.exists(config_file):
            with open(config_file, 'r') as file:
                config = json.load(file)
                mobsf_url = config.get("mobsf_url")
                if mobsf_url and mobsf_url.startswith("http"):
                    return mobsf_url
        return None
        
    def save_mobsf_url(self):
        mobsf_url = self.mobsf_url_input.text()
        with open("mobsf_config.json", "w") as config_file:
            json.dump({"mobsf_url": mobsf_url}, config_file)

    def load_saved_mobsf_url(self):
        try:
            with open("mobsf_config.json", "r") as config_file:
                config = json.load(config_file)
                self.mobsf_url_input.setText(config.get("mobsf_url", ""))
        except (FileNotFoundError, json.JSONDecodeError):
            self.mobsf_url_input.setText("")
        
        # Save the URL whenever it changes
        self.mobsf_url_input.textChanged.connect(self.save_mobsf_url)


    def start_mobsf_heartbeat(self):
        self.heartbeat_timer = QTimer(self)
        self.heartbeat_timer.timeout.connect(self.check_mobsf_connection)
        self.heartbeat_timer.start(10000)

    def check_mobsf_connection(self):
        mobsf_url = self.mobsf_url_input.text()
        
        # Create and start the connection check thread
        self.connection_check_thread = MobSFConnectionCheckThread(mobsf_url)
        self.connection_check_thread.connection_status.connect(self.update_mobsf_status)
        self.connection_check_thread.start()

    def update_mobsf_status(self, is_connected):
        if is_connected:
            self.status_label.setStyleSheet("color: #50fa7b;")  # Green color
            self.status_label.setText("MobSF: Connected")
        else:
            self.status_label.setStyleSheet("color: #ff5555;")  # Red color
            self.status_label.setText("MobSF: Disconnected")


            
        
    def show_context_menu(self, pos):
        # Create and show context menu
        context_menu = QMenu(self)
        
        exclude_action = QAction("Exclude from Export", self)
        exclude_action.triggered.connect(self.exclude_item)
        context_menu.addAction(exclude_action)
        
        context_menu.exec_(self.results_table.viewport().mapToGlobal(pos))

    

    def store_original_data_to_temp(self):
        # Store the original data to a temporary file
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        original_data = []
        
        for row in range(self.results_table.rowCount()):
            finding_item = self.results_table.item(row, 0)
            severity_item = self.results_table.item(row, 1)
            common_fp_item = self.results_table.item(row, 2)
            
            original_data.append({
                'finding': finding_item.text() if finding_item else "",
                'severity': severity_item.text() if severity_item else "",
                'common_fp': common_fp_item.text() if common_fp_item else ""
            })
        
        with open(self.temp_file.name, 'w') as file:
            json.dump(original_data, file)
        
        # Also store the data in self.original_data in case we need to access it directly
        self.original_data = original_data.copy()

        
    def restore_data_from_temp(self):
        try:
            # Restore the data from the temporary file
            with open(self.temp_file.name, 'r') as file:
                original_data = json.load(file)

            # Clear the current table content
            self.results_table.setRowCount(0)

            # Populate the table with the original data
            for data in original_data:
                row_position = self.results_table.rowCount()
                self.results_table.insertRow(row_position)
                
                finding_item = QTableWidgetItem(data['finding'])
                severity_item = QTableWidgetItem(data['severity'])
                common_fp_item = QTableWidgetItem(data['common_fp'])
                
                self.results_table.setItem(row_position, 0, finding_item)
                self.results_table.setItem(row_position, 1, severity_item)
                self.results_table.setItem(row_position, 2, common_fp_item)
            
            # Clear exclusions and reapply filters if necessary
            self.excluded_items.clear()

            # Refresh the table view
            self.results_table.viewport().update()
            self.results_table.update()
        except:
            pass # prevent crashing if reset changes is pressed on a empty scan 



    def reset_changes(self):
        # Restore the data from the temporary file
        self.restore_data_from_temp()
        
        # Clear exclusions
        self.excluded_items.clear()

        # Refresh the table view
        self.results_table.viewport().update()
        self.results_table.update()




    def update_progress(self, message):
        self.status_label.setText(message)
        self.connect_mobsf_button.setText("Scanning...")
        self.connect_mobsf_button.setDisabled(True)

    def scan_finished(self):
        self.status_label.setText("Scan completed.")
        self.connect_mobsf_button.setText("Start Scan")
        self.connect_mobsf_button.setEnabled(True)

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Select IPA/APK File", "", "APK Files (*.apk);;IPA Files (*.ipa)")
        if file_path:
            self.selected_file_label.setText(f"Selected: {file_path}")
            self.selected_file_path = file_path  # Store the file path for later use

    def run_mobsf_scan(self):
        try:
            mobsf_url = self.mobsf_url_input.text()
            app_path = self.selected_file_path

            if not mobsf_url or not app_path:
                QMessageBox.warning(self, "Input Error", "Please provide a MobSF URL and select an APK/IPA file.")
                return

            self.connect_mobsf_button.setDisabled(True)

            # Create and start the scan thread
            self.scan_thread = MobSFScanThread(mobsf_url, app_path)
            self.scan_thread.progress.connect(self.update_progress)
            self.scan_thread.result_ready.connect(self.display_results)
            self.scan_thread.finished.connect(self.scan_finished)
            self.scan_thread.start()
        except Exception as e:
            print(e)
            
    def exclude_item(self):
        current_item = self.results_table.currentItem()
        if current_item:
            row = current_item.row()
            self.excluded_items.add(row)
            self.results_table.removeRow(row)
            
    
    def load_plugin_id_mapping(self, file_path):
        try:
            with open(file_path, 'r') as f:
                self.plugin_id_mapping = json.load(f)
        except FileNotFoundError:
            print(f"File {file_path} not found.")
        except json.JSONDecodeError:
            print(f"Error decoding JSON from file {file_path}.")

    def extract_pattern(self, finding_name):
        # Remove identifiable info within parentheses using regex
        pattern = re.sub(r'\(.*?\)', '()', finding_name)
        return pattern

    def convert_finding_name(self, finding_name):
        pattern = self.extract_pattern(finding_name)
        if pattern in self.plugin_id_mapping:
            return self.plugin_id_mapping[pattern]['new_name']
        return finding_name

    def export_report(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getSaveFileName(self, "Save Report", "", "CSV Files (*.csv)")
        if file_path:
            with open(file_path, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([
                    "Plugin ID", "CVE", "Risk", "Host", "Protocol", "Port",
                    "Name", "Description", "Solution", "See Also", "References"
                ])

                processed_patterns = set()  # Track processed patterns

                for row in range(self.results_table.rowCount()):
                    if row in self.excluded_items:
                        continue  # Skip excluded items

                    finding_item = self.results_table.item(row, 0)
                    severity_item = self.results_table.item(row, 1)

                    finding_name = finding_item.text() if finding_item else ""
                    severity = severity_item.text() if severity_item else ""

                    # Normalize severity using the severity map
                    normalized_severity = self.severity_map.get(severity.capitalize(), severity)

                    # Convert the finding name
                    converted_name = self.convert_finding_name(finding_name)

                    # Use the converted name to get the plugin ID
                    plugin_id = None
                    for key, value in self.plugin_id_mapping.items():
                        if value.get('new_name') == converted_name:
                            plugin_id = value.get('id', "")
                            break

                    if converted_name in processed_patterns:
                        continue

                    csv_row = [
                        plugin_id,  # Plugin ID
                        "",  # CVE (empty for now)
                        normalized_severity,  # Risk
                        "FIXME",  # Host (empty for now)
                        "",  # Protocol (empty for now)
                        "",  # Port (empty for now)
                        converted_name,  # Name (use converted name)
                        "FIXME",  # Description (empty for now)
                        "FIXME",  # Solution (empty for now)
                        "",  # See Also (empty for now)
                        ""   # References (empty for now)
                    ]

                    writer.writerow(csv_row)
                    processed_patterns.add(converted_name)




    def display_results(self, findings):
        unique_findings = []
        seen_titles = set()

        for finding in findings:
            title = finding.get("title", "")
            severity = finding.get("severity", "").capitalize()

            # Exclude findings with 'secure' or 'hotspot' severity
            if severity in ["Secure", "Hotspot"]:
                continue

            # Normalize severity using the severity map
            normalized_severity = self.severity_map.get(severity, severity)

            # Convert the finding name
            converted_title = self.convert_finding_name(title)

            if converted_title not in seen_titles:
                finding["title"] = converted_title
                finding["severity"] = normalized_severity
                unique_findings.append(finding)
                seen_titles.add(converted_title)

        # Populate the results table with unique findings
        self.results_table.setRowCount(len(unique_findings))
        for row, finding in enumerate(unique_findings):
            title_item = QTableWidgetItem(finding.get("title", ""))
            severity_item = QTableWidgetItem(finding.get("severity", ""))
            is_common_fp = "Yes" if self.is_common_fp(finding.get("title", "")) else "No"
            common_fp_item = QTableWidgetItem(is_common_fp)

            self.results_table.setItem(row, 0, title_item)
            self.results_table.setItem(row, 1, severity_item)
            self.results_table.setItem(row, 2, common_fp_item)

        self.results_table.viewport().update()  # Refresh the viewport
        self.results_table.update()  # Refresh the table

        self.store_original_data_to_temp()
        self.load_and_display_manifest() 



    def load_common_false_positives(self, file_path):
        try:
            with open(file_path, 'r') as file:
                self.common_false_positives = {line.strip() for line in file}
        except FileNotFoundError:
            self.common_false_positives = set()
            print(f"Error: File {file_path} not found.")

    def is_common_fp(self, finding_title):
        # Check if the finding is in the common false positives list
        return finding_title in self.common_false_positives
    
    
    def add_button_hover_effect(self, button):
        button.setStyleSheet("""
            background-color: #44475a;
            color: #f8f8f2;
        """)
        button.installEventFilter(self)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Enter and obj in [self.confirm_heartbeat_button, self.execute_command_button, self.clear_console_button]:
            obj.setStyleSheet("""
                background-color: #6272a4;
                color: #f8f8f2;
            """)
        elif event.type() == QEvent.Leave and obj in [self.confirm_heartbeat_button, self.execute_command_button, self.clear_console_button]:
            if obj == self.confirm_heartbeat_button:
                obj.setStyleSheet("""
                    background-color: #50fa7b;
                    color: #282a36;
                """)
            elif obj == self.execute_command_button:
                obj.setStyleSheet("""
                    background-color: #bd93f9;
                    color: #282a36;
                """)
            elif obj == self.clear_console_button:
                obj.setStyleSheet("""
                    background-color: #ff5555;
                    color: #282a36;
                """)
        return super().eventFilter(obj, event)

        
    def open_policy_wizard(self):
        wizard = PolicyWizard(self)
        wizard.exec_()


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
        
        # Policy Wizard Button
        self.policy_wizard_button = QPushButton("Open Policy Wizard")
        self.policy_wizard_button.clicked.connect(self.open_policy_wizard)
        self.zeus_layout.addWidget(self.policy_wizard_button)

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
        self.tools_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), "tools")
        self.zeus_output.clear()
        target_url = self.target_url_input.text().strip()
        project_folder = self.project_folder_input.text().strip()
        login_config = self.login_config_input.text().strip()
        proxy = self.proxy_input.text().strip()

        if not target_url or not project_folder:
            QMessageBox.warning(self, "Parameter Error", "Please provide both a target URL and a project folder.")
            return

        # Define the path to the Zeus executable
        zeus_executable = os.path.join(self.tools_dir, "zeus", "zeus" + (".exe" if platform.system() == "Windows" else ""))

        # Check if the Zeus executable exists
        if not os.path.isfile(zeus_executable):
            QMessageBox.warning(self, "Feature Not Implemented", "The Zeus binary does not exist in the tools directory - use the addon menu to download it.")
            return

        command_args = [zeus_executable, target_url, '--project-folder', project_folder]
        if login_config:
            command_args.extend(['--login-config', login_config])
        if proxy:
            command_args.extend(['--proxy', proxy])

        # Set the working directory to where Zeus config files are located
        zeus_working_dir = os.path.join(self.tools_dir, "zeus")
        
        # Create and start the worker thread
        self.zeus_worker = ZeusWorker(command_args, zeus_working_dir)
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
        # Path to the documentation file
        documentation_file = os.path.join("wiki", "index.html")
        
        # Open the file in the default web browser using QDesktopServices
        url = QUrl.fromLocalFile(os.path.abspath(documentation_file))
        QDesktopServices.openUrl(url)

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
        file_name, _ = QFileDialog.getOpenFileName(self, "Open File", "", "All Supported Files (*.csv *.json);; CSV Files (*.csv);;JSON Files (*.json)", options=options)
        if file_name:
            tab = QWidget()
            tab.is_custom_tab = True
            layout = QVBoxLayout(tab)

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
        self.mode_combobox.addItems(["deploy", "external", "internal", "monitor", "export", "create", "launch", "pause", "resume", "regen"])
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
                "discovery": "Checkbox"
            },
            "create": {
                "client-name": "Text",
                "scope": ["core", "nc", "custom"],
                "exclude-file": "File",
                "targets-file": "File"
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
                "local": "Checkbox"
            },
            "external": {
                "csv-file": "File",
                "local": "Checkbox"
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

        if os.path.exists(log_dir):
            for entry in sorted(os.listdir(log_dir)):
                entry_path = os.path.join(log_dir, entry)
                if os.path.isdir(entry_path):
                    self.log_sessions_combo.addItem(entry)
                elif os.path.isfile(entry_path):
                    if entry.endswith(".log"):
                        self.log_sessions_combo.addItem(entry)

        
    
    def load_log_content(self, index):
        log_dir = os.path.join("logs")
        session_name = self.log_sessions_combo.itemText(index)
        log_file_path = os.path.join(log_dir, session_name)

        log_content = ""

        if os.path.isfile(log_file_path):
            with open(log_file_path, 'r') as file:
                log_content = file.read()
        else:
            session_path = os.path.join(log_dir, session_name)
            if os.path.isdir(session_path):
                for log_file in sorted(os.listdir(session_path)):
                    if log_file.endswith(".log"):
                        log_file_path = os.path.join(session_path, log_file)
                        with open(log_file_path, 'r') as file:
                            log_content += file.read() + "\n" + "-"*40 + "\n"

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
                    elif os.path.isfile(session_path):
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
        close_button.setIcon(self.style().standardIcon(QStyle.SP_DockWidgetCloseButton))
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


class JobConfig:
    def __init__(self, job_type, parameters):
        self.job_type = job_type
        self.parameters = parameters

    def __repr__(self):
        return f"{self.job_type}: {self.parameters}"

class PolicyWizard(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Policy Wizard')
        self.setGeometry(200, 200, 1400, 1100)
        self.jobs = []
        self.user_creds = []
        self.init_ui()

    def init_ui(self):
        self.layout = QVBoxLayout(self)
        self.setup_context_inputs()
        self.setup_user_inputs()
        self.setup_job_tabs()
        self.job_list_widget = QListWidget()
        self.job_list_widget.setMinimumHeight(200)
        self.layout.addWidget(self.job_list_widget)
        self.setup_buttons()
        self.yaml_output = QTextEdit()
        self.yaml_output.setPlaceholderText("Generated YAML will appear here...")
        self.layout.addWidget(self.yaml_output)

    def setup_context_inputs(self):
        form_layout = QFormLayout()
        self.context_name_input = QLineEdit()
        self.login_page_url_input = QLineEdit()
        self.login_page_wait_input = QLineEdit("5")  # default value
        self.browser_id_input = QLineEdit("firefox-headless")  # default value

        form_layout.addRow("Context Name:", self.context_name_input)
        form_layout.addRow("Login Page URL:", self.login_page_url_input)
        form_layout.addRow("Login Page Wait (seconds):", self.login_page_wait_input)
        form_layout.addRow("Browser ID:", self.browser_id_input)
        
        self.layout.addLayout(form_layout)

    def setup_user_inputs(self):
        user_layout = QFormLayout()
        self.user_name_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.add_user_button = QPushButton("Add User")
        self.add_user_button.clicked.connect(self.add_user)

        user_layout.addRow("User Name:", self.user_name_input)
        user_layout.addRow("Username:", self.username_input)
        user_layout.addRow("Password:", self.password_input)
        user_layout.addRow(self.add_user_button)

        self.layout.addLayout(user_layout)

    def add_user(self):
        name = self.user_name_input.text()
        username = self.username_input.text()
        password = self.password_input.text()
        if name and username and password:
            self.user_creds.append({'name': name, 'credentials': {'username': username, 'password': password}})
            self.job_list_widget.addItem(f"User: {name} - Username: {username}")
            self.user_name_input.clear()
            self.username_input.clear()
            self.password_input.clear()
        else:
            QMessageBox.warning(self, "Warning", "All user fields must be filled.")

    def generate_yaml(self):
        context_name = self.context_name_input.text()
        login_page_url = self.login_page_url_input.text()
        login_page_wait = self.login_page_wait_input.text()
        browser_id = self.browser_id_input.text()

        user_section = "\n".join([f"    - name: \"{user['name']}\"\n      credentials:\n        username: \"{user['credentials']['username']}\"\n        password: \"{user['credentials']['password']}\"" for user in self.user_creds])

        yaml_template = f"""
env:
  contexts:
  - name: "{context_name}"
    urls:
      - "{{{{baseURL}}}}"
    authentication:
      method: "browser"
      parameters:
        loginPageUrl: "{login_page_url}"
        loginPageWait: {login_page_wait}
        browserId: "{browser_id}"
      verification:
        method: "autodetect"
    sessionManagement:
      method: "autodetect"
    users:
{user_section}
jobs:
{self.format_jobs()}
"""
        self.yaml_output.setText(yaml_template)

    def format_jobs(self):
        job_entries = []
        for job in self.jobs:
            formatted_parameters = '\n      '.join([line.strip() for line in job.parameters.split('\n')])
            job_entry = f"  - type: {job.job_type}\n    parameters:\n      {formatted_parameters}"
            job_entries.append(job_entry)
        return '\n'.join(job_entries)

    def setup_job_tabs(self):
        self.job_tabs = QTabWidget()
        job_details = {
            "activeScan": "MaxRuleDurationInMins: 0\nMaxScanDurationInMins: 0\nDelayInMs: 0\nThreadPerHost: 2",
            "report": "Template: modern\nReportDir: {{reportDir}}\nReportFile: report-name\nReportTitle: 'report sample'",
            "spider": "MaxDepth: 5\nMaxChildren: 10\nAcceptCookies: true",
            "passiveScan-wait": "MaxDuration: 5",
            "requestor": "User: admin\nURL: {{baseURL}}/protected\nMethod: GET\nResponse Code: 200",
            "script": "action:add, remove, run, enable, disable\ntype: targeted OR standalone\nengine: jython\nname: some_script_name\nfile:/full/path/to/script\ntarget:{{baseURL}}/somepath"
        }
        for job_type, details in job_details.items():
            self.add_job_tab(job_type, details)
        self.layout.addWidget(self.job_tabs)

    def add_job_tab(self, job_type, description):
        widget = QWidget()
        layout = QHBoxLayout(widget)
        description_label = QLabel(description)
        description_label.setWordWrap(True)
        description_label.setStyleSheet("QLabel { font-weight: bold; color: #555; }")

        param_input = QTextEdit()
        param_input.setPlaceholderText("Enter your parameters here.")

        prefill_button = QPushButton("Load Defaults")
        prefill_button.clicked.connect(lambda: param_input.setText(description))

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(description_label)
        splitter.addWidget(param_input)
        splitter.addWidget(prefill_button)
        splitter.setSizes([150, 300, 100])

        layout.addWidget(splitter)
        self.job_tabs.addTab(widget, job_type)

    def setup_buttons(self):
        self.add_job_button = QPushButton('Add Job')
        self.add_job_button.clicked.connect(self.add_job)
        self.generate_button = QPushButton('Generate YAML')
        self.generate_button.clicked.connect(self.generate_yaml)
        buttons_layout = QHBoxLayout()
        buttons_layout.addWidget(self.add_job_button)
        buttons_layout.addWidget(self.generate_button)
        self.layout.addLayout(buttons_layout)

    def add_job(self):
        current_widget = self.job_tabs.currentWidget().findChild(QTextEdit)
        parameters = current_widget.toPlainText()
        job_type = self.job_tabs.tabText(self.job_tabs.currentIndex())
        if parameters.strip():
            self.jobs.append(JobConfig(job_type.lower(), parameters))
            self.job_list_widget.addItem(f"{job_type}: {parameters}")
            current_widget.clear()
        else:
            QMessageBox.warning(self, "Warning", "Parameters cannot be empty.")





if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        app.setStyleSheet(DRACULA_STYLESHEET)
        main_window = MainWindow()
        main_window.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(e)
        pass # don't handle the exceptions here

