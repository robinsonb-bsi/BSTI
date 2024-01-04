#!/usr/bin/python3
from flask import Flask, request
from flask_socketio import SocketIO
import os
import pty
import subprocess
import threading

app = Flask(__name__)
socketio = SocketIO(app)

master_fd_dict = {}

def start_pty_process(client_id):
    master_fd, slave_fd = pty.openpty()
    subprocess.Popen(['bash'], stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, text=True)
    master_fd_dict[client_id] = master_fd
    thread = threading.Thread(target=read_from_master, args=(master_fd, client_id))
    thread.start()

def read_from_master(master_fd, client_id):
    while True:
        try:
            output = os.read(master_fd, 1024).decode()
            socketio.emit('terminal_output', {'output': output, 'client_id': client_id})
        except OSError:
            break

@app.route('/')
def home():
    client_id = request.remote_addr
    start_pty_process(client_id)
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Remote Terminal</title>
        <style>
            body {
                margin: 0;
                height: 100vh;
                width: 100vw;
                overflow: hidden;
                display: flex;
            }
            #terminal {
                flex-grow: 1;
                background-color: black;
            }
        </style>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm/css/xterm.css" />
        <script src="https://cdn.jsdelivr.net/npm/xterm/lib/xterm.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/socket.io/client-dist/socket.io.js"></script>
    </head>
    <body>
        <div id="terminal"></div>
        <script>
            var term = new Terminal();
            term.open(document.getElementById('terminal'));
            term.write('BSTI Terminal\\r\\n');

            var socket = io();

            socket.on('terminal_output', function(msg) {
                if (msg.output) {
                    term.write(msg.output);
                }
            });

            term.onData(function(data) {
                socket.emit('terminal_input', { 'data': data });
            });

            // Resize the terminal to fill the window
            function resizeTerminal() {
                if (term._core._renderService) {
                    const termEl = document.getElementById('terminal');
                    const styles = window.getComputedStyle(termEl);
                    const termWidth = termEl.clientWidth - parseInt(styles.paddingLeft, 10) - parseInt(styles.paddingRight, 10);
                    const termHeight = termEl.clientHeight - parseInt(styles.paddingTop, 10) - parseInt(styles.paddingBottom, 10);
                    const cellWidth = term._core._renderService.dimensions.actualCellWidth;
                    const cellHeight = term._core._renderService.dimensions.actualCellHeight;
                    let cols = Math.floor(termWidth / cellWidth);
                    let rows = Math.floor(termHeight / cellHeight);

                    // Explicitly convert to integers
                    cols = parseInt(cols, 10);
                    rows = parseInt(rows, 10);

                    // Ensure cols and rows are at least 1
                    cols = Math.max(1, cols);
                    rows = Math.max(1, rows);

                    term.resize(cols, rows);
                    logTerminalSize(); // Log the terminal size after resizing
                }
            }

            // Function to log the terminal's current size
            function logTerminalSize() {
                console.log('Terminal size:', term.cols, 'columns x', term.rows, 'rows');
            }


            window.addEventListener('resize', resizeTerminal);
            
            // Call resizeTerminal after terminal initialization
            setTimeout(resizeTerminal, 0);
        </script>
    </body>
    </html>
    """

@socketio.on('connect')
def on_connect():
    client_id = request.sid
    start_pty_process(client_id)

@socketio.on('terminal_input')
def handle_terminal_input(json_data):
    client_id = request.sid
    data = json_data.get('data')
    if client_id in master_fd_dict:
        os.write(master_fd_dict[client_id], data.encode())

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', debug=True) # will need to adjust this for tun0 im assuming
