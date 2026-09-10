#!/usr/bin/env python3
"""Transparent SIP003 test transport; never used as a production plugin."""
import os
from pathlib import Path
import socket
import socketserver
import threading

mode, marker = os.environ["SS_PLUGIN_OPTIONS"].split(";marker=", 1)
local = (os.environ["SS_LOCAL_HOST"], int(os.environ["SS_LOCAL_PORT"]))
remote = (os.environ["SS_REMOTE_HOST"], int(os.environ["SS_REMOTE_PORT"]))
listen, destination = (remote, local) if mode == "server" else (local, remote)


def copy(source, target):
    try:
        while data := source.recv(16384):
            target.sendall(data)
        target.shutdown(socket.SHUT_WR)
    except OSError:
        pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with socket.create_connection(destination, timeout=10) as upstream:
                self.request.settimeout(10)
                thread = threading.Thread(target=copy, args=(self.request, upstream), daemon=True)
                thread.start()
                copy(upstream, self.request)
                thread.join(timeout=10)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


with Server(listen, Handler) as server:
    Path(marker).write_text(str(os.getpid()), encoding="ascii")
    server.serve_forever()
