#!/usr/bin/env python3
"""TCP half-close through ss-local and ss-server: a client that sends its
request and then shuts down its write side still gets the whole response,
and the origin sees the EOF."""
import argparse
import hashlib
import os
from pathlib import Path
import socket
import socketserver
import threading

from interop import free_port, peers, socks


class ReplyAfterEOF(socketserver.BaseRequestHandler):
    """Reads to EOF, then answers with the digest and a large body."""

    def handle(self):
        self.request.settimeout(15)
        digest = hashlib.sha256()
        while chunk := self.request.recv(65536):
            digest.update(chunk)
        body = digest.digest() * 32768  # 1 MiB
        self.request.sendall(body)


class Origin(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", required=True, type=Path)
    args = parser.parse_args()
    bins = args.bin.resolve()
    with Origin(("127.0.0.1", 0), ReplyAfterEOF) as origin:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        for method in ("aes-256-gcm", "2022-blake3-aes-128-gcm"):
            key = ["-k", "pw"] if not method.startswith("2022") else ["-k", "AAAAAAAAAAAAAAAAAAAAAA=="]
            sport, lport = free_port(), free_port()
            server = [str(bins / "ss-server"), "-s", "127.0.0.1", "-p", str(sport), "-m", method] + key
            local = [str(bins / "ss-local"), "-s", "127.0.0.1", "-p", str(sport), "-l", str(lport), "-m",
                     method] + key
            with peers([server, local], [sport, lport]):
                sock, _ = socks(lport, 1, ("127.0.0.1", origin.server_address[1]))
                with sock:
                    sock.settimeout(15)
                    request = os.urandom(200000)
                    sock.sendall(request)
                    sock.shutdown(socket.SHUT_WR)
                    received = bytearray()
                    while chunk := sock.recv(65536):
                        received += chunk
                expected = hashlib.sha256(request).digest() * 32768
                assert bytes(received) == expected, \
                    f"{method}: got {len(received)} of {len(expected)} bytes after a half-close"
            print(f"PASS half-close: {method}")


if __name__ == "__main__":
    main()
