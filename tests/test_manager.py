#!/usr/bin/env python3
"""ss-manager end to end: add a server over the control socket, relay through
it with ss-local, see its traffic in ping, list it, and remove it."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from interop import TCPHandler, TCPOrigin, free_port, peers, receive, socks


def control(port, message, timeout=5):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(message.encode(), ("127.0.0.1", port))
        return sock.recvfrom(65535)[0].decode().rstrip("\0")


def wait_listening(port, deadline=10):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError(f"managed server did not listen on {port}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", required=True, type=Path)
    args = parser.parse_args()
    bins = args.bin.resolve()
    manager_port, server_port, local_port = free_port(), free_port(), free_port()
    with TCPOrigin(("127.0.0.1", 0), TCPHandler) as origin, tempfile.TemporaryDirectory() as workdir:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        manager = subprocess.Popen(
            [str(bins / "ss-manager"), "--manager-address", f"127.0.0.1:{manager_port}",
             "--executable", str(bins / "ss-server"), "-D", workdir, "-s", "127.0.0.1",
             "-m", "aes-256-gcm"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            # The manager answers once its control socket is up.
            for _ in range(50):
                try:
                    reply = control(manager_port, "ping", timeout=.2)
                    break
                except (TimeoutError, OSError):
                    time.sleep(.1)
            else:
                raise AssertionError("ss-manager did not answer")
            assert reply.startswith("stat:"), reply
            reply = control(manager_port, 'add: {"server_port": %d, "password": "secret"}' % server_port)
            assert reply == "ok", reply
            wait_listening(server_port)
            local = [str(bins / "ss-local"), "-s", "127.0.0.1", "-p", str(server_port), "-l", str(local_port),
                     "-k", "secret", "-m", "aes-256-gcm"]
            with peers([local], [local_port]):
                sock, _ = socks(local_port, 1, ("127.0.0.1", origin.server_address[1]))
                payload = os.urandom(65536)
                with sock:
                    sock.sendall(payload)
                    assert receive(sock, len(payload)) == payload, "relay through the managed server failed"
            # ss-server reports traffic to the manager every few seconds.
            deadline = time.monotonic() + 15
            traffic = 0
            while time.monotonic() < deadline and traffic == 0:
                stat = json.loads(control(manager_port, "ping")[len("stat: "):])
                traffic = stat.get(str(server_port), 0)
                time.sleep(.5)
            assert traffic > 0, "no traffic statistics from the managed server"
            listed = json.loads(control(manager_port, "list"))
            assert any(entry.get("server_port") == str(server_port) for entry in listed), listed
            assert control(manager_port, 'remove: {"server_port": %d}' % server_port) == "ok"
            assert json.loads(control(manager_port, "list")) == [], "server still listed after remove"
        finally:
            manager.terminate()
            out = manager.communicate(timeout=10)[0].decode(errors="replace")
        assert manager.returncode == 0, f"ss-manager exited with {manager.returncode}:\n{out}"
    print("PASS ss-manager add/ping/list/remove with traffic statistics")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
