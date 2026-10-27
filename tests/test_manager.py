#!/usr/bin/env python3
"""ss-manager end to end: add a server over the control socket, relay through
it with ss-local, see its traffic in ping, list it, and remove it; over UDP
and over a unix socket."""
import argparse
import json
import os
from pathlib import Path
import socket
import stat as statmode
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


def unix_control(path, message, timeout=5):
    with tempfile.TemporaryDirectory() as temp, socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.bind(os.path.join(temp, "c"))
        sock.settimeout(timeout)
        sock.sendto(message.encode(), path)
        return sock.recvfrom(65535)[0].decode().rstrip("\0")


def wait_closed(port, deadline=10):
    end = time.monotonic() + deadline
    while time.monotonic() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                time.sleep(.05)
        except OSError:
            return
    raise AssertionError(f"managed server on {port} kept running")


def relay_and_count(bins, ask, server_port, local_port, origin):
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
        stat = json.loads(ask("ping")[len("stat: "):])
        traffic = stat.get(str(server_port), 0)
        time.sleep(.5)
    assert traffic > 0, "no traffic statistics from the managed server"


def unix_socket_case(bins, origin):
    server_port, local_port = free_port(), free_port()
    with tempfile.TemporaryDirectory() as workdir:
        path = os.path.join(workdir, "m.sock")
        manager = subprocess.Popen(
            [str(bins / "ss-manager"), "--manager-address", path, "--executable", str(bins / "ss-server"),
             "-D", workdir, "-s", "127.0.0.1", "-m", "aes-256-gcm"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        ask = lambda message: unix_control(path, message)
        try:
            for _ in range(50):
                if os.path.exists(path):
                    break
                time.sleep(.1)
            # No authentication on the control socket: only its owner may use it.
            assert statmode.S_IMODE(os.stat(path).st_mode) == 0o600, oct(os.stat(path).st_mode)
            assert ask('add: {"server_port": %d, "password": "secret"}' % server_port) == "ok"
            wait_listening(server_port)
            relay_and_count(bins, ask, server_port, local_port, origin)
            assert ask('remove: {"server_port": %d}' % server_port) == "ok"
        finally:
            manager.terminate()
            out = manager.communicate(timeout=10)[0].decode(errors="replace")
        assert manager.returncode == 0, f"ss-manager exited with {manager.returncode}:\n{out}"


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
            conf = Path(workdir) / f".shadowsocks_{server_port}.conf"
            # The config holds the password.
            assert statmode.S_IMODE(conf.stat().st_mode) == 0o600, oct(conf.stat().st_mode)
            relay_and_count(bins, lambda message: control(manager_port, message), server_port, local_port, origin)
            listed = json.loads(control(manager_port, "list"))
            assert any(entry.get("server_port") == str(server_port) for entry in listed), listed
            assert control(manager_port, 'remove: {"server_port": %d}' % server_port) == "ok"
            assert json.loads(control(manager_port, "list")) == [], "server still listed after remove"
            assert not conf.exists(), "the config (and its password) outlived remove"
            # "0<port>" names the same server as "<port>".
            reply = control(manager_port, 'add: {"server_port": "0%d", "password": "secret"}' % server_port)
            assert reply == "ok", reply
            wait_listening(server_port)
            listed = json.loads(control(manager_port, "list"))
            assert [entry.get("server_port") for entry in listed] == [str(server_port)], listed
            assert control(manager_port, 'remove: {"server_port": %d}' % server_port) == "ok"
            wait_closed(server_port)
            # A per-server plugin names a program to run: not over UDP.
            reply = control(manager_port,
                            'add: {"server_port": %d, "password": "x", "plugin": "/bin/true"}' % server_port)
            assert reply != "ok", "a plugin was accepted over the UDP control channel"
            assert json.loads(control(manager_port, "list")) == []
        finally:
            manager.terminate()
            out = manager.communicate(timeout=10)[0].decode(errors="replace")
        assert manager.returncode == 0, f"ss-manager exited with {manager.returncode}:\n{out}"
        unix_socket_case(bins, origin)
        # Over IP the unauthenticated protocol is loopback-only.
        refused = subprocess.run(
            [str(bins / "ss-manager"), "--manager-address", f"0.0.0.0:{free_port()}",
             "--executable", str(bins / "ss-server"), "-D", workdir, "-m", "aes-256-gcm"],
            capture_output=True, timeout=10)
        assert refused.returncode != 0, "ss-manager listened on a non-loopback address"
    print("PASS ss-manager add/ping/list/remove with traffic statistics (UDP and unix socket)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
