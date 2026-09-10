#!/usr/bin/env python3
"""Real TCP/UDP interoperability, independent of HTTP proxy environment variables."""
import argparse
import base64
import concurrent.futures
import contextlib
import os
from pathlib import Path
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            while chunk := self.request.recv(16384):
                self.request.sendall(chunk)
        except (OSError, TimeoutError):
            pass


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


class TCPOrigin(socketserver.ThreadingTCPServer):
    daemon_threads = True


class UDPOrigin(socketserver.ThreadingUDPServer):
    daemon_threads = True


def receive(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise AssertionError(f"unexpected EOF after {len(data)}/{size} bytes")
        data.extend(chunk)
    return bytes(data)


def address(sock, kind):
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, receive(sock, 4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, receive(sock, 16))
    elif kind == 3:
        host = receive(sock, receive(sock, 1)[0]).decode("ascii")
    else:
        raise AssertionError(f"invalid SOCKS address type {kind}")
    return host, struct.unpack("!H", receive(sock, 2))[0]


def socks(proxy_port, command, destination):
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00", "SOCKS authentication failed"
        host, port = destination
        encoded = host.encode("ascii")
        sock.sendall(bytes([5, command, 0, 3, len(encoded)]) + encoded + struct.pack("!H", port))
        header = receive(sock, 4)
        assert header[:3] == b"\x05\x00\x00", f"SOCKS request failed: {header.hex()}"
        relay = address(sock, header[3])
        return sock, relay
    except BaseException:
        sock.close()
        raise


def tcp_case(proxy_port, origin_port, size):
    sock, _ = socks(proxy_port, 1, ("localhost", origin_port))
    payload = os.urandom(size)
    with sock, concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        # Upload and download concurrently to exercise backpressure in both directions.
        upload = pool.submit(sock.sendall, payload)
        assert receive(sock, len(payload)) == payload, "TCP payload mismatch"
        upload.result(timeout=10)


def udp_case(proxy_port, origin_port):
    control, relay = socks(proxy_port, 3, ("0.0.0.0", 0))
    host, port = relay
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10)
        for size in (1, 128, 1200, 4096):
            payload = os.urandom(size)
            header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", origin_port)
            sock.sendto(header + payload, (host, port))
            try:
                reply, sender = sock.recvfrom(65535)
            except TimeoutError as error:
                raise AssertionError(f"UDP timeout for {size}-byte payload") from error
            assert sender[1] == port, "UDP reply bypassed relay"
            assert reply[:3] == b"\x00\x00\x00", "fragmented or invalid SOCKS UDP reply"
            if reply[3] == 1:
                offset = 10
            elif reply[3] == 4:
                offset = 22
            elif reply[3] == 3:
                offset = 7 + reply[4]
            else:
                raise AssertionError("invalid UDP address type")
            assert reply[offset:] == payload, "UDP payload mismatch"


def free_port():
    # TCP and UDP have separate port reservations, especially on Windows.
    # Probe both while holding the TCP socket so a TCP-only free port cannot
    # select a reserved or occupied UDP endpoint.
    for _ in range(100):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("could not find a free TCP/UDP port")


def wait_ready(process, port):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"peer exited with {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                return
        except OSError:
            time.sleep(.03)
    raise AssertionError(f"peer failed to listen on port {port}")


@contextlib.contextmanager
def peers(commands, ports, environment=None):
    processes = []
    with tempfile.TemporaryDirectory(prefix="ss-interop-") as temp, contextlib.ExitStack() as stack:
        logs = []
        try:
            for index, (command, port) in enumerate(zip(commands, ports)):
                path = Path(temp) / f"peer-{index}.log"
                log = stack.enter_context(path.open("wb"))
                logs.append(path)
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=environment)
                processes.append(process)
                wait_ready(process, port)
            yield
        except BaseException:
            for path in logs:
                print(path.name + ":\n" + path.read_text(errors="replace")[-6000:], flush=True)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self", action="store_true", help="use this build for both peers")
    parser.add_argument("--method", help="run one cipher")
    parser.add_argument("--bin", default=os.environ.get("SS_BIN_DIR", "build/bin"), help="program directory")
    parser.add_argument("--plugin", help="SIP003 fixture executable (requires --self)")
    parser.add_argument("--isolate-windows-runtime", action="store_true",
                        help="remove MSYS2/toolchain DLL directories from child PATH")
    args = parser.parse_args()
    if args.plugin and not args.self:
        parser.error("--plugin requires --self")
    environment = None
    if args.isolate_windows_runtime:
        if os.name != "nt":
            parser.error("--isolate-windows-runtime requires Windows")
        environment = os.environ.copy()
        system_root = os.environ["SYSTEMROOT"]
        environment["PATH"] = os.pathsep.join((system_root, os.path.join(system_root, "System32")))
    binary_dir = Path(args.bin).resolve()
    suffix = ".exe" if os.name == "nt" else ""
    local, server = [str(binary_dir / (name + suffix)) for name in ("ss-local", "ss-server")]
    rust_local, rust_server = shutil.which("sslocal"), shutil.which("ssserver")
    missing = [p for p in (local, server) if not os.path.isfile(p)]
    if not args.self:
        missing += [name for name, found in (("sslocal", rust_local), ("ssserver", rust_server)) if not found]
    if missing:
        print("Missing interoperability prerequisites: " + ", ".join(missing))
        return 1 if os.environ.get("SS_REQUIRE_INTEROP") == "1" else 77
    methods = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
               "2022-blake3-chacha20-poly1305", "aes-128-gcm", "aes-256-gcm",
               "chacha20-ietf-poly1305"]
    if args.method:
        methods = [args.method]
    failures = 0
    with TCPOrigin(("127.0.0.1", 0), TCPHandler) as tcp, UDPOrigin(("127.0.0.1", 0), UDPHandler) as udp:
        for origin in (tcp, udp):
            threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            for method in methods:
                key_size = 16 if method == "2022-blake3-aes-128-gcm" else 32
                psk = base64.b64encode(os.urandom(key_size)).decode("ascii")
                directions = ("self",) if args.self else ("C client -> Rust server", "Rust client -> C server")
                for direction in directions:
                    label = f"{method}: {direction}"
                    print("RUN " + label, flush=True)
                    server_port, local_port = free_port(), free_port()
                    c_server = [server, "-s", "127.0.0.1", "-p", str(server_port), "-k", psk, "-m", method, "-u"]
                    c_local = [local, "-s", "127.0.0.1", "-p", str(server_port), "-l", str(local_port), "-k", psk, "-m", method, "-u"]
                    commands = [c_server, c_local]
                    plugin_temp = tempfile.TemporaryDirectory(prefix="ss-plugin-") if args.plugin else None
                    markers = []
                    if args.plugin:
                        for mode, command in zip(("server", "client"), commands):
                            marker = Path(plugin_temp.name) / mode
                            markers.append(marker)
                            command.extend(["--plugin", str(Path(args.plugin).resolve()),
                                            "--plugin-opts", f"{mode};marker={marker}"])
                    if direction.startswith("C client"):
                        commands[0] = [rust_server, "-s", f"127.0.0.1:{server_port}", "-k", psk, "-m", method, "-U"]
                    elif direction.startswith("Rust client"):
                        commands[1] = [rust_local, "-b", f"127.0.0.1:{local_port}", "-s", f"127.0.0.1:{server_port}", "-k", psk, "-m", method, "-U"]
                    try:
                        with peers(commands, [server_port, local_port], environment):
                            for marker in markers:
                                deadline = time.monotonic() + 10
                                while not marker.exists() and time.monotonic() < deadline:
                                    time.sleep(.03)
                                assert marker.exists(), "plugin did not become ready"
                            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                                cases = [pool.submit(tcp_case, local_port, tcp.server_address[1], size)
                                         for size in (1, 65536, 1048576)]
                                for case in cases:
                                    case.result(timeout=30)
                            udp_case(local_port, udp.server_address[1])
                        for marker in markers:
                            pid = int(marker.read_text())
                            try:
                                os.kill(pid, 0)
                            except ProcessLookupError:
                                pass
                            else:
                                raise AssertionError(f"plugin child {pid} survived parent shutdown")
                        print("PASS TCP (3 concurrent streams) + UDP: " + label, flush=True)
                    except (OSError, AssertionError, TimeoutError) as error:
                        failures += 1
                        print(f"FAIL {label}: {error}", flush=True)
                    finally:
                        if plugin_temp is not None:
                            plugin_temp.cleanup()
        finally:
            tcp.shutdown()
            udp.shutdown()
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())
