#!/usr/bin/env python3
"""ss-tunnel against ss-server (and shadowsocks-rust when present): concurrent TCP
transfers and a UDP round trip through a fixed tunnel target, for every method."""
import argparse
import base64
import concurrent.futures
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading

from interop import TCPHandler, TCPOrigin, UDPHandler, UDPOrigin, free_port, peers, receive

METHODS = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
           "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"]


def tcp_case(port, size):
    payload = os.urandom(size)
    with socket.create_connection(("127.0.0.1", port), timeout=15) as sock, \
            concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        upload = pool.submit(sock.sendall, payload)
        assert receive(sock, size) == payload, "TCP payload mismatch"
        upload.result(timeout=15)


def udp_case(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(.5)
        for size in (1, 1200):
            payload = os.urandom(size)
            # The UDP-only tunnel has no TCP port to wait on: retry until up.
            for attempt in range(20):
                sock.sendto(payload, ("127.0.0.1", port))
                try:
                    reply, _ = sock.recvfrom(65535)
                    break
                except TimeoutError:
                    if attempt == 19:
                        raise
            assert reply == payload, "UDP payload mismatch"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", required=True, type=Path)
    parser.add_argument("--fast-open", action="store_true")
    args = parser.parse_args()
    bins = args.bin.resolve()
    server, tunnel = str(bins / "ss-server"), str(bins / "ss-tunnel")
    rust_server = shutil.which("ssserver")
    failures = 0
    with TCPOrigin(("127.0.0.1", 0), TCPHandler) as tcp, UDPOrigin(("127.0.0.1", 0), UDPHandler) as udp:
        for origin in (tcp, udp):
            threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            for method in METHODS:
                for peer in ("C server",) + (("Rust server",) if rust_server else ()):
                    key = base64.b64encode(os.urandom(16 if "aes-128" in method else 32)).decode()
                    secret = ["-k", key]
                    sport, tport, uport = free_port(), free_port(), free_port()
                    if peer == "C server":
                        srv = [server, "-s", "127.0.0.1", "-p", str(sport), "-m", method, "-u"] + secret
                    else:
                        srv = [rust_server, "-s", f"127.0.0.1:{sport}", "-m", method, "-U"] + secret
                    extra = ["--fast-open"] if args.fast_open else []
                    tcp_tunnel = [tunnel, "-s", "127.0.0.1", "-p", str(sport), "-l", str(tport), "-m", method,
                                  "-L", f"127.0.0.1:{tcp.server_address[1]}"] + secret + extra
                    udp_tunnel = [tunnel, "-s", "127.0.0.1", "-p", str(sport), "-l", str(uport), "-m", method,
                                  "-U", "-L", f"127.0.0.1:{udp.server_address[1]}"] + secret
                    label = f"{method}: tunnel -> {peer}"
                    try:
                        with peers([srv, tcp_tunnel], [sport, tport]):
                            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                                cases = [pool.submit(tcp_case, tport, size) for size in (1, 4096, 65536, 1048576)]
                                for case in cases:
                                    case.result(timeout=60)
                            udp_proc = subprocess.Popen(udp_tunnel, stdout=subprocess.DEVNULL,
                                                        stderr=subprocess.DEVNULL)
                            try:
                                udp_case(uport)
                            finally:
                                udp_proc.terminate()
                                udp_proc.wait(timeout=5)
                        print("PASS " + label, flush=True)
                    except (OSError, AssertionError, TimeoutError) as error:
                        failures += 1
                        print(f"FAIL {label}: {error!r}", flush=True)
        finally:
            tcp.shutdown()
            udp.shutdown()
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())
