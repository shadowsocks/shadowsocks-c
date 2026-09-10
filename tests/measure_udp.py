#!/usr/bin/env python3
"""Loopback UDP echo measurement; includes Python/SOCKS overhead, not a capacity test."""
import argparse
import base64
import json
import os
from pathlib import Path
import socket
import struct
import threading
import time
from interop import UDPOrigin, UDPHandler, free_port, peers, socks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    results = []
    with UDPOrigin(("127.0.0.1", 0), UDPHandler) as origin:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            for method in ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"):
                server_port, local_port = free_port(), free_port()
                key = base64.b64encode(os.urandom(32)).decode("ascii")
                common = ["-s", "127.0.0.1", "-p", str(server_port), "-m", method, "-k", key, "-u"]
                commands = [[str(args.bin.resolve() / "ss-server"), *common],
                            [str(args.bin.resolve() / "ss-local"), *common, "-l", str(local_port)]]
                with peers(commands, [server_port, local_port]):
                    control, relay = socks(local_port, 3, ("0.0.0.0", 0))
                    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                        udp.settimeout(5)
                        relay = ("127.0.0.1", relay[1])
                        prefix = b"\0\0\0\x01\x7f\0\0\x01" + struct.pack("!H", origin.server_address[1])
                        for trial in range(args.repeat):
                            start = time.perf_counter()
                            for sequence in range(args.count):
                                payload = struct.pack("!I", sequence) + bytes(1196)
                                udp.sendto(prefix + payload, relay)
                                response, sender = udp.recvfrom(65536)
                                assert sender[1] == relay[1] and response[10:] == payload
                            elapsed = time.perf_counter() - start
                            results.append(dict(cipher=method, trial=trial, packets=args.count,
                                                payload_bytes=1200, seconds=elapsed,
                                                payload_mbps=args.count * 1200 * 8 / elapsed / 1e6))
        finally:
            origin.shutdown()
    args.output.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()
