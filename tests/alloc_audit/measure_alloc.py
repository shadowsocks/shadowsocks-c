#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Count heap allocations per proxied TCP connection in ss-local and ss-server.

Both peers run with the alloc_counter shim preloaded. After a warm-up the
script snapshots each process's allocation counter, relays more connections,
and snapshots again. The difference, divided by the number of connections,
is what one connection costs in the steady state. The no-heap goal for the
C++ core is zero.

Report-only by default; --max-per-connection N turns it into a check.

Example:
    python3 tests/alloc_audit/measure_alloc.py --bin build/bin \\
        --shim build/lib/libss_alloc_audit.dylib --method aes-256-gcm
"""
import argparse
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from interop import (TCPHandler, TCPOrigin, UDPHandler, UDPOrigin, free_port, peers, receive, socks,  # noqa: E402
                     udp_case)


def read_snapshot(path, previous_lines, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = path.read_text().splitlines() if path.exists() else []
        if len(lines) > previous_lines:
            pid, allocations, frees, size = (int(v) for v in lines[-1].split())
            return {"pid": pid, "allocations": allocations, "frees": frees, "bytes": size}, len(lines)
        time.sleep(.02)
    raise AssertionError(f"no allocation snapshot written to {path}")


def snapshot_all(processes, outputs, counts):
    results = []
    for index, (process, path) in enumerate(zip(processes, outputs)):
        os.kill(process.pid, signal.SIGUSR2)
        result, counts[index] = read_snapshot(path, counts[index])
        results.append(result)
    return results


def tcp_case(local_port, target, origin_port, size):
    sock, _ = socks(local_port, 1, (target, origin_port))
    payload = os.urandom(size)
    with sock, concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        upload = pool.submit(sock.sendall, payload)
        assert receive(sock, len(payload)) == payload, "TCP payload mismatch"
        upload.result(timeout=10)


def relay(local_port, target, origin_port, connections, concurrency, size, udp=False):
    if udp:
        # Each case is a UDP association with four datagrams.
        for _ in range(connections):
            udp_case(local_port, origin_port)
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [pool.submit(tcp_case, local_port, target, origin_port, size) for _ in range(connections)]
        for future in futures:
            future.result(timeout=60)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bin", default="build/bin", help="directory with ss-local and ss-server")
    parser.add_argument("--shim", required=True, help="path to the alloc_counter shared library")
    parser.add_argument("--method", default="aes-256-gcm")
    parser.add_argument("--warmup", type=int, default=50, help="connections before the first snapshot")
    parser.add_argument("--connections", type=int, default=200, help="connections between snapshots")
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--size", type=int, default=16384, help="bytes echoed per connection")
    parser.add_argument("--max-per-connection", type=float, help="fail if any peer exceeds this")
    parser.add_argument("--udp", action="store_true", help="relay UDP associations instead of TCP streams")
    parser.add_argument("--target", default="localhost",
                        help="destination host sent to the server; a name makes the server resolve it")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args()

    binary_dir = Path(args.bin).resolve()
    shim = str(Path(args.shim).resolve())
    preload = "DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"
    key_size = 16 if args.method == "2022-blake3-aes-128-gcm" else 32
    password = base64.b64encode(os.urandom(key_size)).decode("ascii")

    origin_class, handler = (UDPOrigin, UDPHandler) if args.udp else (TCPOrigin, TCPHandler)
    with origin_class(("127.0.0.1", 0), handler) as origin, \
            tempfile.TemporaryDirectory(prefix="ss-alloc-") as temp:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        server_port, local_port = free_port(), free_port()
        names = ["ss-server", "ss-local"]
        outputs = [Path(temp) / f"{name}.counts" for name in names]
        udp = ["-u"] if args.udp else []
        commands = [
            [str(binary_dir / "ss-server"), "-s", "127.0.0.1", "-p", str(server_port),
             "-k", password, "-m", args.method] + udp,
            [str(binary_dir / "ss-local"), "-s", "127.0.0.1", "-p", str(server_port),
             "-l", str(local_port), "-k", password, "-m", args.method] + udp,
        ]
        environments = []
        for output in outputs:
            env = os.environ.copy()
            env[preload] = shim
            env["SS_ALLOC_AUDIT_OUT"] = str(output)
            environments.append(env)

        # peers() takes one environment for all of its commands, so each
        # peer gets its own context and its own output file.
        with peers([commands[0]], [server_port], environments[0]) as server, \
                peers([commands[1]], [local_port], environments[1]) as local:
            processes = server + local
            counts = [0, 0]
            relay(local_port, args.target, origin.server_address[1], args.warmup, args.concurrency, args.size, args.udp)
            time.sleep(.5)
            before = snapshot_all(processes, outputs, counts)
            relay(local_port, args.target, origin.server_address[1], args.connections, args.concurrency, args.size,
                  args.udp)
            time.sleep(.5)
            after = snapshot_all(processes, outputs, counts)

    report = {"method": args.method, "connections": args.connections, "size": args.size, "peers": {}}
    failed = False
    for name, b, a in zip(names, before, after):
        delta = a["allocations"] - b["allocations"]
        per = delta / args.connections
        report["peers"][name] = {
            "allocations": delta,
            "frees": a["frees"] - b["frees"],
            "bytes": a["bytes"] - b["bytes"],
            "allocations_per_connection": round(per, 2),
        }
        if args.max_per_connection is not None and per > args.max_per_connection:
            failed = True

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"method {args.method}, {args.connections} connections of {args.size} bytes to {args.target}")
        for name, peer in report["peers"].items():
            print(f"  {name:9} {peer['allocations_per_connection']:8.2f} allocations/connection "
                  f"({peer['allocations']} total, {peer['bytes']} bytes)")
    if failed:
        print(f"FAIL: more than {args.max_per_connection} allocations per connection")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
