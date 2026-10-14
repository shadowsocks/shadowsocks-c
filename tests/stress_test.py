#!/usr/bin/env python3
"""
Stress test for shadowsocks-libev: measures bandwidth on loopback
with different ciphers using ss-server and ss-tunnel, and monitors
for memory leaks.

Usage:
    python3 tests/stress_test.py --bin build/bin/
    python3 tests/stress_test.py --bin build/bin/ --size 50 --duration 10
    python3 tests/stress_test.py --bin build/bin/ --cipher aes-256-gcm
"""

from __future__ import print_function
import argparse
import json
import os
import platform
import signal
import socket
import sys
import threading
import time
from subprocess import Popen

# Ciphers to test (the stream ciphers were removed).
AEAD_CIPHERS = [
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
]


# Ports (picked high to avoid conflicts)
SERVER_PORT = 18388
TUNNEL_LOCAL_PORT = 18389
SINK_PORT = 18390


def get_rss_kb(pid):
    """Get resident set size in KB for a process."""
    system = platform.system()
    try:
        if system == "Linux":
            with open("/proc/%d/status" % pid) as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1])
        elif system == "Darwin":
            import subprocess
            out = subprocess.check_output(
                ["ps", "-o", "rss=", "-p", str(pid)],
                stderr=subprocess.DEVNULL
            ).decode().strip()
            if out:
                return int(out)
    except (IOError, OSError, ValueError):
        pass
    return None


class SinkServer:
    """A simple TCP server that accepts connections and discards all data.
    Sends back a small acknowledgement per chunk so the sender knows
    data was received (for accurate bandwidth measurement)."""

    def __init__(self, port):
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(5)
        self.sock.settimeout(1.0)
        self.running = True
        self.bytes_received = 0
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
                t = threading.Thread(
                    target=self._handle, args=(conn,), daemon=True
                )
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle(self, conn):
        conn.settimeout(5.0)
        try:
            while self.running:
                data = conn.recv(65536)
                if not data:
                    break
                self.bytes_received += len(data)
        except (socket.timeout, OSError):
            pass
        finally:
            conn.close()

    def stop(self):
        self.running = False
        self.sock.close()
        self.thread.join(timeout=3)


def server_args(ss_server, cipher, password, server_port):
    """Build command-line args for ss-server."""
    return [
        ss_server,
        "-s", "127.0.0.1",
        "-p", str(server_port),
        "-k", password,
        "-m", cipher,
    ]


def tunnel_args(ss_tunnel, cipher, password, server_port, local_port, fwd_host, fwd_port):
    """Build command-line args for ss-tunnel."""
    return [
        ss_tunnel,
        "--server", "127.0.0.1:%d" % server_port,
        "-l", str(local_port),
        "-k", password,
        "-m", cipher,
        "-L", "%s:%d" % (fwd_host, fwd_port),
    ]


def kill_proc(proc):
    """Kill a process gracefully."""
    if proc and proc.poll() is None:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass


def run_bandwidth_test(bin_dir, cipher, data_size_mb, password="stress_test_pw"):
    """Run a single bandwidth test with the given cipher.

    Returns dict with: cipher, bandwidth_mbps, duration_sec,
    server_rss_before_kb, server_rss_after_kb, tunnel_rss_before_kb,
    tunnel_rss_after_kb, bytes_transferred, error
    """
    result = {
        "cipher": cipher,
        "bandwidth_mbps": 0,
        "duration_sec": 0,
        "bytes_transferred": 0,
        "server_rss_before_kb": None,
        "server_rss_after_kb": None,
        "tunnel_rss_before_kb": None,
        "tunnel_rss_after_kb": None,
        "error": None,
    }

    ss_server_bin = os.path.join(bin_dir, "ss-server")
    ss_tunnel_bin = os.path.join(bin_dir, "ss-tunnel")

    if not os.path.isfile(ss_server_bin) or not os.path.isfile(ss_tunnel_bin):
        result["error"] = "binaries not found in %s" % bin_dir
        return result

    server_proc = None
    tunnel_proc = None
    sink = None
    devnull = open(os.devnull, "w")

    try:
        # Start sink server (the destination ss-tunnel forwards to)
        sink = SinkServer(SINK_PORT)

        # Start ss-server
        server_proc = Popen(
            server_args(ss_server_bin, cipher, password, SERVER_PORT),
            stdout=devnull, stderr=devnull, close_fds=True
        )

        # Start ss-tunnel forwarding to the sink
        tunnel_proc = Popen(
            tunnel_args(ss_tunnel_bin, cipher, password, SERVER_PORT,
                        TUNNEL_LOCAL_PORT, "127.0.0.1", SINK_PORT),
            stdout=devnull, stderr=devnull, close_fds=True
        )

        # Wait for processes to start and bind ports
        # Don't probe the ports as ss-tunnel crashes on empty connections
        time.sleep(3.0)

        if server_proc.poll() is not None:
            result["error"] = "ss-server exited prematurely (code %d)" % server_proc.returncode
            return result

        if tunnel_proc.poll() is not None:
            result["error"] = "ss-tunnel exited prematurely (code %d)" % tunnel_proc.returncode
            return result

        # Record RSS before
        result["server_rss_before_kb"] = get_rss_kb(server_proc.pid)
        result["tunnel_rss_before_kb"] = get_rss_kb(tunnel_proc.pid)

        # Send data through the tunnel
        chunk_size = 64 * 1024  # 64KB chunks
        total_bytes = data_size_mb * 1024 * 1024
        data_chunk = b"\x00" * chunk_size

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        try:
            sock.connect(("127.0.0.1", TUNNEL_LOCAL_PORT))
        except (socket.error, OSError) as e:
            result["error"] = "connect to tunnel failed: %s" % e
            return result

        sent = 0
        start_time = time.time()

        try:
            while sent < total_bytes:
                remaining = total_bytes - sent
                to_send = min(chunk_size, remaining)
                if to_send < chunk_size:
                    data_chunk = b"\x00" * to_send
                sock.sendall(data_chunk)
                sent += to_send
        except (socket.error, OSError) as e:
            result["error"] = "send error at %d bytes: %s" % (sent, e)
        finally:
            elapsed = time.time() - start_time
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            sock.close()

        # Wait a bit for data to flow through
        time.sleep(0.5)

        result["bytes_transferred"] = sent
        result["duration_sec"] = elapsed
        if elapsed > 0:
            result["bandwidth_mbps"] = (sent * 8) / (elapsed * 1e6)

        # Record RSS after
        result["server_rss_after_kb"] = get_rss_kb(server_proc.pid)
        result["tunnel_rss_after_kb"] = get_rss_kb(tunnel_proc.pid)

    except Exception as e:
        result["error"] = str(e)
    finally:
        kill_proc(tunnel_proc)
        kill_proc(server_proc)
        if sink:
            sink.stop()
        devnull.close()

    return result


def format_size(nbytes):
    if nbytes >= 1024 * 1024 * 1024:
        return "%.1f GB" % (nbytes / (1024 * 1024 * 1024))
    elif nbytes >= 1024 * 1024:
        return "%.1f MB" % (nbytes / (1024 * 1024))
    elif nbytes >= 1024:
        return "%.1f KB" % (nbytes / 1024)
    return "%d B" % nbytes


def format_rss(kb):
    if kb is None:
        return "N/A"
    if kb >= 1024:
        return "%.1f MB" % (kb / 1024.0)
    return "%d KB" % kb


def main():
    parser = argparse.ArgumentParser(
        description="Stress test ss-server + ss-tunnel bandwidth on loopback"
    )
    parser.add_argument(
        "--bin", type=str, required=True,
        help="Path to directory containing ss-server and ss-tunnel binaries"
    )
    parser.add_argument(
        "--size", type=int, default=100,
        help="Data size to transfer per cipher in MB (default: 100)"
    )
    parser.add_argument(
        "--cipher", type=str, default=None,
        help="Test only this specific cipher"
    )
    parser.add_argument(
        "--repeat", type=int, default=1,
        help="Number of times to repeat each cipher test (default: 1)"
    )
    parser.add_argument(
        "--leak-threshold", type=int, default=10240,
        help="RSS growth threshold in KB to flag as potential leak (default: 10240)"
    )
    parser.add_argument(
        "--json", type=str, default=None,
        help="Write results as JSON to this file"
    )
    args = parser.parse_args()

    # Determine ciphers to test
    if args.cipher:
        ciphers = [args.cipher]
    else:
        ciphers = AEAD_CIPHERS

    print("=" * 72)
    print("shadowsocks-libev stress test")
    print("=" * 72)
    print("  Binaries : %s" % os.path.abspath(args.bin))
    print("  Data size: %d MB per cipher" % args.size)
    print("  Ciphers  : %s" % ", ".join(ciphers))
    print("  Repeats  : %d" % args.repeat)
    print("=" * 72)
    print()

    all_results = []
    leak_warnings = []

    for cipher in ciphers:
        for run in range(args.repeat):
            label = cipher
            if args.repeat > 1:
                label = "%s (run %d/%d)" % (cipher, run + 1, args.repeat)

            sys.stdout.write("Testing %-35s ... " % label)
            sys.stdout.flush()

            result = run_bandwidth_test(args.bin, cipher, args.size)
            all_results.append(result)

            if result["error"]:
                print("FAILED: %s" % result["error"])
                continue

            bw = result["bandwidth_mbps"]
            dur = result["duration_sec"]
            print("%8.1f Mbps  (%5.2fs, %s)" % (
                bw, dur, format_size(result["bytes_transferred"])
            ))

            # Check for memory leaks
            for role in ["server", "tunnel"]:
                before = result["%s_rss_before_kb" % role]
                after = result["%s_rss_after_kb" % role]
                if before is not None and after is not None:
                    growth = after - before
                    if growth > args.leak_threshold:
                        msg = (
                            "  WARNING: ss-%s RSS grew by %s "
                            "(%s -> %s) during %s test"
                            % (role, format_rss(growth),
                               format_rss(before), format_rss(after), cipher)
                        )
                        print(msg)
                        leak_warnings.append(msg)

    # Summary
    print()
    print("=" * 72)
    print("RESULTS SUMMARY")
    print("=" * 72)
    print()
    print("%-30s %10s %8s %12s %12s" % (
        "Cipher", "Bandwidth", "Time", "Server RSS", "Tunnel RSS"
    ))
    print("-" * 72)

    for r in all_results:
        if r["error"]:
            print("%-30s %10s" % (r["cipher"], "FAILED"))
            continue

        srv_rss = ""
        tun_rss = ""
        if r["server_rss_before_kb"] and r["server_rss_after_kb"]:
            srv_rss = "%s->%s" % (
                format_rss(r["server_rss_before_kb"]),
                format_rss(r["server_rss_after_kb"])
            )
        if r["tunnel_rss_before_kb"] and r["tunnel_rss_after_kb"]:
            tun_rss = "%s->%s" % (
                format_rss(r["tunnel_rss_before_kb"]),
                format_rss(r["tunnel_rss_after_kb"])
            )
        print("%-30s %7.1f Mbps %6.2fs %12s %12s" % (
            r["cipher"], r["bandwidth_mbps"], r["duration_sec"],
            srv_rss or "N/A", tun_rss or "N/A"
        ))

    if leak_warnings:
        print()
        print("MEMORY LEAK WARNINGS:")
        for w in leak_warnings:
            print(w)
        print()
        sys.exit(1)

    print()
    passed = [r for r in all_results if not r["error"]]
    failed = [r for r in all_results if r["error"]]
    print("%d passed, %d failed" % (len(passed), len(failed)))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(all_results, f, indent=2)
        print("Results written to %s" % args.json)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
