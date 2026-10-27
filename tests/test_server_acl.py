#!/usr/bin/env python3
"""ss-server --acl: the outbound block list stops TCP and UDP alike, also
for an IPv4-mapped IPv6 target, and an idle handshake does not hold a
connection slot past --timeout."""
import argparse
import subprocess
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import time

from interop import TCPHandler, TCPOrigin, UDPHandler, UDPOrigin, free_port, peers, receive, socks


def tcp_reaches(lport, host, port):
    try:
        sock, _ = socks(lport, 1, (host, port))
    except (OSError, AssertionError):
        return False
    with sock:
        sock.settimeout(3)
        try:
            sock.sendall(b"ping")
            return receive(sock, 4) == b"ping"
        except (OSError, AssertionError):
            return False


def udp_reaches(lport, port):
    control, relay = socks(lport, 3, ("0.0.0.0", 0))
    host, rport = relay
    if host in ("0.0.0.0", "::"):
        host = "127.0.0.1"
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        payload = os.urandom(32)
        header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", port)
        sock.sendto(header + payload, (host, rport))
        try:
            reply, _ = sock.recvfrom(65535)
        except (TimeoutError, socket.timeout):
            return False
        return reply.endswith(payload)


def run(bins, acl, check):
    sport, lport = free_port(), free_port()
    server = [str(bins / "ss-server"), "-s", "127.0.0.1", "-p", str(sport), "-k", "pw", "-m", "aes-256-gcm", "-u",
              "-t", "2", "--max-connections", "4"]
    if acl is not None:
        server += ["--acl", acl]
    local = [str(bins / "ss-local"), "-s", "127.0.0.1", "-p", str(sport), "-l", str(lport), "-k", "pw",
             "-m", "aes-256-gcm", "-u"]
    with peers([server, local], [sport, lport]):
        check(sport, lport)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", required=True, type=Path)
    args = parser.parse_args()
    bins = args.bin.resolve()
    with TCPOrigin(("127.0.0.1", 0), TCPHandler) as tcp_origin, UDPOrigin(("127.0.0.1", 0), UDPHandler) as udp_origin, \
            tempfile.TemporaryDirectory(prefix="ss-acl-") as temp:
        threading.Thread(target=tcp_origin.serve_forever, daemon=True).start()
        threading.Thread(target=udp_origin.serve_forever, daemon=True).start()
        tport, uport = tcp_origin.server_address[1], udp_origin.server_address[1]
        acl = Path(temp) / "block.acl"
        acl.write_text("[outbound_block_list]\n127.0.0.0/8\n")
        mapped = {}

        def open_relay(_, lport):
            assert tcp_reaches(lport, "127.0.0.1", tport), "TCP relay failed without an ACL"
            assert udp_reaches(lport, uport), "UDP relay failed without an ACL"
            # Whether this host connects ::ffff:127.0.0.1 at all (dual stack).
            mapped["works"] = tcp_reaches(lport, "::ffff:127.0.0.1", tport)

        def blocked(sport, lport):
            assert not tcp_reaches(lport, "127.0.0.1", tport), "TCP reached a blocked address"
            if mapped["works"]:
                assert not tcp_reaches(lport, "::ffff:127.0.0.1", tport), \
                    "TCP reached a blocked address through its IPv4-mapped form"
            assert not udp_reaches(lport, uport), "UDP reached a blocked address"
            # Sockets that never finish a handshake are closed after -t 2,
            # so they cannot hold the four slots.
            idle = [socket.create_connection(("127.0.0.1", sport)) for _ in range(4)]
            for sock in idle:
                sock.sendall(b"x")
            time.sleep(4)
            for sock in idle:
                sock.settimeout(2)
                try:
                    assert sock.recv(1) == b"", "an idle handshake outlived --timeout"
                except ConnectionResetError:
                    pass
                sock.close()

        run(bins, None, open_relay)
        run(bins, str(acl), blocked)

        # An ACL that cannot be loaded stops the server instead of running
        # it without the block list.
        bad = Path(temp) / "bad.acl"
        bad.write_text("[outbound_block_list]\n[unterminated\n")
        result = subprocess.run([str(bins / "ss-server"), "-s", "127.0.0.1", "-p", str(free_port()), "-k", "pw",
                                 "-m", "aes-256-gcm", "--acl", str(bad)], capture_output=True, timeout=10)
        assert result.returncode != 0, "ss-server started with an invalid ACL"
    print("PASS ss-server ACL (TCP, IPv4-mapped, UDP), handshake timeout, invalid ACL"
          + ("" if mapped.get("works") else " (no dual-stack: mapped case skipped)"))


if __name__ == "__main__":
    main()
