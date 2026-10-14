#!/usr/bin/env python3
"""--max-connections: connections beyond the limit are refused, and accepting
resumes once a slot frees."""
import argparse
from pathlib import Path
import socket
import threading
import time

from interop import TCPHandler, TCPOrigin, free_port, peers, receive, socks


def echo_once(sock):
    sock.sendall(b"ping")
    return receive(sock, 4) == b"ping"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", required=True, type=Path)
    args = parser.parse_args()
    bins = args.bin.resolve()
    with TCPOrigin(("127.0.0.1", 0), TCPHandler) as origin:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        sport, lport = free_port(), free_port()
        server = [str(bins / "ss-server"), "-s", "127.0.0.1", "-p", str(sport), "-k", "pw", "-m", "aes-256-gcm",
                  "--max-connections", "2"]
        local = [str(bins / "ss-local"), "-s", "127.0.0.1", "-p", str(sport), "-l", str(lport), "-k", "pw",
                 "-m", "aes-256-gcm"]
        with peers([server, local], [sport, lport]):
            target = ("127.0.0.1", origin.server_address[1])
            held = []
            for _ in range(2):
                sock, _ = socks(lport, 1, target)
                assert echo_once(sock), "connection within the limit failed"
                held.append(sock)
            # The third is refused by ss-server, so ss-local drops it.
            third, _ = socks(lport, 1, target)
            third.settimeout(3)
            try:
                refused = not echo_once(third)
            except (OSError, AssertionError):
                refused = True
            third.close()
            assert refused, "a connection beyond --max-connections was served"
            # Free a slot; accepting resumes.
            held.pop().close()
            deadline = time.monotonic() + 5
            while True:
                try:
                    sock, _ = socks(lport, 1, target)
                    sock.settimeout(3)
                    if echo_once(sock):
                        held.append(sock)
                        break
                except (OSError, AssertionError):
                    pass
                assert time.monotonic() < deadline, "accepting did not resume after a slot freed"
                time.sleep(.1)
            for sock in held:
                sock.close()
    print("PASS --max-connections refuses and recovers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
