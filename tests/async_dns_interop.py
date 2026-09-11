#!/usr/bin/env python3
"""Exercise client hostname ACL bypass with an unreachable proxy upstream."""
import argparse
import concurrent.futures
import os
from pathlib import Path
import tempfile
import threading
from interop import TCPOrigin, TCPHandler, free_port, peers, tcp_case


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', required=True, type=Path)
    parser.add_argument('--isolate-windows-runtime', action='store_true')
    args = parser.parse_args()
    environment = None
    if args.isolate_windows_runtime:
        environment = os.environ.copy()
        root = os.environ['SYSTEMROOT']
        environment['PATH'] = root + '\\System32;' + root
    local = args.bin.resolve() / ('ss-local.exe' if os.name == 'nt' else 'ss-local')
    with tempfile.TemporaryDirectory() as temp, TCPOrigin(('127.0.0.1', 0), TCPHandler) as origin:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            for policy in ('[bypass_all]\n', '[proxy_all]\n[bypass_list]\nfull:localhost\n'):
                acl = Path(temp) / 'acl'
                acl.write_text(policy)
                port, upstream = free_port(), free_port()
                command = [str(local), '-s', '127.0.0.1', '-p', str(upstream), '-l', str(port),
                           '-k', 'dns-integration', '-m', 'aes-128-gcm', '--acl', str(acl)]
                with peers([command], [port], environment):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                        futures = [pool.submit(tcp_case, port, origin.server_address[1], size)
                                   for size in (1, 65536, 1048576)]
                        for future in futures: future.result(timeout=15)
                print('PASS hostname ACL bypass: ' + policy.splitlines()[0], flush=True)
        finally:
            origin.shutdown()


if __name__ == '__main__':
    main()
