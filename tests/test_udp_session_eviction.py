"""Exercise the production relay at the exact AEAD-2022 cache boundary."""
import argparse
import os
from pathlib import Path
import subprocess

from interop import free_port, peers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin', type=Path, required=True)
    parser.add_argument('--server', type=Path)
    parser.add_argument('--count', type=int, choices=(4095, 4096))
    args = parser.parse_args()
    binaries = args.bin.resolve()
    server = (args.server or binaries / 'ss-server').resolve()
    environment = dict(os.environ, UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    for method in ('2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
                   '2022-blake3-chacha20-poly1305'):
        key = ('AAAAAAAAAAAAAAAAAAAAAA==' if 'aes-128' in method else
               'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')
        for count in ((args.count,) if args.count else (4095, 4096)):
            port = free_port()
            command = [str(server), '-s', '127.0.0.1', '-p', str(port),
                       '-k', key, '-m', method, '-u', '-t', '60']
            with peers([command], [port], environment):
                subprocess.run([str(binaries / 'udp_session_eviction_client'),
                                str(port), str(count), method, key],
                               env=environment, check=True, timeout=45)
            print(f'{method}: {count} sessions, both replies verified', flush=True)


if __name__ == '__main__':
    main()
