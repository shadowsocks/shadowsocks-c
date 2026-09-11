#!/usr/bin/env python3
"""Exercise the scratch server/client images with real TCP and UDP traffic."""
import argparse
import base64
import concurrent.futures
import json
import os
import socket
import time
from pathlib import Path
import subprocess
import tempfile
import threading
import uuid

import interop


def inside():
    # All three containers share an isolated network namespace. Only loopback
    # is needed, including for the server's localhost hostname resolution.
    for port in (8388, 1080):
        deadline = time.monotonic() + 15
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise AssertionError(f'container failed to listen on {port}')
                time.sleep(.05)
    with interop.TCPOrigin(('127.0.0.1', 0), interop.TCPHandler) as tcp, \
            interop.UDPOrigin(('127.0.0.1', 0), interop.UDPHandler) as udp:
        for origin in (tcp, udp):
            threading.Thread(target=origin.serve_forever, daemon=True).start()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                futures = [pool.submit(interop.tcp_case, 1080, tcp.server_address[1], size)
                           for size in (1, 65536, 1048576)]
                for future in futures:
                    future.result(timeout=30)
            interop.udp_case(1080, udp.server_address[1])
        finally:
            tcp.shutdown()
            udp.shutdown()
    print('PASS scratch image: concurrent TCP, hostname resolution, and UDP', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='shadowsocks-c:test')
    parser.add_argument('--python-image', default='python:3.12-alpine')
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        inside()
        return
    root = Path(__file__).resolve().parent
    name = 'ss-docker-test-' + uuid.uuid4().hex[:12]
    helper = name + '-helper'
    with tempfile.TemporaryDirectory(prefix='ss-docker-test-') as directory:
        context = Path(directory)
        for filename in ('interop.py', 'docker_smoke.py'):
            (context / filename).write_bytes((root / filename).read_bytes())
        (context / 'Dockerfile').write_text(
            'ARG PYTHON_IMAGE=python:3.12-alpine\nFROM ${PYTHON_IMAGE}\n'
            'COPY interop.py docker_smoke.py /tests/\n'
            'USER 65532:65532\nENTRYPOINT ["python3", "/tests/docker_smoke.py", "--inside"]\n')
        subprocess.run(['docker', 'build', '--build-arg', 'PYTHON_IMAGE=' + args.python_image,
                        '-t', helper, str(context)], check=True)
    try:
        for method in ('aes-256-gcm', '2022-blake3-aes-128-gcm'):
            containers = []
            volume = name + '-config'
            key = base64.b64encode(os.urandom(16)).decode('ascii')
            try:
                common = ['docker', 'run', '-d', '--read-only', '--cap-drop=ALL',
                          '--security-opt=no-new-privileges:true']
                server = name + '-server'
                client = name + '-client'
                subprocess.run(['docker', 'volume', 'create', volume], check=True,
                               stdout=subprocess.DEVNULL)
                config = json.dumps({'server': '0.0.0.0', 'server_port': 8388,
                                     'password': key, 'method': method, 'mode': 'tcp_and_udp'})
                subprocess.run(['docker', 'run', '--rm', '-i', '--network', 'none',
                                '--user', '0:0', '--entrypoint', 'python3',
                                '--mount', 'type=volume,src=' + volume + ',dst=/config', helper,
                                '-c', 'import pathlib,sys; p=pathlib.Path("/config/config.json"); '
                                      'p.write_text(sys.stdin.read()); p.chmod(0o644)'],
                               input=config, text=True, check=True)
                subprocess.run(common + ['--name', server, '--network', 'none',
                                         '--mount', 'type=volume,src=' + volume +
                                         ',dst=/etc/shadowsocks-c,readonly', args.image], check=True)
                containers.append(server)
                subprocess.run(common + ['--name', client, '--network', 'container:' + server,
                                         '--entrypoint', '/usr/local/bin/ss-local', args.image,
                                         '-s', '127.0.0.1', '-p', '8388', '-l', '1080', '-k', key,
                                         '-m', method, '-u'], check=True)
                containers.append(client)
                # The helper waits for both listeners before generating traffic.
                subprocess.run(['docker', 'run', '--rm', '--network', 'container:' + server,
                                '--read-only', '--cap-drop=ALL', helper], check=True, timeout=90)
                for container in containers:
                    assert subprocess.check_output(['docker', 'inspect', '--format',
                                                    '{{.State.Running}}', container], text=True).strip() == 'true'
                for container in reversed(containers):
                    subprocess.run(['docker', 'stop', '--time', '5', container], check=True,
                                   stdout=subprocess.DEVNULL)
                    code = subprocess.check_output(['docker', 'inspect', '--format',
                                                    '{{.State.ExitCode}}', container], text=True).strip()
                    assert code == '0', f'{container}: unclean shutdown ({code})'
                print('PASS runtime image: ' + method, flush=True)
            except BaseException:
                for container in containers:
                    subprocess.run(['docker', 'logs', container], check=False)
                raise
            finally:
                for container in reversed(containers):
                    subprocess.run(['docker', 'rm', '-f', container], check=False, stdout=subprocess.DEVNULL)
                subprocess.run(['docker', 'volume', 'rm', volume], check=False, stdout=subprocess.DEVNULL)
    finally:
        subprocess.run(['docker', 'image', 'rm', helper], check=False, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
