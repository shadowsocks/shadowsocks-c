#!/usr/bin/env python3
"""Exercise CLI parsing, diagnostics, and configuration overrides on real binaries."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest

BIN_DIR = Path(os.environ.get('SS_BIN_DIR', 'build/bin')).resolve()


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        suffix = '.exe' if os.name == 'nt' else ''
        cls.binaries = {name: BIN_DIR / ('ss-' + name + suffix)
                        for name in ('local', 'server', 'tunnel', 'redir', 'manager')
                        if (BIN_DIR / ('ss-' + name + suffix)).is_file()}
        for name in ('local', 'server', 'tunnel'):
            if name not in cls.binaries:
                raise RuntimeError(f'Missing required CLI binary: ss-{name}')

    def run_cli(self, name, *arguments):
        return subprocess.run([str(self.binaries[name]), *arguments],
                              capture_output=True, text=True, timeout=10)

    def test_help_and_version(self):
        for name in self.binaries:
            with self.subTest(name=name):
                help_result = self.run_cli(name, '--help')
                self.assertEqual(help_result.returncode, 0)
                self.assertEqual(help_result.stderr, '')
                for flag in ('--config', '--cipher', '--tcp-only', '--udp-only',
                             '--ipv4-first', '--ipv6-first', '--version'):
                    self.assertIn(flag, help_result.stdout)
                version = self.run_cli(name, '--version')
                self.assertEqual(version.returncode, 0)
                self.assertRegex(version.stdout, rf'^ss-{name} \(shadowsocks-c\) \d+\.\d+')
                self.assertEqual(len(version.stdout.splitlines()), 1)
                self.assertEqual(version.stderr, '')
                if name == 'manager':
                    self.assertNotIn('--server-port', help_result.stdout)
                    self.assertNotIn('--listen-port', help_result.stdout)
                    self.assertNotIn('--tcp-incoming-sndbuf', help_result.stdout)
                    self.assertNotIn('--mptcp', help_result.stdout)
                elif name == 'server':
                    self.assertIn('--outbound-address', help_result.stdout)
                    self.assertNotIn('--server-port', help_result.stdout)

    def test_printable_salt_is_local_only_and_rejects_other_ciphers(self):
        for name in self.binaries:
            help_result = self.run_cli(name, '--help')
            self.assertEqual('--printable-salt' in help_result.stdout, name == 'local')
            if name != 'local':
                self.assertEqual(self.run_cli(name, '--printable-salt').returncode, 2)
        for method in ('aes-128-gcm', 'aes-192-gcm', '2022-blake3-aes-256-gcm',
                       '2022-blake3-chacha20-poly1305'):
            with self.subTest(method=method):
                result = self.run_cli('local', '-s', '127.0.0.1', '-p', '8388',
                                      '-l', '1080', '-k', 'test-password', '-m', method,
                                      '--printable-salt')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('requires chacha20-ietf-poly1305', result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'client.json'
            config.write_text(json.dumps(dict(server='127.0.0.1', server_port=8388,
                                              local_port=1080, password='test-password',
                                              method='aes-128-gcm')))
            result = self.run_cli('local', '-c', str(config), '--printable-salt')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires chacha20-ietf-poly1305', result.stderr)
            # The config key alone enables it, so the cipher check still applies.
            config.write_text(json.dumps(dict(server='127.0.0.1', server_port=8388,
                                              local_port=1080, password='test-password',
                                              method='aes-128-gcm', printable_salt=True)))
            result = self.run_cli('local', '-c', str(config))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('requires chacha20-ietf-poly1305', result.stderr)
            config.write_text(json.dumps(dict(server='127.0.0.1', server_port=8388,
                                              local_port=1080, password='test-password',
                                              method='aes-128-gcm', printable_salt='yes')))
            result = self.run_cli('local', '-c', str(config))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("option 'printable_salt' must be a boolean", result.stderr)

    def test_removed_stream_ciphers_are_rejected(self):
        for method in ('aes-256-cfb', 'chacha20-ietf', 'rc4-md5'):
            with self.subTest(method=method):
                result = self.run_cli('server', '-s', '127.0.0.1', '-p', '1', '-k', 'test-password',
                                      '-m', method)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('no longer supported', result.stderr)

    def test_long_aliases_accept_their_arguments(self):
        for name in self.binaries:
            args = ['--config', 'not-loaded-before-help.json', '--cipher', 'aes-128-gcm',
                    '--password', 'test-password', '--timeout', '60', '--user', 'nobody',
                    '--pid-file', 'not-created.pid', '--verbose', '--udp', '--udp-only',
                    '--tcp-only', '--ipv6-first', '--ipv4-first', '--listen-address', '127.0.0.1']
            if name not in ('server', 'manager'):
                args += ['--server', '127.0.0.1', '--server-port', '8388']
            if name != 'manager':
                args += ['--listen-port', '1080']
            if name == 'server':
                args += ['--outbound-address', '127.0.0.1']
            if name != 'redir':
                args += ['--interface', 'lo']
            if name in ('server', 'manager'):
                args += ['--nameserver', '127.0.0.1']
            if name == 'tunnel':
                args += ['--destination', '127.0.0.1:80']
            if name == 'redir':
                args += ['--tproxy']
            result = self.run_cli(name, *args, '--help')
            self.assertEqual(result.returncode, 0, (name, result.stderr))
            self.assertIn('Usage:', result.stdout)

    def test_usage_errors_are_stderr_exit_two_without_secrets(self):
        secret = 'private-argument-value'
        for name in self.binaries:
            for args in (['--unknown=' + secret], ['-Z' + secret], [secret],
                         ['--', secret], ['--password'], ['-k'], ['-A']):
                with self.subTest(name=name, arguments=args[:1]):
                    result = self.run_cli(name, *args)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, '')
                    self.assertIn('--help', result.stderr)
                    self.assertNotIn(secret, result.stderr)
            result = self.run_cli(name, '--password')
            self.assertIn('missing required argument', result.stderr)
            self.assertIn('--password', result.stderr)
        for name in ('server', 'manager'):
            if name in self.binaries:
                self.assertEqual(self.run_cli(name, '-l', '1080').returncode, 2)

    def test_transport_and_address_family_override_configuration(self):
        cases = [(['--tcp-only', '--ipv4-first'], False, False),
                 (['--udp-only', '--tcp-only', '--ipv6-first', '--ipv4-first'], False, False),
                 (['--tcp-only', '--udp', '--ipv4-first', '--ipv6-first'], True, True)]
        for args, udp, ipv6 in cases:
            with self.subTest(args=args), tempfile.TemporaryDirectory() as directory:
                with socket.socket() as reservation:
                    reservation.bind(('127.0.0.1', 0))
                    port = reservation.getsockname()[1]
                config = Path(directory) / 'config.json'
                config.write_text(json.dumps({'server': '127.0.0.1', 'server_port': 0,
                    'local_address': '127.0.0.1', 'local_port': port, 'password': 'test-password',
                    'method': 'aes-128-gcm', 'mode': 'udp_only', 'ipv6_first': True}))
                with tempfile.TemporaryFile(mode='w+') as log:
                    proc = subprocess.Popen([str(self.binaries['local']), '--config', str(config),
                        '--server', '127.0.0.1:9', '--listen-port', str(port), '--verbose', *args], stdout=log, stderr=log)
                    try:
                        deadline = time.monotonic() + 5
                        connected = False
                        while time.monotonic() < deadline and proc.poll() is None:
                            try:
                                with socket.create_connection(('127.0.0.1', port), timeout=0.1):
                                    connected = True
                                break
                            except OSError:
                                time.sleep(0.02)
                        self.assertTrue(connected, 'CLI TCP mode did not override UDP-only config')
                    finally:
                        if proc.poll() is None:
                            proc.terminate()
                        proc.wait(timeout=5)
                    log.seek(0)
                    output = log.read()
                    self.assertEqual('udprelay enabled' in output, udp, output)
                    self.assertEqual('resolving hostname to IPv6 address first' in output, ipv6, output)

    def test_server_endpoint_arguments(self):
        for name in ('local', 'tunnel', 'redir'):
            if name not in self.binaries:
                continue
            for endpoint in ('example.com:8388', '127.0.0.1:8388', '[::1]:8388',
                             '[fe80::1%eth0]:8388', '2001:db8::1:8388'):
                result = self.run_cli(name, '--server', endpoint, '--help')
                self.assertEqual(result.returncode, 0, (name, endpoint, result.stderr))
            for endpoint in ('[::1', '[::1]:', '[::1]junk', '[::1]:65536',
                             'host:', ':8388', 'host:0', 'host:bad', '[host]:80'):
                result = self.run_cli(name, '--server', endpoint)
                self.assertEqual(result.returncode, 2, (name, endpoint))
                self.assertEqual(result.stdout, '')
                self.assertIn('invalid server endpoint', result.stderr)
            for args in (['--server', '2001:db8::1:8388'],
                         ['--server', 'host:8388', '--server', 'other'],
                         ['--server', 'host:8388', '--server', 'other:8389', '--plugin', 'unused']):
                result = self.run_cli(name, *args)
                self.assertEqual(result.returncode, 2, (name, args))
                self.assertIn('each server needs a port', result.stderr)

    def test_numeric_option_validation(self):
        for name in self.binaries:
            for value in ('0', '-1', 'abc', '2147483648'):
                result = self.run_cli(name, '--timeout', value)
                self.assertEqual(result.returncode, 2, (name, value))
                self.assertEqual(result.stdout, '')
                self.assertIn('positive integer', result.stderr)
            if name != 'manager':
                for value in ('0', '65536', '-1', 'abc'):
                    result = self.run_cli(name, '--listen-port', value)
                    self.assertEqual(result.returncode, 2, (name, value))
                    self.assertIn('1 to 65535', result.stderr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin-dir', type=Path, default=BIN_DIR)
    args = parser.parse_args()
    BIN_DIR = args.bin_dir.resolve()
    unittest.main(argv=[__file__])
