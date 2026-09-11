#!/usr/bin/env python3
"""Reject non-system runtime dependencies in static macOS/Windows outputs."""
import argparse
import platform
import re
import subprocess
from pathlib import Path

WINDOWS_SYSTEM_DLLS = {
    'advapi32.dll', 'bcrypt.dll', 'crypt32.dll', 'dnsapi.dll', 'iphlpapi.dll',
    'dbghelp.dll', 'kernel32.dll', 'msvcrt.dll', 'ntdll.dll', 'ole32.dll', 'psapi.dll',
    'rpcrt4.dll', 'secur32.dll', 'shell32.dll', 'ucrtbase.dll', 'user32.dll',
    'userenv.dll', 'winmm.dll', 'ws2_32.dll',
}


def dependencies(binary, system):
    if system == 'Darwin':
        output = subprocess.check_output(['otool', '-L', str(binary)], text=True)
        return [line.strip().split(' (compatibility version', 1)[0]
                for line in output.splitlines() if line.startswith('\t')]
    output = subprocess.check_output(
        ['llvm-readobj', '--coff-imports', str(binary)], text=True)
    return re.findall(r'^\s+Name: (.+)$', output, re.MULTILINE)


def is_system_dependency(name, system):
    if system == 'Darwin':
        return name.startswith(('/usr/lib/', '/System/Library/'))
    name = name.strip().lower()
    return name in WINDOWS_SYSTEM_DLLS or (
        name.startswith(('api-ms-win-', 'ext-ms-win-')) and name.endswith('.dll'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binaries', type=Path, nargs='+')
    args = parser.parse_args()
    system = platform.system()
    if system not in ('Darwin', 'Windows'):
        parser.error('this check supports macOS and native Windows Python')
    for binary in args.binaries:
        names = dependencies(binary, system)
        if not names:
            raise SystemExit(f'{binary}: no OS imports found; check file format/tool output')
        unexpected = [name for name in names if not is_system_dependency(name, system)]
        if unexpected:
            raise SystemExit(f'{binary}: non-system dependencies: {unexpected}')
        print(f'PASS {binary}: {", ".join(names)}')


if __name__ == '__main__':
    main()
