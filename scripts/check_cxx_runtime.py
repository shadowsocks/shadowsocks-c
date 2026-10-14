#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail if programs or libraries need the C++ runtime library.

The C++ core is built without exceptions or RTTI and uses only header-only
parts of the standard library, so the programs and libshadowsocks-c stay
consumable from plain C: a C program linking libshadowsocks-c.a must not need
libstdc++ or libc++. This script lists the undefined symbols of each file with
nm and rejects anything served by the C++ runtime (operator new/delete,
exception and RTTI support, std:: functions).

Usage: check_cxx_runtime.py [--nm NM] FILE...
"""

import argparse
import re
import shutil
import subprocess
import sys

# Itanium-ABI names (with or without the Mach-O leading underscore) that only
# the C++ runtime defines.
RUNTIME = re.compile(
    r"^_?(?:"
    r"_Zn[wa]|_Zd[la]|"                     # operator new / delete
    r"_ZSt|_ZNSt|_ZNKSt|"                    # std:: functions and members
    r"_ZTI|_ZTS|_ZTV|"                       # typeinfo / vtables (RTTI, classes from the runtime)
    r"__cxa_(?!atexit$|finalize$|thread_atexit_impl$)|"  # exception/guard support; libc owns these three
    r"__gxx_personality|_Unwind_|__dynamic_cast"
    r")"
)


def undefined_symbols(nm, path):
    result = subprocess.run([nm, "-u", path], capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"{nm} failed on {path}: {result.stderr.strip()}")
    symbols = set()
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.endswith(":"):
            continue  # archive member headers
        # glibc nm prints versioned names (__cxa_atexit@GLIBC_2.2.5).
        symbols.add(line.split()[-1].split("@")[0])
    return symbols


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--nm", default=shutil.which("nm") or "nm")
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    failed = False
    for path in args.files:
        bad = sorted(s for s in undefined_symbols(args.nm, path) if RUNTIME.match(s))
        if bad:
            failed = True
            print(f"{path}: needs the C++ runtime:")
            for symbol in bad:
                print(f"    {symbol}")
        else:
            print(f"{path}: ok")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
