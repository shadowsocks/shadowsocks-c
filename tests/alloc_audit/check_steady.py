#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run a test program under the alloc_counter shim and check a steady phase.

The program calls ss::test::alloc_mark() (tests/alloc_audit/alloc_probe.hpp)
before and after the code that must not allocate. This script preloads the
shim, runs the program, and fails unless exactly two marks were recorded and
no allocation happened between them.

Usage: check_steady.py --shim LIB [--max N] -- PROGRAM [ARGS...]
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--shim", required=True)
    parser.add_argument("--max", type=int, default=0, help="allocations allowed between the marks")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("missing program to run")

    with tempfile.TemporaryDirectory(prefix="ss-steady-") as temp:
        out = Path(temp) / "counts"
        env = os.environ.copy()
        env["DYLD_INSERT_LIBRARIES" if sys.platform == "darwin" else "LD_PRELOAD"] = str(Path(args.shim).resolve())
        env["SS_ALLOC_AUDIT_OUT"] = str(out)
        result = subprocess.run(command, env=env)
        if result.returncode != 0:
            print(f"{command[0]} exited with {result.returncode}")
            return 1
        lines = out.read_text().splitlines() if out.exists() else []
    if len(lines) != 2:
        print(f"expected 2 allocation marks, got {len(lines)}")
        return 1
    before, after = ([int(v) for v in line.split()] for line in lines)
    allocations = after[1] - before[1]
    print(f"steady phase: {allocations} allocation(s), {after[3] - before[3]} bytes (allowed: {args.max})")
    return 0 if allocations <= args.max else 1


if __name__ == "__main__":
    sys.exit(main())
