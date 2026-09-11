#!/usr/bin/env python3
"""Create an offline source archive from Git's tracked working-tree files.

Maintainer-only tool; building the resulting archive needs neither Git nor
Python (unless integration tests or generated documentation are requested).
"""
import argparse
import gzip
import io
import os
from pathlib import Path
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--prefix", default="shadowsocks-c-3.3.6")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if "/" in args.prefix or args.prefix in ("", ".", ".."):
        parser.error("prefix must be a single directory name")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or subprocess.check_output(
        ["git", "show", "-s", "--format=%ct", "HEAD"], cwd=root, text=True).strip())
    entries = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root).split(b"\0")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as archive:
            for entry in entries:
                if not entry:
                    continue
                metadata, encoded = entry.split(b"\t", 1)
                mode, _, stage = metadata.split()
                if stage != b"0" or mode == b"160000":
                    raise RuntimeError("Unmerged entry or submodule in source archive")
                relative = os.fsdecode(encoded)
                path = root / relative
                info = tarfile.TarInfo(args.prefix + "/" + relative)
                info.mtime = epoch
                info.mode = int(mode, 8) & 0o777
                if path.is_symlink():
                    info.type = tarfile.SYMTYPE
                    info.linkname = os.readlink(path)
                    archive.addfile(info)
                else:
                    content = path.read_bytes()
                    info.size = len(content)
                    archive.addfile(info, io.BytesIO(content))
    print(args.output)


if __name__ == "__main__":
    main()
