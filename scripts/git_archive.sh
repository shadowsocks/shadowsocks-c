#!/usr/bin/env bash
# Backward-compatible maintainer entrypoint for the offline release archive.
set -euo pipefail
root=$(git rev-parse --show-toplevel)
name=shadowsocks-c
directory=$root
while getopts "n:o:" opt; do
    case "$opt" in
        n) name=$OPTARG ;;
        o) directory=$OPTARG ;;
        *) exit 1 ;;
    esac
done
exec python3 "$root/scripts/source_archive.py" "$directory/$name.tar.gz" --prefix "$name"
