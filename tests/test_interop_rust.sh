#!/bin/sh
# Compatibility entry point. Python uses explicit SOCKS sockets, never curl
# or HTTP proxy environment variables. Required CI treats missing peers as errors.
if ! command -v python3 >/dev/null 2>&1; then
    echo 'Missing interoperability prerequisite: python3' >&2
    if [ "${SS_REQUIRE_INTEROP:-0}" = 1 ]; then exit 1; fi
    exit 77
fi
exec python3 "$(dirname "$0")/interop.py" "$@"
