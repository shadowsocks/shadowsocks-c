# Modernization measurements

Local macOS arm64 results, 2026-09-10. Base commit: `8fe386b`; comparison:
`feature/self-contained-portable-c`. Raw JSON lives in [measurements](measurements/).
These are short loopback measurements on one machine, not capacity guarantees.

## Size and runtime dependencies

Unstripped Release executable sizes in bytes:

| Program | Old system-shared | Old static dependencies | Bundled | Minimal |
|---|---:|---:|---:|---:|
| ss-local | 295,912 | 1,326,328 | 756,920 | 416,424 |
| ss-server | 314,360 | 1,500,968 | 962,632 | 622,024 |
| ss-tunnel | 268,680 | 828,712 | 416,440 | 397,704 |

Bundled programs link only macOS OS libraries (`libSystem`, and where needed
`libresolv`). They need no separately installed libev, c-ares, PCRE2, libsodium
or Mbed TLS. Compared with the old static-dependency build, ss-server shrinks
about 36%; minimal shrinks about 59%. Compared with a shared-dependency binary
alone, bundling makes the executable larger; that comparison excludes the old
libraries' disk footprint. Bundled source archives add roughly 12 MB to checkout
and release size. There is no configure-time network access or submodule fetch.

## TCP and resident memory

Median of three 100 MiB transfers using `tests/stress_test.py`, old shared
dependencies versus bundled. Both sets pass all nine transfers.

| Cipher | Before Mbps | Bundled Mbps | Before server RSS after, KiB | Bundled server RSS after, KiB |
|---|---:|---:|---:|---:|
| AES-128-GCM | 7,002 | 7,003 | 3,488 | 3,040 |
| AES-256-GCM | 7,776 | 8,498 | 3,488 | 2,992 |
| ChaCha20-IETF-Poly1305 | 3,439 | 3,268 | 3,472 | 3,072 |

Bundled tunnel RSS after transfer was about 2,000–2,032 KiB versus
2,576–2,592 KiB before. RSS includes OS accounting and shared-page effects;
this is not a proof of bounded memory under arbitrary workloads. Transfer times
are short (roughly 0.1–0.3 s), so the apparent AES-256 improvement and ChaCha
regression need longer controlled measurements before drawing performance claims.

## UDP

Median of three runs, 2,000 sequential 1,200-byte echo packets per run through
SOCKS5 UDP ASSOCIATE. Every packet's payload and relay source port are checked.

| Cipher | Before payload Mbps | Bundled payload Mbps |
|---|---:|---:|
| AES-128-GCM | 77.43 | 75.01 |
| AES-256-GCM | 81.34 | 63.33 |
| ChaCha20-IETF-Poly1305 | 78.65 | 67.89 |

This round-trip benchmark includes Python thread creation, scheduling and SOCKS
overhead. It shows lower observed UDP rates in this run, up to 22%; modernization
is not claimed to improve UDP throughput. The portable libsodium backend is a
maintenance/performance tradeoff. Optimized backends require separate compiler
probes and cross-platform known-answer tests before adoption.

Independently of these timings, the new interoperability test exposed the old
MTU-sized receive buffer truncating 4 KiB UDP payloads. Full datagram reception
now passes 1, 128, 1,200 and 4,096-byte interoperability cases against
shadowsocks-rust in both directions.

## Reproduce

```sh
python3 tests/stress_test.py --bin build-bundled/bin --size 100 --repeat 3 --json tcp.json
python3 tests/measure_udp.py --bin build-bundled/bin --output udp.json
python3 tests/interop.py --bin build-bundled/bin
python3 tests/interop.py --self --bin build-bundled/bin --plugin tests/sip003_fixture.py
```

Run comparisons serially. The baseline was rebuilt from its own worktree using
the preserved original dependency checkouts; no modernization fixes were applied
to that source. The historical curl interop harness obeyed `no_proxy` and could
bypass SOCKS, so its old results are excluded from compatibility evidence.
