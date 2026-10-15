# Modernization measurements

## C++20 rewrite (2026-10-14)

Local macOS arm64 (Apple clang), Release, bundled dependencies. Baseline:
`master` at `553cdc7` (C). Comparison: the C++20 engine branch stack. Raw
JSON is in [measurements](measurements/) (`cpp20-*`). These are short
loopback runs on one machine, not capacity guarantees.

### Heap allocations per relayed connection

`tests/alloc_audit/measure_alloc.py --target 127.0.0.1`: 200 TCP connections
with a small payload each, after warm-up. Each value is allocations per
connection as ss-server / ss-local.

| Method | C | C++ |
|---|---:|---:|
| aes-256-gcm | 39.0 / 39.0 | 0 / 0 |
| chacha20-ietf-poly1305 | 33.1 / 33.0 | 0 / 0 |
| 2022-blake3-aes-256-gcm | 34.0 / 32.9 | 0 / 0 |
| aes-256-cfb (stream, since removed) | 27.1 / 26.4 | 0 / 0 |

With a host-name target (`localhost`, resolved by ss-server) the C++ programs
are still at 0, because c-ares allocates from its fixed heap. The C ss-server
rises to 89.1 per connection. UDP relaying is also 0 per datagram, where the C relay allocated a
64 KiB buffer for every one. ctest enforces all of this (`alloc_steady_*`, including
`alloc_steady_programs_*`).

### Size

Unstripped Release executables, in bytes:

| Program | C | C++ |
|---|---:|---:|
| ss-local | 1,086,888 | 1,129,960 |
| ss-server | 1,086,952 | 1,130,408 |
| ss-tunnel | 542,200 | 789,144 |

ss-tunnel grows because it now shares the full relay engine with the other
programs, including the resolver, the UDP relay and every codec.

### TCP throughput and memory

`tests/stress_test.py --size 100 --repeat 3`: median of three runs, server RSS
after the transfer.

| Cipher | C Mbps | C++ Mbps | C server RSS, KiB | C++ server RSS, KiB |
|---|---:|---:|---:|---:|
| aes-128-gcm | 6,353 | 6,285 | 3,472 | 3,648 |
| aes-256-gcm | 6,829 | 6,637 | 3,440 | 3,616 |
| chacha20-ietf-poly1305 | 3,037 | 2,891 | 3,456 | 3,664 |

The throughput differences are within the run-to-run spread, which is about
±20% for these 0.1–0.3 s transfers.

RSS with 1,000 established, idle connections through ss-local and ss-server
(aes-256-gcm):

| | C server | C++ server (inline buffers) | C local | C++ local (inline buffers) |
|---|---:|---:|---:|---:|
| idle | 2,624 KiB | 2,992 KiB | 2,272 KiB | 2,576 KiB |
| 1,000 connections | 60,256 KiB | 80,912 KiB | 54,416 KiB | 74,752 KiB |

Each connection slot used to carry about 104 KiB of inline buffers, against
roughly 58 KiB that the C relay allocated on demand. The pool is reserved
virtually at startup and only the touched pages of a slot become resident.

The table above was taken on Apple Silicon, whose 16 KiB pages round every
touched buffer up to a whole page. The same test on Linux (4 KiB pages, GCC,
Alpine container, aes-256-gcm, one small request per connection, then idle):

| per connection | C | C++, inline buffers | C++, leased buffers |
|---|---:|---:|---:|
| ss-server (Linux) | 26.2 KiB | 35.4 KiB | 27.2 KiB |
| ss-local (Linux) | 23.5 KiB | 32.6 KiB | 24.4 KiB |
| ss-server (macOS) | | 73.9 KiB | 42.2 KiB |
| ss-local (macOS) | | 68.2 KiB | 36.4 KiB |

The two relay buffers of a connection (one per direction, 16 KiB each) now
come from a shared `ObjectPool` with two buffers per connection slot. A
connection leases one only while bytes wait in it and gives it back as soon
as it drains, so idle connections hold none, and the LIFO free list hands the
same warm pages to the next busy connection. Because the pool covers every
direction of every slot, a lease never fails and reads never stall on it. The
slot itself shrank from 104 KiB to 68 KiB; most of the rest is the AEAD
decoder's chunk buffer, which only touches the pages a chunk lands in.

Throughput with leased buffers (`stress_test.py --size 1000 --cipher
aes-256-gcm`, alternating runs): median 7,180 against 6,880 Mbps with inline
buffers on Linux (12 runs each), 5,367 against 5,697 Mbps on macOS (16 runs
each). Both gaps are inside the run-to-run spread of 4,300–8,100 Mbps.
`FixedBuffer` has a user-provided constructor, so a lease does not zero-fill
16 KiB; without it the pooled build was about 12% slower.

### UDP

`tests/measure_udp.py`: median payload Mbps over three runs of 2,000 echoed
1,200-byte packets.

| Cipher | C | C++ |
|---|---:|---:|
| aes-128-gcm | 80.9 | 81.4 |
| aes-256-gcm | 81.1 | 55.1 |
| chacha20-ietf-poly1305 | 56.2 | 65.6 |

This benchmark is dominated by Python and SOCKS round trips. Single runs vary
by more than 30% in both builds (for example, C aes-256-gcm ranged from 64 to
81), so no UDP throughput change is claimed either way.

### Reproduce

```sh
python3 tests/alloc_audit/measure_alloc.py --bin build/bin --shim build/lib/libss_alloc_audit.dylib \
    --method aes-256-gcm --target 127.0.0.1
python3 tests/stress_test.py --bin build/bin --size 100 --repeat 3 --json tcp.json
python3 tests/measure_udp.py --bin build/bin --output udp.json
```

## Bundled dependencies (2026-09-10)

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
