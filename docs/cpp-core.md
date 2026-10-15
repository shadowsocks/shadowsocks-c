# C++20 core and allocation policy

Status: all ten phases are done. Every module of `src/` is C++20. The four
relaying programs run on one TCP engine and one UDP engine (`src/relay/`)
built from the ownership and allocation primitives in `src/core/`, the libuv
wrappers in `src/event/` and value-type codecs in `src/crypto/`. On the data
path they make no heap allocations (see [performance](performance.md)).
The original C codecs and cache are kept only as test oracles in
`tests/reference/`.

## Goals

- Move `src/` from C11 to C++20, one module at a time, with every step
  keeping the CLI, the JSON configuration, protocol behaviour and the public
  `shadowsocks.h` C ABI unchanged.
- Make ownership explicit. Each object has exactly one owner, a
  `std::unique_ptr`. Non-owning references are generation-checked handles
  that go stale instead of dangling.
- No heap allocation after startup. Connections, buffers, cipher contexts,
  DNS queries and UDP sessions come from fixed-capacity pools reserved once
  at startup. The steady-state data path does not call `malloc`. When a pool
  is full, new work is refused rather than allocated.

## Language profile

- C++20, `-fno-exceptions -fno-rtti -fno-threadsafe-statics`, warnings as
  errors. Errors are returned as `ss::Result<T>` (`src/core/result.hpp`), which
  implements a subset of `std::expected`.
- Only header-only parts of the standard library are used (`<array>`,
  `<span>`, `<optional>`, `<variant>`, `<memory>`'s `std::unique_ptr`). This
  keeps the binaries and the static library free of libstdc++/libc++ symbols,
  so C consumers of `libshadowsocks-c.a` do not need a C++ runtime.
- `scripts/check_no_heap.py` (a ctest) rejects `new`, `malloc`, allocating
  containers, `std::string`, `std::function` and `std::shared_ptr` in C++
  sources under `src/`. A startup reservation that really must allocate is
  marked `// heap-ok: <reason>`.
- blake3 (`src/blake3`) and `third_party/bloom` stay C.
- Minimum compilers: GCC 11, Clang 14, Apple Clang 15.

## Primitives (`src/core/`)

| Header | Purpose |
|---|---|
| `result.hpp` | `Result<T>`, `Status`, `Errc`, `SS_TRY`. |
| `region.hpp` | `Region`, the only startup `calloc` in the core. Also ASan poison helpers. |
| `pool.hpp` | `ObjectPool<T>`, `PoolPtr<T>` (`std::unique_ptr` with a pool deleter), `Handle<T>`. Types that embed libuv handles model `AsyncClosable`: their slot is recycled only after the asynchronous close finishes. |
| `ref.hpp` | `RefCounted<T>`/`RefPtr<T>`, intrusive shared ownership for the few genuinely shared objects (AEAD-2022 UDP sessions). Used instead of `std::shared_ptr` because its control block cannot be pooled portably. |
| `buffer.hpp` | `FixedBuffer<N>`: inline bytes with `std::span` views; replaces `buffer_t`. |
| `arena.hpp` | `MonotonicArena` for configuration data that lives as long as the process. |
| `fixed_map.hpp` | `FixedHashMap` (open addressing, backward-shift deletion) and `FixedLru`; replace uthash and `cache.cpp`. |
| `intrusive_list.hpp` | `IntrusiveList`/`ListNode`; replaces `ss_list`. Nodes unlink themselves when destroyed. |
| `fixed_heap.hpp` | Bounded size-class allocator to hand to libuv, c-ares and Mbed TLS through their allocator hooks. |
| `heap_guard.hpp` | `install_library_heaps()` routes libuv, c-ares and Mbed TLS into their own `FixedHeap`s (executables only, never the library); `heap_seal()` marks the end of startup; `log_heap_report()` prints heap use with `-v`. |

## Event layer (`src/event/loop.hpp`)

`Loop`, `Poll`, `Timer`, `Signal` and `Async` wrap libuv handles that are
embedded by value in their owner and call a member function of the owner
chosen at compile time (declare that member before the handle). A `Poll`
owns its socket and carries both read and write interest on one libuv
handle; a handle closed from another callback gets no further events.
Handles close into a `CloseGroup`, which signals completion after the last
asynchronous close, so pooled owners implement `AsyncClosable::begin_close`
by closing their handles into one. `DeadlineList` drives the idle timeouts
of many owners from one timer. `program.hpp` holds what every `main()`
shares: the loop, SIGINT/SIGTERM (and SIGCHLD when a plugin runs), periodic
callbacks, a cross-thread `request_stop()`, and `after_fork()` for
`daemonize()`.

## Relay engines (`src/relay/`)

| File | Purpose |
|---|---|
| `tcp.hpp` | `TcpRelay`: listeners, a pool of `max_connections` connections, one idle-deadline timer. `Kind` selects the handshake (tunnel, SOCKS5 local, redir, server). A full pool pauses accepting until a slot frees. |
| `udp.hpp` | `UdpRelay`: sessions in a `FixedLru` over a pool of `max_udp_sessions`, one 64 KiB scratch buffer per relay. AEAD-2022 server sessions are `RefPtr`-shared between the session table and their client sockets. |
| `codec.hpp` | `Method` (immutable, from the configuration) and per-connection `Encoder`/`Decoder` variants: plain, stream, AEAD, AEAD-2022. |
| `resolver.hpp` | c-ares with a pool of `max_dns_queries` queries; answers reach their connection through a generation-checked handle, so a closed connection is never called back. |
| `socket.hpp` | Upstream socket setup, TCP Fast Open, SOCKS address encoding. |

Per-binary behaviour (TOS per redir port, connmark-to-TOS, nftables, manager
statistics, Android protect) plugs in through hooks on the configs, so the
engines do not link it.

## Crypto (`src/crypto/`)

`aead.hpp` (SIP004/SIP007 AEAD) and `aead2022.hpp` (SIP022) provide
value-type codecs (the unauthenticated stream ciphers were removed): the cipher state is held
inside the codec, TCP decoders reassemble into a fixed buffer sized for one
chunk and can hand plaintext out in windows of any size, and HKDF-SHA1 runs
on stack SHA-1 state. `keys.hpp` derives keys and lists the supported
methods. All codecs are tested byte for byte against the C reference
implementation in `tests/reference/`. The bundled Mbed TLS enables
`MBEDTLS_BLOCK_CIPHER_C` so GCM key setup does not allocate; with a system
Mbed TLS lacking it, `mbedtls_gcm_setkey` may still allocate.

## Capacities

| Setting | Default | Pool |
|---|---|---|
| `--max-connections` / `max_connections` | 1024 | TCP connections: a 68 KiB slot each, plus two 16 KiB relay buffers leased from a shared pool while data is in flight |
| `--max-udp-sessions` / `max_udp_sessions` | 256 (ss-server 512) | UDP associations; the least recently used is dropped when full |
| `--max-dns-queries` / `max_dns_queries` | the connection limit (ss-server +64) | DNS lookups in flight |

Pools are reserved at startup and only touched slots become resident.

## Phases

1. Build and core: C++ in CMake, `src/core/`, the no-heap lint, the C++
   runtime check and the allocation audit.
2. Mechanical C-to-C++ conversion, leaf modules first.
   `scripts/no_heap_baseline.txt` ratchets down the remaining startup
   allocations in converted modules.
3. Event layer over libuv (`src/event/`).
4. Crypto codecs held by value: AEAD, stream and AEAD-2022.
5. Services: the cache on a fixed slab, `IntrusiveList` for ACL rules and
   the manager, the pooled resolver, and `read_jconf` on arenas (the file and
   JSON tree in a scratch arena released before it returns, the parsed
   strings in one process-lifetime arena). ACL rules and IP-set nodes still
   come from `malloc` at startup: the IP-set trie frees nodes as it merges
   prefixes, and its size depends on the ACL file, so a bump arena would
   have to reserve for the worst case.
6. One TCP engine for ss-tunnel, ss-local, ss-redir and ss-server.
7. One UDP engine.
8. Library heaps for libuv, c-ares and Mbed TLS, `heap_seal()`, and the
   capacity settings above.
9. Public API: `shadowsocks.h` unchanged, plus `shadowsocks/control.h`
   (`ss_local_start`/`stop`/`wait`/`destroy`) and the RAII
   `shadowsocks/shadowsocks.hpp`.
10. Removal of `ss_event`, the C resolver, the C codecs (now test oracles),
    uthash and `ss_list`, and the unit tests ported to C++
    (`tests/test_helpers.hpp`).

## Allocation audit

`tests/alloc_audit/alloc_counter.c` is a preloadable `malloc` counter
(glibc and macOS). `tests/alloc_audit/measure_alloc.py` warms ss-local and
ss-server up, snapshots their counters, relays more connections and reports
heap allocations per connection; `--udp` measures datagrams instead and
`--target` picks the destination. The `alloc_steady_programs_*` ctests
require zero for each method family over TCP and UDP.

```sh
python3 tests/alloc_audit/measure_alloc.py --bin build/bin \
    --shim build/lib/libss_alloc_audit.dylib --method aes-256-gcm
```

### C baseline (before the rewrite)

Commit `553cdc7`, macOS arm64, bundled Release build, 200 connections, each
echoing 16 KiB through ss-local and ss-server on loopback. The figures
include allocations made inside libuv, c-ares and Mbed TLS. ss-server
resolves the destination (`localhost`) for every connection, so its count
includes a DNS lookup.

| Method | ss-server allocations/connection | ss-local allocations/connection |
|---|---:|---:|
| aes-256-gcm | 89.1 | 39.2 |
| chacha20-ietf-poly1305 | 83.1 | 33.0 |
| 2022-blake3-aes-256-gcm | 84.0 | 33.0 |
| aes-256-cfb (stream, since removed) | 77.1 | 26.5 |
| aes-256-gcm, 1-byte payload | 85.0 | 36.0 |

The C++ programs are at 0 for every row, including the name-resolving
ss-server case; see [performance](performance.md) for the full comparison.

Unstripped Release sizes at the same commit: ss-local 1,086,888 bytes,
ss-server 1,086,952 bytes, ss-tunnel 542,200 bytes.
