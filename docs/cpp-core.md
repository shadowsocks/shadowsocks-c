# C++20 core and allocation policy

Status: phase 1 of an incremental port. The ownership and allocation
primitives in `src/core/` exist and are tested; no program code uses them yet.
All binaries are still built from the C sources.

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

## Phases

1. Build and core (this change): C++ enabled in CMake, `src/core/`, unit tests
   (`test_core_*`), the no-heap lint and the allocation audit.
2. Mechanical C-to-C++ conversion, leaf modules first.
3. Event loop wrapper over libuv.
4. Crypto: cipher contexts held by value, dispatched with `std::variant`.
5. Services: cache, lists, resolver, ACL and configuration on the new primitives.
6. One TCP relay engine shared by ss-tunnel, ss-local, ss-redir and ss-server.
7. UDP relay engine.
8. Seal the heap after startup; new `max_connections`, `max_udp_sessions`
   and `max_dns_queries` settings size the pools.
9. Public API: `shadowsocks.h` kept byte-for-byte, plus a new installed C++
   header with an RAII handle.
10. Remove the C shims.

## Allocation audit

`tests/alloc_audit/alloc_counter.c` is a preloadable `malloc` counter
(glibc and macOS). `tests/alloc_audit/measure_alloc.py` warms ss-local and
ss-server up, snapshots their counters, relays more connections and reports
heap allocations per connection. It runs as the `alloc_audit_report` ctest
(report-only for now). It becomes a hard check, with a budget of zero, once
the relay is ported.

```sh
python3 tests/alloc_audit/measure_alloc.py --bin build/bin \
    --shim build/lib/libss_alloc_audit.dylib --method aes-256-gcm
```

### C baseline

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
| aes-256-cfb (stream) | 77.1 | 26.5 |
| aes-256-gcm, 1-byte payload | 85.0 | 36.0 |

Unstripped Release sizes at the same commit: ss-local 1,086,888 bytes,
ss-server 1,086,952 bytes, ss-tunnel 542,200 bytes.
