# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

shadowsocks-c (formerly shadowsocks-libev) is a lightweight SOCKS5 proxy. Version 3.3.6, licensed under GPLv3.
The sources are C11 and are being ported to C++20 module by module (see `docs/cpp-core.md`); the public
`src/shadowsocks.h` stays a C header with a stable ABI.

## Build Commands

### CMake (sole build system)

```bash
cmake --preset bundled          # or: cmake -S . -B build -G Ninja
cmake --build --preset bundled
ctest --preset bundled
```

Bundled mode (the default, `SS_DEPENDENCY_MODE=bundled`) builds every dependency from the pinned archives in
`third_party/dist` with no network access. `SS_DEPENDENCY_MODE=system` uses distro libraries instead.
There are no git submodules.

Binaries land in `<build>/bin/`, libraries in `<build>/lib/`.

### Build Dependencies

- CMake >= 3.20, C11 and C++20 compilers (GCC >= 11, Clang >= 14, Apple Clang >= 15), Ninja for the presets
- System mode only: Mbed TLS 2.x/3.x, libsodium >= 1.0.4, PCRE2 (8-bit), libuv, c-ares
- Doxygen (documentation only)

### CMake Options

- `-DSS_MINIMAL=ON`: no regex, plugins, manager or legacy stream ciphers
- `-DWITH_STATIC=OFF`: link third-party dependencies dynamically
- `-DSS_BUILD_EXECUTABLES / SS_BUILD_STATIC_LIBRARY / SS_BUILD_SHARED_LIBRARY`: choose outputs
- `-DWITH_DOC_MAN=ON` / `-DWITH_DOC_HTML=ON`: build documentation
- `-DENABLE_CONNMARKTOS=ON`, `-DENABLE_NFTABLES=ON`: Linux netfilter features
- `-DENABLE_SANITIZERS=ON`, `-DENABLE_COVERAGE=ON`, `-DDISABLE_SSP=ON`, `-DBUILD_TESTING=OFF`

## Testing

### Unit Tests (CTest)

```bash
ctest --test-dir build -LE memcheck --output-on-failure
```

C unit tests (`tests/test_*.c`) compile the specific `src/*.c` files they need (see `ss_add_test` in
`tests/CMakeLists.txt`). C++ core tests are `tests/test_core_*.cpp` using `tests/test_helpers.hpp`.
Labels: `unit`, `vendor`, `integration`, `memcheck` (Linux + valgrind).

### Integration Tests

```bash
python3 tests/interop.py --self --bin build/bin          # TCP/UDP relay, all AEAD/2022 methods
python3 tests/test.py --bin build/bin/ -c tests/aes-gcm.json   # one cipher via curl/dig (needs network)
python3 tests/test_cli.py --bin-dir build/bin           # CLI contract: help/version/exit codes
python3 tests/stress_test.py --bin build/bin/ --size 10
```

### Allocation audit

```bash
python3 tests/alloc_audit/measure_alloc.py --bin build/bin --shim build/lib/libss_alloc_audit.dylib
```

Reports heap allocations per relayed connection (C baseline numbers are in `docs/cpp-core.md`).

## Code Formatting

Uses **uncrustify** with the config at `.uncrustify.cfg`. Key settings: 4-space indent, no tabs, 120-column width, K&R brace style (braces on same line).

## Code Quality Tooling

- **clang-tidy**: config in `.clang-tidy`. The build exports `compile_commands.json` automatically. Run locally:
  ```bash
  run-clang-tidy -quiet -p build '/(src/(core/|event/|relay/|crypto/|api/)?[^/]+\.(c|cpp)|tests/test_core_[^/]+\.cpp)$'
  ```
  On macOS with Homebrew LLVM, add `-extra-arg="-isysroot$(xcrun --show-sdk-path)"`. CI (`clang-tidy` job in `tests.yml`) enforces a warning-count ratchet via `MAX_WARNINGS` — lower it when fixing findings; never raise it without justification.
- **No-heap lint**: `scripts/check_no_heap.py --self-test` (also a ctest) rejects heap allocation in C++ sources under `src/`.
- **Sanitizers**: `cmake .. -DENABLE_SANITIZERS=ON` builds with ASan + UBSan. CI runs ctest and the stress test under sanitizers on every PR.
- **Coverage**: `cmake .. -DENABLE_COVERAGE=ON`, run tests, then `make coverage` (needs lcov). HTML report lands in `build/coverage-html/`. CI uploads it as the `coverage-html` artifact.

## Architecture

### Binaries (all in `src/`)

Each binary is compiled with a module define that controls conditional compilation:

| Binary | Define | Purpose |
|---|---|---|
| `ss-local` | `MODULE_LOCAL` | SOCKS5 client proxy |
| `ss-server` | `MODULE_REMOTE` | Server-side proxy |
| `ss-tunnel` | `MODULE_TUNNEL` | Port forwarding tunnel (implies `MODULE_LOCAL`) |
| `ss-redir` | `MODULE_REDIR` | Transparent proxy via iptables (Linux only, implies `MODULE_LOCAL`) |
| `ss-manager` | `MODULE_MANAGER` | Multi-server manager daemon (Linux only by default) |

A library `libshadowsocks-c` (legacy names `libshadowsocks-libev.*` are kept) is built from the ss-local sources with `-DLIB_ONLY`. Its public API is in `src/shadowsocks.h`.

### Source Organization (`src/`)

**Shared by all binaries:**
- `utils.c` - logging, system utilities, `ss_malloc`/`ss_free`
- `jconf.c` / `json.c` - JSON config file parsing
- `netutils.c` - network address utilities
- `cache.c` - uthash-based connection cache (UDP relay, AEAD-2022 tables)
- `udprelay.c` - UDP relay implementation (shared, but uses `#ifdef MODULE_*` for per-binary behavior)
- `ss_event.c` / `ss_event.h` - event loop API over libuv
- `resolv.c` - asynchronous DNS via c-ares

**Crypto layer** (behind a common `crypto_t` function-pointer interface):
- `crypto.c` / `crypto.h` - crypto initialization, key derivation (HKDF), `buffer_t` management
- `stream.c` - legacy stream ciphers
- `aead.c` - AEAD ciphers (AES-GCM via Mbed TLS/libsodium, ChaCha20-Poly1305 via libsodium)
- `aead2022.c` / `aead2022_udp.c` - Shadowsocks 2022 (SIP022), BLAKE3 from `src/blake3`
- `ppbloom.c` - ping-pong bloom filter for salt replay detection (`third_party/bloom`)

**ACL:** `acl.c` / `rule.c` / `ipset.c` - IP prefix sets and PCRE2/literal domain rules.

**Plugins:** `plugin.c` / `process.c` - SIP003 plugin subprocess management.

**C++ core:** `src/core/*.hpp` - header-only ownership and allocation primitives (pools, handles, fixed
buffers, arena, fixed hash map/LRU, intrusive list, bounded heap). See `docs/cpp-core.md`.

### Event Loop

All binaries use the `ss_event` API (libuv backend: kqueue/epoll/IOCP). The connection lifecycle follows stages defined in `src/common.h`: `STAGE_INIT` -> `STAGE_HANDSHAKE` -> `STAGE_RESOLVE` -> `STAGE_STREAM` -> `STAGE_STOP`. Each binary defines its own `listen_ctx_t`, `server_t`, and `remote_t` structs (note: "server" in `local.h` means the local-side connection, "remote" means the ss-server side).

### Compiler Flags

From `cmake/ProjectOptions.cmake`: `-Wall -Werror -Wno-deprecated-declarations -fno-strict-aliasing -fstack-protector-strong`, plus `_GNU_SOURCE` on Linux. C is C11 with GNU extensions. C++ is C++20 without extensions and adds `-Wextra -fno-exceptions -fno-rtti -fno-threadsafe-statics`.

`-Werror` means all warnings are errors — new code must compile warning-free.
