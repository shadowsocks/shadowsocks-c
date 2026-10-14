# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

shadowsocks-c (formerly shadowsocks-libev) is a lightweight SOCKS5 proxy. Version 3.3.6, licensed under GPLv3.
The sources are C++20 (no exceptions, no RTTI, no heap allocation after startup; see `docs/cpp-core.md`).
The public `src/shadowsocks.h` stays a C header with a stable ABI.

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

- `-DSS_MINIMAL=ON`: no regex, plugins or manager
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

Unit tests compile the specific `src/*.cpp` files they need (see `ss_add_test` in `tests/CMakeLists.txt`).
New tests are C++ (`tests/test_*_cpp.cpp`, `tests/test_core_*.cpp`) using `tests/test_helpers.hpp`; older
ones are C (`tests/test_*.c`). Codec tests compare against the C oracle in `tests/reference/`. The
`alloc_steady_*` tests fail on any heap allocation in steady state.
Labels: `unit`, `vendor`, `integration`, `memcheck` (Linux + valgrind).

### Integration Tests

```bash
python3 tests/interop.py --self --bin build/bin          # TCP/UDP relay, all AEAD/2022 methods
python3 tests/tunnel_interop.py --bin build/bin          # ss-tunnel, every method
python3 tests/test_manager.py --bin build/bin            # ss-manager (needs -DWITH_SS_MANAGER=ON on macOS)
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
  run-clang-tidy -quiet -p build '/(src/(core/|event/|relay/|crypto/|api/)?[^/]+\.(c|cpp)|tests/test_(core_[^/]+|[a-z0-9_]+_cpp)\.cpp)$'
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
- `utils.cpp` - logging, system utilities, `ss_malloc`/`ss_free` (startup only), CLI help snippets
- `jconf.cpp` / `json.cpp` - JSON config file parsing
- `netutils.cpp` - network address utilities
- `ppbloom.cpp` - ping-pong bloom filter for salt replay detection (`third_party/bloom`)

**Relay engines** (`src/relay/`): `tcp.cpp` (one TCP engine for all four programs, `Kind` selects the
handshake), `udp.cpp` (UDP relay), `codec.cpp` (per-connection encoder/decoder variants), `resolver.cpp`
(pooled c-ares queries), `socket.cpp` (upstream sockets, TFO). Each program's `main()` builds a config and
runs them.

**Crypto** (`src/crypto/`): value-type codecs `aead.cpp` (AES-GCM, ChaCha20-Poly1305), `aead2022.cpp`
(Shadowsocks 2022, BLAKE3 from `src/blake3`), `keys.cpp`
(key derivation, method tables). The old C implementation lives in `tests/reference/` as a test oracle.

**ACL:** `acl.cpp` / `rule.cpp` / `ipset.cpp` - IP prefix sets and PCRE2/literal domain rules.

**Plugins:** `plugin.cpp` / `process.cpp` - SIP003 plugin subprocess management.

**C++ core:** `src/core/*.hpp` - ownership and allocation primitives (pools, handles, fixed buffers, arena,
fixed hash map/LRU, intrusive list, bounded heap, `heap_guard` for third-party allocators).

**Embedding API:** `src/shadowsocks.h` (unchanged C ABI), `src/shadowsocks/control.h`
(`ss_local_start`/`stop`/`wait`/`destroy`) and `src/shadowsocks/shadowsocks.hpp` (RAII wrapper).

### Event Loop

`src/event/loop.hpp` wraps libuv (kqueue/epoll/IOCP) handles embedded by value in their owners;
`src/event/program.hpp` is the per-process loop, signals and timers. Connections come from fixed pools sized by
`--max-connections`, `--max-udp-sessions` and `--max-dns-queries`; a full TCP pool pauses accepting.
Non-owning references (DNS answers, timers) are generation-checked handles. Each binary still defines its
own `main()` and option parsing in `local.cpp`, `tunnel.cpp`, `redir.cpp`, `server.cpp`, `manager.cpp`.

### Compiler Flags

From `cmake/ProjectOptions.cmake`: `-Wall -Werror -Wno-deprecated-declarations -fno-strict-aliasing -fstack-protector-strong`, plus `_GNU_SOURCE` on Linux. C is C11 with GNU extensions. C++ is C++20 without extensions and adds `-Wextra -fno-exceptions -fno-rtti -fno-threadsafe-statics`.

`-Werror` means all warnings are errors — new code must compile warning-free.
