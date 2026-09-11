# Self-contained C modernization

Status: complete for the agreed modernization scope. Native MSVC remains an
explicitly deferred milestone. Implementation branch: feature/self-contained-portable-c;
review: https://github.com/shadowsocks/shadowsocks-libev/pull/3050 (merged).

## Compatibility contract

Keep C11 and the existing CLI, JSON configuration, ss:// parsing, SIP003 plugins,
ACL blacklist/whitelist/outbound precedence, public shadowsocks.h API, legacy
stream ciphers, AEAD and SIP022 TCP/UDP behavior in the compatibility profile.
Removing regex or legacy ciphers is explicit opt-in, with configuration errors
for unavailable functionality. Linux redirection/netfilter remains Linux-only.

## Work and evidence

- [x] Baseline: fresh rebuild, unit/integration results, binary/dependency sizes,
      TCP and UDP throughput, and memory measurements.
- [x] Required independent interoperability including TCP and UDP; missing peers
      fail the required CI job and are reported as skips in optional local runs.
- [x] Target-scoped CMake, separate programs/static/shared library options,
      reliable dependency discovery, installation/export metadata and presets.
- [x] Offline bundled dependency mode and source release archive; explicit system
      mode for distro packages; checksums, licenses, versions, update procedure.
- [x] Remove libcork: address parsing, lists, hash maps, subprocess lifecycle.
- [x] Remove libipset: bounded IPv4/IPv6 prefix storage with insertion/deletion;
      differential tests including holes inside larger networks.
- [x] Vendor the small bloom filter and remove all three submodule requirements.
- [x] Portability layer for sockets/errors, I/O, clocks, randomness and processes.
- [x] Runtime CI: Linux glibc/musl, macOS, FreeBSD, Windows MinGW.
- [x] Document MSVC/event-loop compatibility assessment as a later milestone.
- [x] Minimal profile: no regex/plugins/manager/legacy stream ciphers.
- [x] Crypto-only Mbed TLS configuration and evidence-backed provider assessment.
- [x] Complete sanitizers/static analysis, compatibility and stress validation,
      release archive offline build, installed consumer, before/after report.

## Baseline provenance

Base commit: 8fe386b. Its libcork checkout is 074e074b, different from the
superproject gitlink; this was pre-existing local state. That checkout, libipset
and libbloom are preserved and ignored locally. Fresh baseline builds use those
same checkouts, with no modernization changes applied to baseline source.
The fresh baseline passes all 13 original unit tests.

## Build interface

Requires CMake 3.20+, a C11 compiler, and a build executor. Presets use Ninja;
manual configuration may use another generator.

```
cmake --preset system
cmake --build --preset system
ctest --preset system
```

Programs are in build-system/bin for either linkage mode. WITH_STATIC selects
static third-party dependencies; it does not promise a static libc or OS runtime.
SS_BUILD_EXECUTABLES, SS_BUILD_STATIC_LIBRARY and SS_BUILD_SHARED_LIBRARY control
outputs independently. Docs and platform shell tools are explicit opt-ins.
Bundled mode is the default and the `bundled` / `minimal` presets exercise it.
Maintainers stage the intended source files, then run
`scripts/source_archive.py build-artifacts/shadowsocks-c.tar.gz`.
The archive includes tracked working-tree contents (so uncommitted changes are
included); record the final commit with a published release and use a clean
checkout for publishing. No submodules are accepted in the archive.

## Lint and static analysis

The `tests` workflow runs actionlint 1.7.12 on GitHub Actions workflows and
Ruff 0.15.6 on Python scripts/tests (`E9,F63,F7,F82`: syntax errors, invalid
constructs and undefined names). Run the same checks locally:

```sh
actionlint -shellcheck= -pyflakes=
uvx --from ruff==0.15.6 ruff check --select E9,F63,F7,F82 tests scripts
```

Project C builds treat compiler warnings as errors. The separate clang-tidy-18
job analyzes project sources using the CMake compilation database and allows
zero warnings. Tool failures and compiler errors also fail the job; complete
diagnostics are uploaded even on failure. Vendored sources remain excluded.

## Platform validation

Implementation validation at commit cdb192a passes the full platform matrix:
Linux glibc x86-64/ARM64 and macOS full/minimal builds, real TCP/UDP relay, SIP003
cleanup (full profile), and relocated installed consumers. FreeBSD 14.3 passes
compilation, unit/vendor tests, real TCP/UDP relay and installed consumers.
Native Windows UCRT64 passes all 31 unit/vendor tests, six-method TCP/UDP relay,
and installed static/shared consumers. Relay and consumer execution excludes
MSYS2/toolchain DLL directories from PATH; binaries require only Windows system
DLLs. Zig cross-builds also include both libraries and installed consumers.

Alpine/musl builds the release archive with networking and Python discovery
disabled and passes all unit/vendor and TCP/UDP tests. Linux Valgrind, ASan/UBSan,
coverage, required shadowsocks-rust interoperability, clang-tidy-18, and Debian
package construction pass. Evidence: [platform matrix](https://github.com/shadowsocks/shadowsocks-libev/actions/runs/34505389620),
[tests and analysis](https://github.com/shadowsocks/shadowsocks-libev/actions/runs/34505389548),
[system builds and packaging](https://github.com/shadowsocks/shadowsocks-libev/actions/runs/34505389561).

The same committed source archive also builds locally on Linux arm64 with
networking and Python discovery disabled, passing all 31 unit/vendor tests and
six-method TCP/UDP plus SIP003 tests. The source release itself needs no Git or
Python to compile. Executable-only installation omits library metadata, and a
minimal static-library-only build succeeds with the PCRE2 archive removed.
The final documentation commit is rechecked by the same CI matrix before delivery.

## Compatibility details

Address classification now uses inet_pton consistently with socket conversion;
malformed dotted addresses previously accepted by libcork but rejected by
inet_pton are no longer classified as IP literals. Full and suffix ACL rules
are explicit additions; normal regex remains available by default.
Legacy methods unavailable in Mbed TLS 3 (such as RC4) are not resurrected.
Crypto providers remain libsodium plus the reduced Mbed TLS primitive set:
AES-128/192-GCM, software AES fallback, MD5/SHA1 compatibility derivation, and
legacy AES/Camellia stream modes prevent a transparent libsodium-only switch.
See https://doc.libsodium.org/secret-key_cryptography/aead/aes-256-gcm and
https://shadowsocks.org/doc/sip022.html for the provider and protocol contracts.

## Local validation

- Fresh base-commit build (8fe386b) passes all 13 original unit tests, using the
  preserved dependency checkouts described above. Both its system-shared and
  static-dependency programs were rebuilt for size comparisons.
- macOS full bundled: 31 tests; minimal: 29 tests. System dependencies: 17 tests.
- ASan + UBSan: all 17 project tests and six-method TCP/UDP SIP003 tests pass.
- Clang-tidy: zero warnings/errors with Homebrew LLVM; project compiler warnings
  remain errors. CI additionally uses its existing pinned clang-tidy-18 check.
- IP-set differential test: 1,028,000 comparisons against the original libipset,
  including randomized full-width IPv4/IPv6 insertion/deletion and membership.
- Linux x86-64 musl: 31 unit/vendor tests and all six TCP/UDP relay cases pass
  in containers with networking disabled. The preinstalled cross compiler
  intermittently crashed under CPU emulation; incremental retries completed.
- Installed bundled static/shared consumers run after relocation. Installed
  system-mode static/shared consumers also link and run. System static exports
  require the exact Mbed TLS version used at build time to avoid an ABI mismatch.
- Windows x86-64: programs, both libraries, all tests and installed consumers
  cross-compile with Zig. Native UCRT64 execution and installed consumers pass
  with runtime DLL lookup restricted to the installation and Windows system paths.
- SIP003 fixture: real TCP forwarding, UDP bypass, and child cleanup pass through
  the actual programs. DNS cancellation covers outstanding A/AAAA requests,
  exactly-once callbacks/free callbacks and reinitialization after shutdown.

### MSVC assessment

MSVC is an explicitly deferred milestone, not a supported build today. MinGW-w64
supplies the POSIX compatibility headers/functions (`unistd.h`, `getopt`,
`ssize_t`, string helpers) used throughout the existing CLI. Native MSVC needs
those interfaces isolated, compiler-specific flags in the libsodium adapter,
libuv/Win32 build verification and export/import validation. CMake now rejects
MSVC early with the supported UCRT64/Zig alternatives. Removing the event loop
or inventing replacement crypto implementations is outside this modernization.

### Crypto provider decision

Retain libsodium plus Mbed TLS crypto primitives. The bundled Mbed TLS config
omits TLS, X.509, certificate parsing and handshake machinery; it retains only
cipher/hash primitives needed by protocol compatibility. Libsodium alone cannot
replace AES-128-GCM, software AES fallback, MD5/SHA1 compatibility derivation and
legacy stream modes. PCRE2 is absent in the minimal profile. This removes three
submodule dependencies and reduces what is built without replacing audited
cryptographic algorithms with project-specific implementations.

See [measurements and tradeoffs](performance.md) for reproducible local results.

## Static build CI

The `static-macos` and `static-windows` jobs use Clang, bundled dependencies and
`SS_BUILD_SHARED_LIBRARY=OFF`. They run unit/vendor tests, relocate the installed
static library, build its consumer, and exercise the installed TCP/UDP programs.
The macOS job also exercises SIP003. `tests/check_static_runtime.py` rejects
non-system dylibs and DLLs (including Windows delay imports) in every installed
program and the static consumer. Windows runtime tests exclude toolchain DLL
paths. Windows uses the native [MSYS2 CLANG64 environment](https://www.msys2.org/docs/environments/).

macOS and Windows retain their OS libraries; static builds on these platforms
mean no separately distributed project, crypto, event-loop or toolchain shared
libraries. The `static-linux` job builds the Clang/musl Dockerfile, which also
links libc statically and rejects ELF interpreters and `NEEDED` entries. All
three jobs publish the tested installations as workflow artifacts.

## Native event backends and asynchronous DNS

Libuv 1.52.1 replaces libev in bundled builds; system builds use the distro's
libuv. Windows uses libuv's IOCP-backed AFD socket polling and macOS uses kqueue.
The internal event API supports independent read/write watchers on one socket,
including stopping/freeing watchers during callbacks. Handles close separately
from application objects. Native tests exercise 256 descriptors and verify the
IOCP handle or kqueue descriptor on the corresponding platform.

c-ares drives asynchronous A/AAAA lookups for TCP/UDP destinations and client
hostname ACL bypass, with a dynamically sized DNS watcher list. Manager hostname
updates also use this resolver. Runtime calls to the numeric-address helper
cannot fall back to blocking DNS. Initial configuration/listener/proxy-address
resolution remains synchronous before serving traffic. Tests use a local delayed
DNS server to verify both address families, NXDOMAIN, cancellation, exactly-once
callbacks, and timer progress while requests wait. Hostname ACL integration uses
an unreachable proxy upstream so successful transfers prove direct resolution.

## Project name and compatibility

The project is named **shadowsocks-c**. New library outputs are
`libshadowsocks-c`, and CMake/pkg-config consumers use `shadowsocks-c`.
`shadowsocks.h`, its ABI version, and all `ss-*` commands remain stable.
Legacy library filenames are installed as relative symlinks on Unix and copies
on Windows; `find_package(shadowsocks-libev)` and the old pkg-config name resolve
to the new library. Private dependency archives and license files install under
`shadowsocks-c`. Source archives and the main manual use the new name.

Existing configuration paths, Debian package identifiers and service names
remain compatible. GitHub URLs retain the current repository location.
