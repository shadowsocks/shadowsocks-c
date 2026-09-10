# Self-contained C modernization

Status: in progress. This checklist tracks the complete agreed scope; unchecked
items are not claimed complete. Implementation branch: feature/self-contained-portable-c.

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
- [ ] Offline bundled dependency mode and source release archive; explicit system
      mode for distro packages; checksums, licenses, versions, update procedure.
- [x] Remove libcork: address parsing, lists, hash maps, subprocess lifecycle.
- [x] Remove libipset: bounded IPv4/IPv6 prefix storage with insertion/deletion;
      differential tests including holes inside larger networks.
- [x] Vendor the small bloom filter and remove all three submodule requirements.
- [x] Portability layer for sockets/errors, I/O, clocks, randomness and processes.
- [ ] Runtime CI: Linux glibc/musl, macOS, FreeBSD, Windows MinGW.
- [x] Document MSVC/event-loop compatibility assessment as a later milestone.
- [x] Minimal profile: no regex/plugins/manager/legacy stream ciphers.
- [x] Crypto-only Mbed TLS configuration and evidence-backed provider assessment.
- [ ] Complete sanitizers/static analysis, compatibility and stress validation,
      release archive offline build, installed consumer, before/after report.

## Initial evidence (2026-09-10)

Base commit: 8fe386b. Existing libcork checkout is 074e074b, different from the
superproject gitlink; it has no uncommitted files and is preserved during work.
The existing build passed all 13 unit tests. Fresh shared-dependency Release
build with the first CMake changes also passed all 13 unit tests.
The initial baseline stress/interop runs collided on a shared port; discard
those measurements and repeat serially before reporting a baseline.

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
`scripts/source_archive.py build-artifacts/shadowsocks-libev.tar.gz`.
The archive includes tracked working-tree contents (so uncommitted changes are
included); record the final commit with a published release and use a clean
checkout for publishing. No submodules are accepted in the archive.

## Verified implementation evidence

- Bundled macOS arm64 build: 17 project tests and 14 upstream libsodium tests
  pass with the crypto-only Mbed TLS configuration.
- Minimal profile: 15 project tests plus 14 upstream libsodium tests pass.
- Linux arm64 glibc: built inside Docker with networking disabled, 29 tests
  passed before the later literal-rule and crypto-profile changes. Repeat the
  final matrix before marking the full platform requirement complete.
- ASan + UBSan: 29 tests passed before the most recent changes; final rerun pending.
- Real shadowsocks-rust 1.24.0 interoperability passes six AEAD methods in both
  directions, each with three simultaneous TCP streams (up to 1 MiB) and four
  UDP payload sizes (1, 128, 1200, 4096 bytes).
- The former curl harness obeyed `no_proxy`, producing false positives by
  bypassing SOCKS. Its historical results are not valid interoperability proof.
  The Python replacement opens SOCKS5 sockets explicitly and reports missing
  peers as skip 77, or failure under SS_REQUIRE_INTEROP=1.
- That replacement exposed truncation of 4 KiB UDP datagrams in the MTU-sized
  receive buffer. The relay now receives full datagrams before authentication.
- The sanitizer baseline found null-URI output was uninitialized in ss_url_parse;
  the output is now cleared before rejecting null input, with a poisoned-output
  regression assertion.
- `otool -L` on bundled ss-server lists only macOS libSystem and libresolv.
- An independent CMake consumer linked and ran against the installed bundled
  static library. Shared/system consumers and relocation remain to be tested.
- Existing libcork, libipset and libbloom directories are preserved locally and
  ignored. Gitlinks are removed; archives no longer require those checkouts.

## Remaining completion gates

Finish Windows MinGW and FreeBSD runtime support/CI, Linux musl and x86-64,
platform socket/error/clock isolation, DNS cancellation and plugin integration
coverage, final differential IP set comparison, installation relocation and
system/shared builds, source-archive offline verification, complete local lint
and tests, and the final binary/memory/TCP/UDP before/after report. Assess MSVC
constraints explicitly. Do not infer these from the successful macOS build.

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

## Final local validation and remaining runtime gates

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
  cross-compile with Zig. Native Windows and FreeBSD CI results are still pending.
- SIP003 fixture: real TCP forwarding, UDP bypass, and child cleanup pass through
  the actual programs. DNS cancellation covers outstanding A/AAAA requests,
  exactly-once callbacks/free callbacks and reinitialization after shutdown.

### MSVC assessment

MSVC is an explicitly deferred milestone, not a supported build today. MinGW-w64
supplies the POSIX compatibility headers/functions (`unistd.h`, `getopt`,
`ssize_t`, string helpers) used throughout the existing CLI. Native MSVC needs
those interfaces isolated, compiler-specific flags in the libsodium adapter,
libev/Win32 build verification and export/import validation. CMake now rejects
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
