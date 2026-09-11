# Bundled sources

`dist/` contains unmodified upstream source release archives. `manifest.json`
records upstream URLs, versions and SHA-256 hashes; CMake verifies hashes before
extracting into the build tree. Configuration never downloads dependencies.
These hashes pin downloaded content; they are not a claim of an independent
signature verification.

- Mbed TLS 3.6.7: Apache-2.0 OR GPL-2.0-or-later; see the archive's LICENSE files.
- libsodium 1.0.22: ISC; see LICENSE in the archive.
- c-ares 1.34.8: MIT; see LICENSE.md in the archive.
- PCRE2 10.48: BSD-3-Clause; see LICENCE.md in the archive, including third-party notices.
- libuv 1.52.1: MIT; see LICENSE in the archive, including third-party notices.
- bloom: copied unchanged from the former shadowsocks/libbloom submodule,
  commit 437e1add5a2b9a87797d8c648df7cf5f3ee155a8. BSD-2-Clause;
  license and MurmurHash2 source notices retained alongside the sources.
- BLAKE3 remains in src/blake3; its existing license files remain there.
- uthash remains in src/uthash.h with its upstream copyright/license notice.

Mbed TLS, c-ares, libuv and PCRE2 use their upstream CMake builds. The local libsodium
CMake adapter compiles the portable C backends listed in upstream Makefile.am;
it is maintained by this project, not upstream. Upstream known-answer tests
are built and run under the `vendor` CTest label. SIMD acceleration needs its
own compiler probes and validation before enabling additional backends.
On Windows, `LibuvWindows.cmake` applies a checked, idempotent fix to extracted
libuv 1.52.1 CPU-info code: a mutable string temporary replaces an incompatible
`const char **` output argument rejected by GCC 14+. The archive is unchanged.

Libuv replaces libev. Its Windows socket polling uses AFD readiness requests
completed through IOCP; macOS uses kqueue. The internal `ss_event` layer combines
read/write watchers for each descriptor and owns libuv handle lifetime separately
from connection objects. c-ares stays integrated into that loop for asynchronous
A/AAAA resolution, custom DNS servers and cancellation. Native platform tests
exercise the backend, concurrent watchers, delayed DNS completion and shutdown.

To update an archive: select a supported upstream release, download its release
archive from the upstream source, verify published signatures/checksums where
available, update manifest.json (including version-specific configuration in
Sodium.cmake), and run bundled builds, vendor tests, project tests, sanitizers,
and independent TCP/UDP interoperability on the supported platform matrix.
Keep release archives and notices intact. Review upstream advisories and local
adapter changes when selecting an update. System mode remains available to
packagers who update libraries separately.
