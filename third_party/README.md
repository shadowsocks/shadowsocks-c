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
- libev 4.33: BSD-2-Clause OR GPL-2.0-or-later; see LICENSE and source notices.
- bloom: copied unchanged from the former shadowsocks/libbloom submodule,
  commit 437e1add5a2b9a87797d8c648df7cf5f3ee155a8. BSD-2-Clause;
  license and MurmurHash2 source notices retained alongside the sources.
- BLAKE3 remains in src/blake3; its existing license files remain there.
- uthash remains in src/uthash.h with its upstream copyright/license notice.

Mbed TLS, c-ares and PCRE2 use their upstream CMake builds. The local libsodium
CMake adapter compiles the portable C backends listed in upstream Makefile.am;
it is maintained by this project, not upstream. Upstream known-answer tests
are built and run under the `vendor` CTest label. SIMD acceleration needs its
own compiler probes and validation before enabling additional backends.
On Windows, `libev_windows.h` selects raw Winsock handles rather than CRT file
descriptors, consistently for application I/O and libev's wakeup sockets.
Windows therefore requires bundled mode; an arbitrary system libev build does
not necessarily use the same descriptor convention.

To update an archive: select a supported upstream release, download its release
archive from the upstream source, verify published signatures/checksums where
available, update manifest.json (including version-specific configuration in
Sodium.cmake), and run bundled builds, vendor tests, project tests, sanitizers,
and independent TCP/UDP interoperability on the supported platform matrix.
Keep release archives and notices intact. Review upstream advisories and local
adapter changes when selecting an update. System mode remains available to
packagers who update libraries separately.
