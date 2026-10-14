/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_HEAP_GUARD_HPP
#define SS_CORE_HEAP_GUARD_HPP

// Bounded heaps for the third-party libraries, and the "no heap after
// startup" seal.
//
// install_library_heaps() points libuv, c-ares and (when built with
// MBEDTLS_PLATFORM_MEMORY) Mbed TLS at their own FixedHeap, reserved once.
// Programs call it first thing in main(); the library build never does, so
// an application embedding libshadowsocks-c keeps its allocator. Memory a
// library got before the switch is still freed through the system
// allocator, and a request no heap can serve falls back to it as well,
// counted as a fallback.
//
// heap_seal() marks the end of startup. After it, ss_malloc() and friends
// count every call (heap_report().after_seal); verbose mode logs the
// report at exit.

#include <cstddef>
#include <cstdint>

#include "core/result.hpp"

namespace ss {

struct LibraryHeapBudgets {
    std::size_t uv     = std::size_t{ 4 } << 20;
    std::size_t cares  = std::size_t{ 8 } << 20;
    std::size_t mbedtls = std::size_t{ 1 } << 20;
};

struct HeapReport {
    std::size_t uv_in_use = 0, uv_peak = 0;
    std::size_t cares_in_use = 0, cares_peak = 0;
    std::size_t mbedtls_in_use = 0, mbedtls_peak = 0;
    std::size_t fallbacks  = 0; // requests served by the system allocator
    std::size_t after_seal = 0; // ss_malloc() calls after heap_seal()
};

Status install_library_heaps(const LibraryHeapBudgets &budgets = {}) noexcept;
void heap_seal() noexcept;
bool heap_sealed() noexcept;
HeapReport heap_report() noexcept;
// Log the report (verbose mode does this at exit).
void log_heap_report() noexcept;

} // namespace ss

#endif
