/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "core/heap_guard.hpp"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <memory>

#include <ares.h>
#include <uv.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <mbedtls/platform.h>

#include "core/fixed_heap.hpp"
#include "utils.h"

namespace ss {

namespace {

struct Heaps {
    FixedHeap uv, cares, mbedtls;
};

// Constructed in install_library_heaps() and never destroyed: libraries may
// free into their heap until the very end of the process.
alignas(Heaps) std::byte heaps_storage[sizeof(Heaps)];
Heaps *heaps = nullptr;
std::atomic<std::size_t> fallbacks{ 0 };

void *heap_malloc(FixedHeap &h, std::size_t size) noexcept
{
    if (void *p = h.allocate(size)) {
        return p;
    }
    fallbacks.fetch_add(1, std::memory_order_relaxed);
    return std::malloc(size); // heap-ok: over budget, see heap_report()
}

void *heap_calloc(FixedHeap &h, std::size_t count, std::size_t size) noexcept
{
    if (void *p = h.allocate_zeroed(count, size)) {
        return p;
    }
    fallbacks.fetch_add(1, std::memory_order_relaxed);
    return std::calloc(count, size); // heap-ok: over budget, see heap_report()
}

void *heap_realloc(FixedHeap &h, void *old, std::size_t size) noexcept
{
    if (old != nullptr && !h.owns(old)) {
        return std::realloc(old, size); // heap-ok: allocated before the switch
    }
    if (old != nullptr && size == 0) {
        h.deallocate(old);
        return nullptr;
    }
    // Remember the old block's size first: reallocate() frees it only when
    // it succeeds.
    std::size_t usable = old != nullptr ? h.usable_size(old) : 0;
    if (void *p = h.reallocate(old, size)) {
        return p;
    }
    // Too large for any size class, or over budget: move to the system heap
    // (libuv aborts when growing its watcher array fails).
    fallbacks.fetch_add(1, std::memory_order_relaxed);
    void *fresh = std::malloc(size); // heap-ok: over budget, see heap_report()
    if (fresh != nullptr && old != nullptr) {
        std::memcpy(fresh, old, usable < size ? usable : size);
        h.deallocate(old);
    }
    return fresh; // on failure the caller keeps `old`
}

void heap_free(FixedHeap &h, void *p) noexcept
{
    if (p == nullptr) {
        return;
    }
    if (h.owns(p)) {
        h.deallocate(p);
    } else {
        std::free(p); // heap-ok: allocated before the switch or as a fallback
    }
}

void *uv_malloc_fn(std::size_t size) { return heap_malloc(heaps->uv, size); }
void *uv_realloc_fn(void *p, std::size_t size) { return heap_realloc(heaps->uv, p, size); }
void *uv_calloc_fn(std::size_t count, std::size_t size) { return heap_calloc(heaps->uv, count, size); }
void uv_free_fn(void *p) { heap_free(heaps->uv, p); }

void *ares_malloc_fn(std::size_t size) { return heap_malloc(heaps->cares, size); }
void *ares_realloc_fn(void *p, std::size_t size) { return heap_realloc(heaps->cares, p, size); }
void ares_free_fn(void *p) { heap_free(heaps->cares, p); }

#ifdef MBEDTLS_PLATFORM_MEMORY
void *mbedtls_calloc_fn(std::size_t count, std::size_t size) { return heap_calloc(heaps->mbedtls, count, size); }
void mbedtls_free_fn(void *p) { heap_free(heaps->mbedtls, p); }
#endif

} // namespace

Status install_library_heaps(const LibraryHeapBudgets &budgets) noexcept
{
    if (heaps != nullptr) {
        return fail(Errc::invalid);
    }
    heaps = std::construct_at(reinterpret_cast<Heaps *>(heaps_storage));
    SS_TRY(heaps->uv.reserve(budgets.uv));
    SS_TRY(heaps->cares.reserve(budgets.cares));
    SS_TRY(heaps->mbedtls.reserve(budgets.mbedtls));
    if (uv_replace_allocator(&uv_malloc_fn, &uv_realloc_fn, &uv_calloc_fn, &uv_free_fn) != 0) {
        return fail(Errc::invalid);
    }
    if (ares_library_init_mem(ARES_LIB_INIT_ALL, &ares_malloc_fn, &ares_free_fn, &ares_realloc_fn) != ARES_SUCCESS) {
        return fail(Errc::invalid);
    }
#ifdef MBEDTLS_PLATFORM_MEMORY
    if (mbedtls_platform_set_calloc_free(&mbedtls_calloc_fn, &mbedtls_free_fn) != 0) {
        return fail(Errc::invalid);
    }
#endif
    return {};
}

void heap_seal() noexcept
{
    ss_heap_sealed = 1;
}

bool heap_sealed() noexcept
{
    return ss_heap_sealed != 0;
}

HeapReport heap_report() noexcept
{
    HeapReport r;
    if (heaps != nullptr) {
        auto uv = heaps->uv.stats(), ca = heaps->cares.stats(), mb = heaps->mbedtls.stats();
        r.uv_in_use      = uv.in_use;
        r.uv_peak        = uv.peak;
        r.cares_in_use   = ca.in_use;
        r.cares_peak     = ca.peak;
        r.mbedtls_in_use = mb.in_use;
        r.mbedtls_peak   = mb.peak;
    }
    r.fallbacks  = fallbacks.load(std::memory_order_relaxed);
    r.after_seal = ss_heap_late_allocations;
    return r;
}

void log_heap_report() noexcept
{
    HeapReport r = heap_report();
    LOGI("heaps: libuv %zu KiB (peak %zu), c-ares %zu KiB (peak %zu), mbedtls %zu KiB (peak %zu), "
         "%zu fallback(s), %zu allocation(s) after startup",
         r.uv_in_use / 1024, r.uv_peak / 1024, r.cares_in_use / 1024, r.cares_peak / 1024, r.mbedtls_in_use / 1024,
         r.mbedtls_peak / 1024, r.fallbacks, r.after_seal);
}

} // namespace ss

