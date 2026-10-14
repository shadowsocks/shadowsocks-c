/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_FIXED_HEAP_HPP
#define SS_CORE_FIXED_HEAP_HPP

// FixedHeap: a bounded malloc replacement for third-party libraries.
//
// libuv (uv_replace_allocator), c-ares (ares_library_init_mem) and Mbed TLS
// (MBEDTLS_PLATFORM_MEMORY) can be pointed at our own allocation functions.
// Each library gets its own FixedHeap, carved out of one region reserved at
// startup, so their steady-state allocations stay inside a budget and can
// never starve each other or the relay pools.
//
// Blocks come in power-of-two size classes from 32 bytes to 128 KiB, each
// with a 16-byte header. Freed blocks go to a per-class free list and are
// reused; untouched memory is handed out by bumping a pointer. Calls are
// serialised with a spin lock, because libuv's thread pool may allocate
// from worker threads.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>

#include "core/region.hpp"
#include "core/result.hpp"

namespace ss {

class FixedHeap {
public:
    struct Stats {
        std::size_t in_use      = 0; // bytes in live blocks, headers included
        std::size_t peak        = 0;
        std::size_t reserved    = 0;
        std::size_t allocations = 0;
        std::size_t failures    = 0;
    };

    FixedHeap() noexcept = default;
    FixedHeap(const FixedHeap &)            = delete;
    FixedHeap &operator=(const FixedHeap &) = delete;

    Status reserve(std::size_t budget) noexcept
    {
        if (!region_.empty()) {
            return fail(Errc::invalid);
        }
        auto region = Region::reserve(budget, kHeader);
        if (!region) {
            return fail(region.error());
        }
        region_         = std::move(*region);
        bump_           = 0;
        stats_.reserved = region_.size();
        return {};
    }

    void *allocate(std::size_t size) noexcept
    {
        Guard guard(lock_);
        return allocate_locked(size);
    }

    void *allocate_zeroed(std::size_t count, std::size_t size) noexcept
    {
        if (size != 0 && count > SIZE_MAX / size) {
            Guard guard(lock_);
            ++stats_.failures;
            return nullptr;
        }
        std::size_t total = count * size;
        Guard guard(lock_);
        void *p = allocate_locked(total);
        if (p != nullptr) {
            std::memset(p, 0, total);
        }
        return p;
    }

    void *reallocate(void *old, std::size_t size) noexcept
    {
        if (old == nullptr) {
            return allocate(size);
        }
        if (size == 0) {
            deallocate(old);
            return nullptr;
        }
        Guard guard(lock_);
        Header *h          = header_of(old);
        std::size_t usable = class_size(h->cls) - kHeader;
        if (size <= usable) {
            return old;
        }
        void *fresh = allocate_locked(size);
        if (fresh != nullptr) {
            std::memcpy(fresh, old, usable);
            deallocate_locked(old);
        }
        return fresh;
    }

    void deallocate(void *p) noexcept
    {
        if (p == nullptr) {
            return;
        }
        Guard guard(lock_);
        deallocate_locked(p);
    }

    // Bytes the caller may use in a block this heap returned.
    std::size_t usable_size(void *p) noexcept
    {
        Guard guard(lock_);
        return class_size(header_of(p)->cls) - kHeader;
    }

    bool owns(const void *p) const noexcept
    {
        auto *b = static_cast<const std::byte *>(p);
        return b >= region_.data() && b < region_.data() + region_.size();
    }

    Stats stats() const noexcept
    {
        Guard guard(lock_);
        return stats_;
    }

    static constexpr std::size_t max_request() noexcept { return class_size(kClasses - 1) - kHeader; }

private:
    static constexpr std::size_t kHeader   = 16;
    static constexpr unsigned kMinShift    = 5;  // 32-byte blocks
    static constexpr unsigned kClasses     = 13; // ... up to 128 KiB
    static constexpr std::uint32_t kMagic  = 0x55aa1357U;
    static constexpr std::uint32_t kFreed  = 0xdeadf7eeU;

    struct Header {
        std::uint32_t magic;
        std::uint32_t cls;
        void *next_free; // valid only while the block is on a free list
    };
    static_assert(sizeof(Header) <= kHeader);

    class Guard {
    public:
        explicit Guard(std::atomic_flag &flag) noexcept : flag_(flag)
        {
            while (flag_.test_and_set(std::memory_order_acquire)) {
            }
        }
        ~Guard() { flag_.clear(std::memory_order_release); }
        Guard(const Guard &)            = delete;
        Guard &operator=(const Guard &) = delete;

    private:
        std::atomic_flag &flag_;
    };

    static constexpr std::size_t class_size(unsigned cls) noexcept { return std::size_t{ 1 } << (cls + kMinShift); }

    static Header *header_of(void *p) noexcept
    {
        auto *h = reinterpret_cast<Header *>(static_cast<std::byte *>(p) - kHeader);
        if (h->magic != kMagic || h->cls >= kClasses) {
            std::abort(); // not ours, or corrupted
        }
        return h;
    }

    void *allocate_locked(std::size_t size) noexcept
    {
        if (size == 0) {
            size = 1;
        }
        unsigned cls = 0;
        while (cls < kClasses && class_size(cls) - kHeader < size) {
            ++cls;
        }
        if (cls == kClasses) {
            ++stats_.failures;
            return nullptr;
        }
        std::byte *block = nullptr;
        if (free_[cls] != nullptr) {
            block = static_cast<std::byte *>(free_[cls]);
            SS_UNPOISON(block, class_size(cls));
            free_[cls] = reinterpret_cast<Header *>(block)->next_free;
        } else if (class_size(cls) <= region_.size() - bump_) {
            block = region_.data() + bump_;
            bump_ += class_size(cls);
        } else {
            ++stats_.failures;
            return nullptr;
        }
        auto *h      = reinterpret_cast<Header *>(block);
        h->magic     = kMagic;
        h->cls       = cls;
        h->next_free = nullptr;
        stats_.in_use += class_size(cls);
        ++stats_.allocations;
        if (stats_.in_use > stats_.peak) {
            stats_.peak = stats_.in_use;
        }
        return block + kHeader;
    }

    void deallocate_locked(void *p) noexcept
    {
        if (!owns(p)) {
            std::abort();
        }
        Header *h = header_of(p);
        unsigned cls = h->cls;
        stats_.in_use -= class_size(cls);
        h->magic     = kFreed; // a second free of this block aborts in header_of
        h->next_free = free_[cls];
        free_[cls]   = h;
        // Keep the header readable for the free list; poison the payload.
        SS_POISON(static_cast<std::byte *>(p), class_size(cls) - kHeader);
    }

    Region region_;
    std::size_t bump_ = 0;
    void *free_[kClasses] = {};
    Stats stats_;
    mutable std::atomic_flag lock_ = ATOMIC_FLAG_INIT;
};

} // namespace ss

#endif
