/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_REGION_HPP
#define SS_CORE_REGION_HPP

// Region: one aligned block of raw memory obtained from the system allocator.
//
// This is the only place in src/core that calls malloc. Pools, arenas and
// tables reserve their storage through a Region while the process starts up;
// after that the steady-state data path never touches the system allocator.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <utility>

#include "core/result.hpp"

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SS_HAVE_ASAN 1
#endif
#endif
#if defined(__SANITIZE_ADDRESS__)
#define SS_HAVE_ASAN 1
#endif

#ifdef SS_HAVE_ASAN
#include <sanitizer/asan_interface.h>
#define SS_POISON(addr, size)   ASAN_POISON_MEMORY_REGION((addr), (size))
#define SS_UNPOISON(addr, size) ASAN_UNPOISON_MEMORY_REGION((addr), (size))
#else
#define SS_POISON(addr, size)   ((void)(addr), (void)(size))
#define SS_UNPOISON(addr, size) ((void)(addr), (void)(size))
#endif

namespace ss {

class Region {
public:
    Region() noexcept = default;
    Region(const Region &)            = delete;
    Region &operator=(const Region &) = delete;
    Region(Region &&other) noexcept
        : base_(std::exchange(other.base_, nullptr))
        , data_(std::exchange(other.data_, nullptr))
        , size_(std::exchange(other.size_, 0))
    {
    }
    Region &operator=(Region &&other) noexcept
    {
        if (this != &other) {
            release();
            base_ = std::exchange(other.base_, nullptr);
            data_ = std::exchange(other.data_, nullptr);
            size_ = std::exchange(other.size_, 0);
        }
        return *this;
    }
    ~Region() { release(); }

    // Reserve `size` zeroed bytes aligned to `align` (a power of two).
    static Result<Region> reserve(std::size_t size, std::size_t align = alignof(std::max_align_t)) noexcept
    {
        if (align == 0 || (align & (align - 1)) != 0) {
            return fail(Errc::invalid);
        }
        if (align < alignof(std::max_align_t)) {
            align = alignof(std::max_align_t);
        }
        if (size == 0) {
            return Region{};
        }
        if (size > SIZE_MAX - align) {
            return fail(Errc::exhausted);
        }
        // Over-allocate and align by hand: aligned_alloc is missing on
        // MinGW, and _aligned_malloc would need its own free function.
        void *base = std::calloc(1, size + align); // heap-ok: startup reservation
        if (base == nullptr) {
            return fail(Errc::exhausted);
        }
        auto addr = reinterpret_cast<std::uintptr_t>(base);
        auto aligned = (addr + align - 1) & ~(static_cast<std::uintptr_t>(align) - 1);
        Region r;
        r.base_ = base;
        r.data_ = reinterpret_cast<std::byte *>(aligned);
        r.size_ = size;
        return r;
    }

    std::byte *data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }

private:
    void release() noexcept
    {
        if (base_ != nullptr) {
            // Pools may leave freed slots poisoned; the allocator needs to
            // be able to reuse the whole block.
            SS_UNPOISON(data_, size_);
            std::free(base_); // heap-ok: startup reservation
        }
        base_ = nullptr;
        data_ = nullptr;
        size_ = 0;
    }

    void *base_      = nullptr;
    std::byte *data_ = nullptr;
    std::size_t size_ = 0;
};

} // namespace ss

#endif
