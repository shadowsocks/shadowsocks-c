/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_ARENA_HPP
#define SS_CORE_ARENA_HPP

// MonotonicArena: bump allocation for data that lives as long as the
// process configuration (parsed JSON, CLI strings, ACL entries).
//
// The arena reserves one block at startup. Allocations never free
// individually; reset() discards everything at once (ss-manager uses this
// per control command). Only trivially destructible types may be placed in
// an arena, because nothing runs destructors.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>

#include "core/region.hpp"
#include "core/result.hpp"

namespace ss {

class MonotonicArena {
public:
    MonotonicArena() noexcept = default;
    MonotonicArena(const MonotonicArena &)            = delete;
    MonotonicArena &operator=(const MonotonicArena &) = delete;
    MonotonicArena(MonotonicArena &&)                 = default;
    MonotonicArena &operator=(MonotonicArena &&)      = default;

    Status reserve(std::size_t bytes) noexcept
    {
        if (!block_.empty()) {
            return fail(Errc::invalid);
        }
        auto region = Region::reserve(bytes);
        if (!region) {
            return fail(region.error());
        }
        block_ = std::move(*region);
        used_  = 0;
        return {};
    }

    Result<std::span<std::byte> > allocate(std::size_t size, std::size_t align = alignof(std::max_align_t)) noexcept
    {
        if (align == 0 || (align & (align - 1)) != 0) {
            return fail(Errc::invalid);
        }
        auto base    = reinterpret_cast<std::uintptr_t>(block_.data());
        auto current = base + used_;
        auto aligned = (current + align - 1) & ~(static_cast<std::uintptr_t>(align) - 1);
        std::size_t offset = static_cast<std::size_t>(aligned - base);
        if (block_.empty() || offset > block_.size() || size > block_.size() - offset) {
            return fail(Errc::exhausted);
        }
        used_ = offset + size;
        if (used_ > peak_) {
            peak_ = used_;
        }
        return std::span<std::byte>(block_.data() + offset, size);
    }

    template <class T, class... Args>
    Result<T *> make(Args &&...args) noexcept
    {
        static_assert(std::is_trivially_destructible_v<T>, "arena objects are never destroyed");
        auto bytes = allocate(sizeof(T), alignof(T));
        if (!bytes) {
            return fail(bytes.error());
        }
        return std::construct_at(reinterpret_cast<T *>(bytes->data()), std::forward<Args>(args)...);
    }

    template <class T>
    Result<std::span<T> > make_array(std::size_t count) noexcept
    {
        static_assert(std::is_trivially_destructible_v<T> && std::is_default_constructible_v<T>);
        if (count > SIZE_MAX / sizeof(T)) {
            return fail(Errc::exhausted);
        }
        auto bytes = allocate(sizeof(T) * count, alignof(T));
        if (!bytes) {
            return fail(bytes.error());
        }
        T *first = reinterpret_cast<T *>(bytes->data());
        for (std::size_t i = 0; i < count; ++i) {
            std::construct_at(first + i);
        }
        return std::span<T>(first, count);
    }

    // Copy a string into the arena, NUL-terminated so it can be handed to C
    // APIs. The returned view excludes the terminator.
    Result<std::string_view> intern(std::string_view text) noexcept
    {
        auto bytes = allocate(text.size() + 1, 1);
        if (!bytes) {
            return fail(bytes.error());
        }
        char *out = reinterpret_cast<char *>(bytes->data());
        if (!text.empty()) {
            std::memcpy(out, text.data(), text.size());
        }
        out[text.size()] = '\0';
        return std::string_view(out, text.size());
    }

    void reset() noexcept { used_ = 0; }

    std::size_t capacity() const noexcept { return block_.size(); }
    std::size_t used() const noexcept { return used_; }
    std::size_t peak() const noexcept { return peak_; }

private:
    Region block_;
    std::size_t used_ = 0;
    std::size_t peak_ = 0;
};

} // namespace ss

#endif
