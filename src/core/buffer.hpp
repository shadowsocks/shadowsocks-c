/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_BUFFER_HPP
#define SS_CORE_BUFFER_HPP

// FixedBuffer<N>: a byte buffer with inline, compile-time capacity.
//
// Replaces buffer_t (crypto.h) and balloc/brealloc/bprepend. The bytes live
// inside the object, so a buffer embedded in a pooled connection costs no
// allocation at all. Instead of growing, writers see how much room is left
// through writable() and stop reading from the socket when it is full.
//
// Layout:  [ consumed | readable (idx .. idx+len) | writable ]

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

namespace ss {

using Bytes      = std::span<std::byte>;
using ConstBytes = std::span<const std::byte>;

inline ConstBytes as_bytes(const void *data, std::size_t size) noexcept
{
    return { static_cast<const std::byte *>(data), size };
}

template <std::size_t N>
class FixedBuffer {
    static_assert(N > 0 && N <= UINT32_MAX);

public:
    // User-provided so that value-initialising a buffer (a pool lease, a
    // variant alternative) does not zero-fill the storage on every use.
    FixedBuffer() noexcept {}

    constexpr std::size_t capacity() const noexcept { return N; }
    constexpr std::size_t size() const noexcept { return len_; }
    constexpr bool empty() const noexcept { return len_ == 0; }
    constexpr bool full() const noexcept { return idx_ + len_ == N; }

    ConstBytes readable() const noexcept { return { data_.data() + idx_, len_ }; }
    Bytes readable() noexcept { return { data_.data() + idx_, len_ }; }
    Bytes writable() noexcept { return { data_.data() + idx_ + len_, N - idx_ - len_ }; }

    // Mark `n` bytes of writable() as filled.
    bool commit(std::size_t n) noexcept
    {
        if (n > N - idx_ - len_) {
            return false;
        }
        len_ += static_cast<std::uint32_t>(n);
        return true;
    }

    // Drop `n` bytes from the front of readable().
    bool consume(std::size_t n) noexcept
    {
        if (n > len_) {
            return false;
        }
        idx_ += static_cast<std::uint32_t>(n);
        len_ -= static_cast<std::uint32_t>(n);
        if (len_ == 0) {
            idx_ = 0;
        }
        return true;
    }

    // Move the readable bytes to the front so writable() is as large as it
    // can be.
    void compact() noexcept
    {
        if (idx_ != 0) {
            if (len_ != 0) {
                std::memmove(data_.data(), data_.data() + idx_, len_);
            }
            idx_ = 0;
        }
    }

    bool append(ConstBytes bytes) noexcept
    {
        if (bytes.size() > N - idx_ - len_) {
            compact();
            if (bytes.size() > N - len_) {
                return false;
            }
        }
        if (!bytes.empty()) {
            std::memcpy(data_.data() + idx_ + len_, bytes.data(), bytes.size());
        }
        len_ += static_cast<std::uint32_t>(bytes.size());
        return true;
    }

    // Insert bytes in front of readable(), e.g. a salt or an address header.
    bool prepend(ConstBytes bytes) noexcept
    {
        std::size_t n = bytes.size();
        if (n > N - len_) {
            return false;
        }
        if (n > idx_) {
            // Not enough headroom: shift the payload right.
            std::size_t new_idx = n;
            if (len_ != 0) {
                std::memmove(data_.data() + new_idx, data_.data() + idx_, len_);
            }
            idx_ = static_cast<std::uint32_t>(new_idx);
        }
        idx_ -= static_cast<std::uint32_t>(n);
        if (n != 0) {
            std::memcpy(data_.data() + idx_, bytes.data(), n);
        }
        len_ += static_cast<std::uint32_t>(n);
        return true;
    }

    void clear() noexcept
    {
        idx_ = 0;
        len_ = 0;
    }

    // Overwrite the contents. Fails, leaving the buffer unchanged, if the
    // bytes do not fit.
    bool assign(ConstBytes bytes) noexcept
    {
        if (bytes.size() > N) {
            return false;
        }
        clear();
        return append(bytes);
    }

    // Wipe the storage, for buffers that held key material or plaintext.
    void wipe() noexcept
    {
        volatile std::byte *p = data_.data();
        for (std::size_t i = 0; i < N; ++i) {
            p[i] = std::byte{ 0 };
        }
        clear();
    }

private:
    std::uint32_t idx_ = 0;
    std::uint32_t len_ = 0;
    std::array<std::byte, N> data_;
};

} // namespace ss

#endif
