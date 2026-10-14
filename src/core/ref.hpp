/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_REF_HPP
#define SS_CORE_REF_HPP

// RefCounted<T> / RefPtr<T>: intrusive shared ownership.
//
// Use this only where ownership is genuinely shared. Today that means
// AEAD-2022 UDP sessions, which are held by the session table and by every
// relay slot that is still talking to the peer. Everything else has a single
// owner and uses std::unique_ptr (usually PoolPtr).
//
// Why not std::shared_ptr: std::allocate_shared has an implementation-
// defined control block that cannot be sized into a pool portably, weak_ptr
// would keep the slot alive after the object dies, and the atomic count is
// wasted on a single-threaded event loop. The count here is a plain integer;
// RefPtr must not cross threads.
//
// T derives from RefCounted<T> and provides
//     static void destroy(T *object) noexcept;
// which runs when the last reference goes away (typically by dropping the
// PoolPtr that owns the storage).

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <utility>

namespace ss {

template <class T>
class RefPtr;

template <class T>
class RefCounted {
public:
    RefCounted(const RefCounted &)            = delete;
    RefCounted &operator=(const RefCounted &) = delete;

    std::size_t ref_count() const noexcept { return count_; }

protected:
    ~RefCounted()
    {
        if (count_ != 0) {
            std::abort(); // destroyed while references remain
        }
    }

private:
    friend T;
    friend class RefPtr<T>;

    RefCounted() noexcept = default;

    void retain() noexcept
    {
        if (count_ == SIZE_MAX) {
            std::abort();
        }
        ++count_;
    }

    void release() noexcept
    {
        if (count_ == 0) {
            std::abort();
        }
        if (--count_ == 0) {
            T::destroy(static_cast<T *>(this));
        }
    }

    std::size_t count_ = 0;
};

template <class T>
class RefPtr {
public:
    constexpr RefPtr() noexcept = default;
    constexpr RefPtr(std::nullptr_t) noexcept {} // NOLINT(google-explicit-constructor)

    // Takes the first reference, or adds one to an object that is already
    // shared.
    explicit RefPtr(T *object) noexcept : ptr_(object)
    {
        if (ptr_ != nullptr) {
            ptr_->retain();
        }
    }

    RefPtr(const RefPtr &other) noexcept : RefPtr(other.ptr_) {}
    RefPtr(RefPtr &&other) noexcept : ptr_(std::exchange(other.ptr_, nullptr)) {}

    RefPtr &operator=(const RefPtr &other) noexcept
    {
        RefPtr(other).swap(*this);
        return *this;
    }
    RefPtr &operator=(RefPtr &&other) noexcept
    {
        RefPtr(std::move(other)).swap(*this);
        return *this;
    }
    RefPtr &operator=(std::nullptr_t) noexcept
    {
        reset();
        return *this;
    }

    ~RefPtr() { reset(); }

    void reset() noexcept
    {
        if (T *p = std::exchange(ptr_, nullptr)) {
            p->release();
        }
    }

    void swap(RefPtr &other) noexcept { std::swap(ptr_, other.ptr_); }

    T *get() const noexcept { return ptr_; }
    T &operator*() const noexcept { return *ptr_; }
    T *operator->() const noexcept { return ptr_; }
    explicit operator bool() const noexcept { return ptr_ != nullptr; }

    friend bool operator==(const RefPtr &a, const RefPtr &b) noexcept { return a.ptr_ == b.ptr_; }
    friend bool operator==(const RefPtr &a, std::nullptr_t) noexcept { return a.ptr_ == nullptr; }

private:
    T *ptr_ = nullptr;
};

} // namespace ss

#endif
