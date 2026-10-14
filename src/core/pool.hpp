/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_POOL_HPP
#define SS_CORE_POOL_HPP

// ObjectPool<T>: fixed-capacity storage for objects of one type.
//
// Ownership model
//   * acquire() constructs a T in a free slot and returns PoolPtr<T>, a
//     std::unique_ptr whose deleter hands the slot back to the pool. The
//     PoolPtr is the one and only owner.
//   * Anything that needs to refer to the object without owning it (a DNS
//     callback, a timer, the peer of a relay) keeps a Handle<T>. A handle
//     carries the slot's generation, so resolve() returns nullptr once the
//     object is gone, even if the slot has been reused since.
//   * A type that embeds libuv handles cannot be freed while libuv still
//     points at them. Such types model AsyncClosable: when the owner drops
//     the PoolPtr, the slot enters the closing state (handles stop
//     resolving), T::begin_close() starts closing the libuv handles, and the
//     slot is destroyed and recycled only when T invokes the completion.
//
// The pool reserves all of its memory up front, so acquire() and release
// never call the system allocator. Free slots are poisoned under ASan, which
// keeps use-after-free detectable even though memory is recycled.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>
#include <utility>

#include "core/region.hpp"
#include "core/result.hpp"

namespace ss {

template <class T>
class ObjectPool;

template <class T>
struct Handle {
    std::uint32_t index = UINT32_MAX;
    std::uint32_t gen   = 0;

    constexpr explicit operator bool() const noexcept { return gen != 0; }
    friend constexpr bool operator==(const Handle &, const Handle &) = default;
};

// Passed to T::begin_close(). T must invoke it exactly once, after its last
// asynchronous close has finished; it may also be invoked synchronously from
// inside begin_close(). The object is destroyed during the call, so T must
// not touch itself afterwards.
class CloseCompletion {
public:
    CloseCompletion() noexcept = default;
    CloseCompletion(void (*fn)(void *, std::uint32_t), void *pool, std::uint32_t index) noexcept
        : fn_(fn), pool_(pool), index_(index)
    {
    }

    void operator()() noexcept
    {
        auto fn = std::exchange(fn_, nullptr);
        if (fn == nullptr) {
            std::abort(); // completed twice, or never armed
        }
        fn(pool_, index_);
    }

    explicit operator bool() const noexcept { return fn_ != nullptr; }

private:
    void (*fn_)(void *, std::uint32_t) = nullptr;
    void *pool_                         = nullptr;
    std::uint32_t index_                = 0;
};

template <class T>
concept AsyncClosable = requires(T &t, CloseCompletion done) {
    t.begin_close(done);
};

template <class T>
struct PoolDeleter {
    ObjectPool<T> *pool = nullptr;

    void operator()(T *object) const noexcept
    {
        if (pool == nullptr) {
            std::abort(); // a PoolPtr must come from ObjectPool::acquire
        }
        pool->release(object);
    }
};

template <class T>
using PoolPtr = std::unique_ptr<T, PoolDeleter<T> >;

template <class T>
class ObjectPool {
    static_assert(std::is_nothrow_destructible_v<T>);

public:
    ObjectPool() noexcept = default;
    ObjectPool(const ObjectPool &)            = delete;
    ObjectPool &operator=(const ObjectPool &) = delete;
    ObjectPool(ObjectPool &&)                 = delete;
    ObjectPool &operator=(ObjectPool &&)      = delete;

    ~ObjectPool()
    {
        // Every PoolPtr must be gone and every close finished before the
        // pool goes away; otherwise a deleter or close callback would write
        // into freed memory.
        if (live_ != 0 || closing_ != 0) {
            std::abort();
        }
    }

    // Reserve storage for `capacity` objects. Called once at startup.
    Status reserve(std::uint32_t capacity) noexcept
    {
        if (capacity_ != 0 || capacity == 0 || capacity == UINT32_MAX) {
            return fail(Errc::invalid);
        }
        auto objects = Region::reserve(static_cast<std::size_t>(capacity) * sizeof(T), alignof(T));
        if (!objects) {
            return fail(objects.error());
        }
        auto meta = Region::reserve(static_cast<std::size_t>(capacity) * sizeof(Meta), alignof(Meta));
        if (!meta) {
            return fail(meta.error());
        }
        objects_  = std::move(*objects);
        meta_     = std::move(*meta);
        capacity_ = capacity;
        for (std::uint32_t i = 0; i < capacity; ++i) {
            Meta *m = std::construct_at(meta_at(i));
            m->next = (i + 1 < capacity) ? i + 1 : kNone;
        }
        free_head_ = 0;
        SS_POISON(objects_.data(), objects_.size());
        return {};
    }

    template <class... Args>
    Result<PoolPtr<T> > acquire(Args &&...args) noexcept
    {
        if (free_head_ == kNone) {
            return fail(Errc::exhausted);
        }
        std::uint32_t index = free_head_;
        Meta *m             = meta_at(index);
        free_head_          = m->next;
        m->next             = kNone;
        m->state            = State::live;
        ++live_;
        void *raw = slot_at(index);
        SS_UNPOISON(raw, sizeof(T));
        T *object = std::construct_at(static_cast<T *>(raw), std::forward<Args>(args)...);
        return PoolPtr<T>(object, PoolDeleter<T>{ this });
    }

    // Re-own an object whose PoolPtr was release()d, e.g. to hand a raw
    // pointer to a C library callback and take it back afterwards.
    PoolPtr<T> adopt(T *object) noexcept
    {
        if (meta_at(index_of(object))->state != State::live) {
            std::abort();
        }
        return PoolPtr<T>(object, PoolDeleter<T>{ this });
    }

    // Handle for a live object owned by this pool.
    Handle<T> handle_of(const T *object) const noexcept
    {
        std::uint32_t index = index_of(object);
        return Handle<T>{ index, meta_at(index)->gen };
    }

    // The object a handle refers to, or nullptr once it is closing or gone.
    T *resolve(Handle<T> handle) const noexcept
    {
        if (handle.index >= capacity_) {
            return nullptr;
        }
        const Meta *m = meta_at(handle.index);
        if (m->state != State::live || m->gen != handle.gen) {
            return nullptr;
        }
        return static_cast<T *>(slot_at(handle.index));
    }

    bool owns(const T *object) const noexcept
    {
        auto *p     = reinterpret_cast<const std::byte *>(object);
        auto *first = objects_.data();
        return first != nullptr && p >= first && p < first + objects_.size();
    }

    std::uint32_t capacity() const noexcept { return capacity_; }
    std::uint32_t live() const noexcept { return live_; }
    std::uint32_t closing() const noexcept { return closing_; }
    std::uint32_t available() const noexcept { return capacity_ - live_ - closing_; }
    bool full() const noexcept { return free_head_ == kNone; }

private:
    friend struct PoolDeleter<T>;

    enum class State : std::uint8_t { free, live, closing };

    struct Meta {
        std::uint32_t gen  = 1; // 0 is reserved for the empty handle
        std::uint32_t next = kNone;
        State state        = State::free;
    };

    static constexpr std::uint32_t kNone = UINT32_MAX;

    void *slot_at(std::uint32_t index) const noexcept
    {
        return objects_.data() + static_cast<std::size_t>(index) * sizeof(T);
    }
    Meta *meta_at(std::uint32_t index) const noexcept
    {
        return reinterpret_cast<Meta *>(meta_.data()) + index;
    }

    std::uint32_t index_of(const T *object) const noexcept
    {
        if (!owns(object)) {
            std::abort();
        }
        auto offset = static_cast<std::size_t>(reinterpret_cast<const std::byte *>(object) - objects_.data());
        if (offset % sizeof(T) != 0) {
            std::abort();
        }
        return static_cast<std::uint32_t>(offset / sizeof(T));
    }

    void release(T *object) noexcept
    {
        std::uint32_t index = index_of(object);
        Meta *m             = meta_at(index);
        if (m->state != State::live) {
            std::abort(); // double release
        }
        --live_;
        if constexpr (AsyncClosable<T>) {
            m->state = State::closing;
            ++closing_;
            object->begin_close(CloseCompletion(&ObjectPool::closed_trampoline, this, index));
        } else {
            recycle(index);
        }
    }

    static void closed_trampoline(void *pool, std::uint32_t index) noexcept
    {
        auto *self = static_cast<ObjectPool *>(pool);
        Meta *m    = self->meta_at(index);
        if (m->state != State::closing) {
            std::abort();
        }
        --self->closing_;
        self->recycle(index);
    }

    void recycle(std::uint32_t index) noexcept
    {
        Meta *m = meta_at(index);
        std::destroy_at(static_cast<T *>(slot_at(index)));
        SS_POISON(slot_at(index), sizeof(T));
        m->state = State::free;
        if (++m->gen == 0) {
            m->gen = 1;
        }
        m->next    = free_head_;
        free_head_ = index;
    }

    Region objects_;
    Region meta_;
    std::uint32_t capacity_  = 0;
    std::uint32_t free_head_ = kNone;
    std::uint32_t live_      = 0;
    std::uint32_t closing_   = 0;
};

} // namespace ss

#endif
