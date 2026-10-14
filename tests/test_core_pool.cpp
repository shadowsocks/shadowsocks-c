/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <cstdint>
#include <utility>

#include "core/pool.hpp"
#include "test_helpers.hpp"

namespace {

int g_destroyed = 0;

struct Plain {
    explicit Plain(int v) noexcept : value(v) {}
    ~Plain() { ++g_destroyed; }
    int value;
};

// Models an object that owns libuv handles: it can only be recycled once
// its asynchronous closes have finished.
struct Closable {
    static inline ss::CloseCompletion pending;
    static inline int begun = 0;

    void begin_close(ss::CloseCompletion done) noexcept
    {
        ++begun;
        pending = done;
    }
    ~Closable() { ++g_destroyed; }
};

struct ClosesSynchronously {
    void begin_close(ss::CloseCompletion done) noexcept { done(); }
};

void test_acquire_release()
{
    ss::ObjectPool<Plain> pool;
    SS_CHECK(pool.reserve(2));
    g_destroyed = 0;
    {
        auto a = pool.acquire(1);
        auto b = pool.acquire(2);
        SS_CHECK(a && b);
        SS_CHECK((*a)->value == 1 && (*b)->value == 2);
        SS_CHECK(pool.live() == 2 && pool.full());

        auto c = pool.acquire(3);
        SS_CHECK(!c && c.error().code == ss::Errc::exhausted);
    }
    SS_CHECK(g_destroyed == 2);
    SS_CHECK(pool.live() == 0 && pool.available() == 2);
}

void test_reuse_and_handles()
{
    ss::ObjectPool<Plain> pool;
    SS_CHECK(pool.reserve(1));
    auto first = pool.acquire(10);
    SS_CHECK(first);
    ss::PoolPtr<Plain> owner = std::move(first).value();
    ss::Handle<Plain> h      = pool.handle_of(owner.get());
    SS_CHECK(h);
    SS_CHECK(pool.resolve(h) == owner.get());

    owner.reset();
    SS_CHECK(pool.resolve(h) == nullptr);

    // The slot is reused, but the stale handle must not resolve to the new
    // occupant.
    auto second = pool.acquire(20);
    SS_CHECK(second);
    SS_CHECK(pool.resolve(h) == nullptr);
    SS_CHECK(pool.resolve(pool.handle_of(second->get())) == second->get());
    SS_CHECK(!pool.resolve(ss::Handle<Plain>{}));
}

void test_async_close()
{
    ss::ObjectPool<Closable> pool;
    SS_CHECK(pool.reserve(1));
    g_destroyed      = 0;
    Closable::begun  = 0;
    auto obj         = pool.acquire();
    SS_CHECK(obj);
    ss::Handle<Closable> h = pool.handle_of(obj->get());

    obj->reset();
    // Ownership is gone, but the memory is not reusable yet.
    SS_CHECK(Closable::begun == 1);
    SS_CHECK(g_destroyed == 0);
    SS_CHECK(pool.closing() == 1 && pool.available() == 0);
    SS_CHECK(pool.resolve(h) == nullptr);
    SS_CHECK(!pool.acquire());

    Closable::pending();
    SS_CHECK(g_destroyed == 1);
    SS_CHECK(pool.closing() == 0 && pool.available() == 1);
    {
        auto again = pool.acquire();
        SS_CHECK(again);
    }
    // The pool refuses to die with a close still in flight, so finish it.
    SS_CHECK(pool.closing() == 1);
    Closable::pending();
    SS_CHECK(pool.closing() == 0);
}

void test_sync_close()
{
    ss::ObjectPool<ClosesSynchronously> pool;
    SS_CHECK(pool.reserve(1));
    {
        auto obj = pool.acquire();
        SS_CHECK(obj);
    }
    SS_CHECK(pool.available() == 1);
}

void test_reserve_rules()
{
    ss::ObjectPool<Plain> pool;
    SS_CHECK(!pool.acquire(1));
    SS_CHECK(!pool.reserve(0));
    SS_CHECK(pool.reserve(4));
    SS_CHECK(!pool.reserve(4));
    SS_CHECK(pool.capacity() == 4);
}

} // namespace

int main()
{
    SS_RUN(test_acquire_release);
    SS_RUN(test_reuse_and_handles);
    SS_RUN(test_async_close);
    SS_RUN(test_sync_close);
    SS_RUN(test_reserve_rules);
    return 0;
}
