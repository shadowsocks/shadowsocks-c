/* SPDX-License-Identifier: GPL-3.0-or-later */
// IntrusiveList, RefPtr and FixedHeap: the remaining ownership primitives.
#include <cstdint>
#include <cstring>
#include <utility>

#include "core/fixed_heap.hpp"
#include "core/intrusive_list.hpp"
#include "core/pool.hpp"
#include "core/ref.hpp"
#include "test_helpers.hpp"

namespace {

struct IdleTag;

struct Conn : ss::ListNode<>, ss::ListNode<IdleTag> {
    explicit Conn(int v) noexcept : id(v) {}
    int id;
};

void test_list_basic()
{
    ss::IntrusiveList<Conn> all;
    ss::IntrusiveList<Conn, IdleTag> idle;
    Conn a(1), b(2), c(3);
    all.push_back(a);
    all.push_back(b);
    all.push_front(c);
    idle.push_back(b);
    SS_CHECK(all.size() == 3 && idle.size() == 1);
    SS_CHECK(all.front()->id == 3 && all.back()->id == 2);

    all.move_to_back(c);
    SS_CHECK(all.back()->id == 3);

    // Being on one list does not affect the other.
    ss::IntrusiveList<Conn>::remove(b);
    SS_CHECK(all.size() == 2 && idle.front() == &b);

    int sum = 0;
    all.for_each([&](Conn &x) { sum += x.id; });
    SS_CHECK(sum == 4);
    SS_CHECK(all.pop_front()->id == 1);
}

void test_list_unlinks_on_destruction()
{
    ss::IntrusiveList<Conn> all;
    {
        Conn temp(9);
        all.push_back(temp);
        SS_CHECK(!all.empty());
    }
    SS_CHECK(all.empty());
}

// A pooled, shared object: the pool owns the storage, references own the
// object's lifetime.
struct Session : ss::RefCounted<Session> {
    static inline ss::ObjectPool<Session> *pool = nullptr;
    static inline int destroyed                 = 0;

    // The PoolPtr is parked inside the object while references exist.
    ss::PoolPtr<Session> self;

    static void destroy(Session *s) noexcept
    {
        ++destroyed;
        ss::PoolPtr<Session> owner = std::move(s->self);
        owner.reset(); // returns the slot to the pool
    }
};

ss::RefPtr<Session> make_session()
{
    auto slot = Session::pool->acquire();
    SS_CHECK(slot);
    Session *raw = slot->get();
    raw->self    = std::move(slot).value();
    return ss::RefPtr<Session>(raw);
}

void test_refptr_lifecycle()
{
    ss::ObjectPool<Session> pool;
    SS_CHECK(pool.reserve(2));
    Session::pool      = &pool;
    Session::destroyed = 0;
    {
        ss::RefPtr<Session> table = make_session();
        SS_CHECK(table->ref_count() == 1);
        ss::RefPtr<Session> relay = table;
        SS_CHECK(table->ref_count() == 2);
        ss::RefPtr<Session> moved = std::move(relay);
        SS_CHECK(!relay && moved->ref_count() == 2); // NOLINT(bugprone-use-after-move): checks moved-from state
        table.reset();
        SS_CHECK(Session::destroyed == 0 && pool.live() == 1);
        moved = nullptr;
        SS_CHECK(Session::destroyed == 1 && pool.live() == 0);
    }
    SS_CHECK(pool.available() == 2);
}

void test_fixed_heap()
{
    ss::FixedHeap heap;
    SS_CHECK(heap.reserve(4096));
    void *a = heap.allocate(10);
    void *b = heap.allocate_zeroed(4, 25);
    SS_CHECK(a && b && heap.owns(a) && heap.owns(b));
    SS_CHECK(reinterpret_cast<std::uintptr_t>(a) % 16 == 0);
    auto *zeros = static_cast<unsigned char *>(b);
    for (int i = 0; i < 100; ++i) {
        SS_CHECK(zeros[i] == 0);
    }
    std::memcpy(a, "0123456789", 10);
    void *grown = heap.reallocate(a, 200);
    SS_CHECK(grown && std::memcmp(grown, "0123456789", 10) == 0);

    auto before = heap.stats();
    heap.deallocate(grown);
    heap.deallocate(b);
    SS_CHECK(heap.stats().in_use < before.in_use);

    // Freed blocks are reused instead of consuming fresh space.
    void *again = heap.allocate(200);
    SS_CHECK(again == grown);
    heap.deallocate(again);

    SS_CHECK(heap.allocate(ss::FixedHeap::max_request() + 1) == nullptr);
    SS_CHECK(heap.allocate(8192) == nullptr); // over budget
    SS_CHECK(heap.stats().failures == 2);
}

} // namespace

int main()
{
    SS_RUN(test_list_basic);
    SS_RUN(test_list_unlinks_on_destruction);
    SS_RUN(test_refptr_lifecycle);
    SS_RUN(test_fixed_heap);
    return 0;
}
