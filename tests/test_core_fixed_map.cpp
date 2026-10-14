/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <cstdint>
#include <cstring>
#include <memory>
#include <string_view>

#include "core/fixed_map.hpp"
#include "test_helpers.hpp"

namespace {

using Key = ss::FixedKey<16>;

Key key(std::string_view s)
{
    auto k = Key::from(ss::as_bytes(s.data(), s.size()));
    SS_CHECK(k.has_value());
    return *k;
}

// Every key lands in the same home slot, to exercise probe runs and the
// backward-shift deletion.
struct CollidingHash {
    std::uint64_t operator()(std::uint32_t, std::uint64_t) const noexcept { return 7; }
};

void test_map_basic()
{
    ss::FixedHashMap<std::uint32_t, int> map;
    SS_CHECK(map.reserve(3, 0x1234));
    SS_CHECK(map.emplace(1, 10));
    SS_CHECK(map.emplace(2, 20));
    SS_CHECK(map.emplace(3, 30));
    auto dup = map.emplace(2, 99);
    SS_CHECK(!dup && dup.error().code == ss::Errc::invalid);
    auto over = map.emplace(4, 40);
    SS_CHECK(!over && over.error().code == ss::Errc::exhausted);
    SS_CHECK(*map.find(2) == 20);
    auto taken = map.take(2);
    SS_CHECK(taken && *taken == 20);
    SS_CHECK(!map.find(2) && map.size() == 2);
    SS_CHECK(map.emplace(4, 40));
    SS_CHECK(!map.erase(5));
}

void test_map_backward_shift()
{
    ss::FixedHashMap<std::uint32_t, int, CollidingHash> map;
    SS_CHECK(map.reserve(8));
    for (std::uint32_t i = 0; i < 8; ++i) {
        SS_CHECK(map.emplace(i, static_cast<int>(i) * 100));
    }
    // Remove from the middle of the probe run; later entries must still be
    // reachable without tombstones.
    SS_CHECK(map.erase(3));
    SS_CHECK(map.erase(0));
    for (std::uint32_t i = 0; i < 8; ++i) {
        const int *v = map.find(i);
        if (i == 0 || i == 3) {
            SS_CHECK(v == nullptr);
        } else {
            SS_CHECK(v != nullptr && *v == static_cast<int>(i) * 100);
        }
    }
    int count = 0;
    map.for_each([&](std::uint32_t, int &) { ++count; });
    SS_CHECK(count == 6);
}

void test_map_move_only_values()
{
    ss::FixedHashMap<std::uint32_t, std::unique_ptr<int> > map;
    SS_CHECK(map.reserve(2));
    SS_CHECK(map.emplace(1, std::make_unique<int>(5)));
    auto v = map.take(1);
    SS_CHECK(v && **v == 5);
}

void test_lru_order()
{
    ss::FixedLru<Key, int> lru;
    SS_CHECK(lru.reserve(3, 42));
    SS_CHECK(lru.emplace(key("a"), 1));
    SS_CHECK(lru.emplace(key("b"), 2));
    SS_CHECK(lru.emplace(key("c"), 3));
    SS_CHECK(lru.full());
    auto over = lru.emplace(key("d"), 4);
    SS_CHECK(!over && over.error().code == ss::Errc::exhausted);

    // Touch "a" so "b" becomes the oldest.
    SS_CHECK(*lru.find(key("a")) == 1);
    SS_CHECK(*lru.oldest_key() == key("b"));
    // peek() does not change the order.
    SS_CHECK(*lru.peek(key("b")) == 2);
    SS_CHECK(*lru.oldest_key() == key("b"));

    auto evicted = lru.pop_oldest();
    SS_CHECK(evicted && evicted->first == key("b") && evicted->second == 2);
    SS_CHECK(lru.emplace(key("d"), 4));

    int order[3] = {};
    int n        = 0;
    lru.for_each([&](const Key &, int &v) { order[n++] = v; });
    SS_CHECK(n == 3 && order[0] == 3 && order[1] == 1 && order[2] == 4);
}

void test_lru_stable_values()
{
    ss::FixedLru<std::uint32_t, int> lru;
    SS_CHECK(lru.reserve(64));
    auto first = lru.emplace(0, 1000);
    SS_CHECK(first);
    int *stable = *first;
    for (std::uint32_t i = 1; i < 64; ++i) {
        SS_CHECK(lru.emplace(i, static_cast<int>(i)));
    }
    for (std::uint32_t i = 1; i < 64; i += 2) {
        SS_CHECK(lru.erase(i));
    }
    // Erasing others reshuffles the index but never moves values.
    SS_CHECK(lru.peek(0) == stable && *stable == 1000);
    auto taken = lru.take(0);
    SS_CHECK(taken && *taken == 1000);
    SS_CHECK(lru.size() == 31);
    lru.clear();
    SS_CHECK(lru.empty() && lru.oldest() == nullptr);
}

void test_key_limits()
{
    char big[17] = {};
    SS_CHECK(!Key::from(ss::as_bytes(big, sizeof(big))));
    SS_CHECK(key("ab") != key("abc"));
    SS_CHECK(key("") == key(""));
}

} // namespace

int main()
{
    SS_RUN(test_map_basic);
    SS_RUN(test_map_backward_shift);
    SS_RUN(test_map_move_only_values);
    SS_RUN(test_lru_order);
    SS_RUN(test_lru_stable_values);
    SS_RUN(test_key_limits);
    return 0;
}
