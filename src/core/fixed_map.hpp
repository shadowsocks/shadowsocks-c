/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_FIXED_MAP_HPP
#define SS_CORE_FIXED_MAP_HPP

// Fixed-capacity associative containers. Replace uthash (cache.cpp,
// ss_event.cpp, manager.cpp) without any per-entry allocation.
//
// FixedHashMap<K, V>
//     Open addressing with linear probing and backward-shift deletion (no
//     tombstones, so lookups stay short however long the process runs).
//     The table is sized at reserve() time to at least twice the capacity.
//     Entries move when others are erased, so never keep a pointer to a
//     value across an erase.
//
// FixedLru<K, V>
//     Map plus recency order. Values live in a slab and never move, so the
//     pointer returned by insert() or find() stays valid until that entry
//     is erased or evicted. Replaces the pseudo-LRU in cache.cpp.
//
// Keys from the network (UDP peer addresses, session IDs) are hashed with a
// per-table seed. Seed it from a CSPRNG in production code so a peer cannot
// precompute colliding keys.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

#include "core/buffer.hpp"
#include "core/region.hpp"
#include "core/result.hpp"

namespace ss {

constexpr std::uint64_t mix64(std::uint64_t x) noexcept
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

inline std::uint64_t hash_bytes(const void *data, std::size_t size, std::uint64_t seed) noexcept
{
    const auto *p   = static_cast<const unsigned char *>(data);
    std::uint64_t h = mix64(seed ^ (size * 0x9e3779b97f4a7c15ULL));
    while (size >= 8) {
        std::uint64_t chunk;
        std::memcpy(&chunk, p, 8);
        h = mix64(h ^ chunk) * 0x9e3779b97f4a7c15ULL;
        p += 8;
        size -= 8;
    }
    std::uint64_t tail = 0;
    if (size != 0) {
        std::memcpy(&tail, p, size);
    }
    return mix64(h ^ tail);
}

// Inline byte-string key of at most N bytes (e.g. a sockaddr or an
// AEAD-2022 session ID).
template <std::size_t N>
class FixedKey {
    static_assert(N > 0 && N <= 255);

public:
    constexpr FixedKey() noexcept = default;

    static std::optional<FixedKey> from(ConstBytes bytes) noexcept
    {
        if (bytes.size() > N) {
            return std::nullopt;
        }
        FixedKey key;
        key.len_ = static_cast<std::uint8_t>(bytes.size());
        if (!bytes.empty()) {
            std::memcpy(key.data_.data(), bytes.data(), bytes.size());
        }
        return key;
    }

    ConstBytes bytes() const noexcept { return { data_.data(), len_ }; }
    std::size_t size() const noexcept { return len_; }

    friend bool operator==(const FixedKey &a, const FixedKey &b) noexcept
    {
        return a.len_ == b.len_ && std::memcmp(a.data_.data(), b.data_.data(), a.len_) == 0;
    }

private:
    std::array<std::byte, N> data_{};
    std::uint8_t len_ = 0;
};

template <class K>
struct Hasher;

template <class K>
requires std::is_integral_v<K> || std::is_enum_v<K>
struct Hasher<K> {
    std::uint64_t operator()(K key, std::uint64_t seed) const noexcept
    {
        return mix64(static_cast<std::uint64_t>(key) ^ mix64(seed));
    }
};

template <std::size_t N>
struct Hasher<FixedKey<N> > {
    std::uint64_t operator()(const FixedKey<N> &key, std::uint64_t seed) const noexcept
    {
        return hash_bytes(key.bytes().data(), key.size(), seed);
    }
};

template <class K, class V, class Hash = Hasher<K> >
class FixedHashMap {
    static_assert(std::is_nothrow_move_constructible_v<K> && std::is_nothrow_move_constructible_v<V>);

public:
    FixedHashMap() noexcept = default;
    FixedHashMap(const FixedHashMap &)            = delete;
    FixedHashMap &operator=(const FixedHashMap &) = delete;
    ~FixedHashMap() { clear(); }

    Status reserve(std::uint32_t capacity, std::uint64_t seed = 0) noexcept
    {
        if (capacity_ != 0 || capacity == 0 || capacity > (UINT32_MAX >> 2)) {
            return fail(Errc::invalid);
        }
        std::uint32_t slots = 2;
        while (slots < capacity * 2U) {
            slots <<= 1;
        }
        auto entries = Region::reserve(static_cast<std::size_t>(slots) * sizeof(Entry), alignof(Entry));
        if (!entries) {
            return fail(entries.error());
        }
        auto used = Region::reserve(slots, 1);
        if (!used) {
            return fail(used.error());
        }
        entries_  = std::move(*entries);
        used_     = std::move(*used);
        mask_     = slots - 1;
        capacity_ = capacity;
        seed_     = seed;
        return {};
    }

    std::uint32_t size() const noexcept { return size_; }
    std::uint32_t capacity() const noexcept { return capacity_; }
    bool empty() const noexcept { return size_ == 0; }
    bool full() const noexcept { return size_ == capacity_; }

    V *find(const K &key) noexcept
    {
        std::uint32_t slot;
        return locate(key, slot) ? &entry(slot)->value : nullptr;
    }
    const V *find(const K &key) const noexcept { return const_cast<FixedHashMap *>(this)->find(key); }
    bool contains(const K &key) const noexcept { return find(key) != nullptr; }

    // Insert a new key. Fails with Errc::exhausted when full and with
    // Errc::invalid when the key is already present.
    template <class... Args>
    Result<V *> emplace(const K &key, Args &&...args) noexcept
    {
        if (capacity_ == 0) {
            return fail(Errc::exhausted);
        }
        std::uint32_t slot;
        if (locate(key, slot)) {
            return fail(Errc::invalid);
        }
        if (full()) {
            return fail(Errc::exhausted);
        }
        // locate() leaves `slot` at the first empty slot of the probe run.
        Entry *e = std::construct_at(entry(slot), key, std::forward<Args>(args)...);
        used_.data()[slot] = std::byte{ 1 };
        ++size_;
        return &e->value;
    }

    std::optional<V> take(const K &key) noexcept
    {
        std::uint32_t slot;
        if (!locate(key, slot)) {
            return std::nullopt;
        }
        std::optional<V> out(std::move(entry(slot)->value));
        remove_at(slot);
        return out;
    }

    bool erase(const K &key) noexcept
    {
        std::uint32_t slot;
        if (!locate(key, slot)) {
            return false;
        }
        remove_at(slot);
        return true;
    }

    void clear() noexcept
    {
        for (std::uint32_t i = 0; capacity_ != 0 && i <= mask_; ++i) {
            if (occupied(i)) {
                std::destroy_at(entry(i));
                used_.data()[i] = std::byte{ 0 };
            }
        }
        size_ = 0;
    }

    // Visit every entry in unspecified order. The callback must not insert
    // or erase.
    template <class F>
    void for_each(F &&f)
    {
        for (std::uint32_t i = 0; capacity_ != 0 && i <= mask_; ++i) {
            if (occupied(i)) {
                f(static_cast<const K &>(entry(i)->key), entry(i)->value);
            }
        }
    }

private:
    struct Entry {
        template <class... Args>
        explicit Entry(const K &k, Args &&...args) : key(k), value(std::forward<Args>(args)...)
        {
        }
        K key;
        V value;
    };

    Entry *entry(std::uint32_t slot) const noexcept { return reinterpret_cast<Entry *>(entries_.data()) + slot; }
    bool occupied(std::uint32_t slot) const noexcept { return used_.data()[slot] != std::byte{ 0 }; }
    std::uint32_t home(const K &key) const noexcept
    {
        return static_cast<std::uint32_t>(Hash{}(key, seed_)) & mask_;
    }

    // True if found (slot = its position); otherwise slot = first empty slot.
    bool locate(const K &key, std::uint32_t &slot) const noexcept
    {
        if (capacity_ == 0) {
            return false;
        }
        std::uint32_t i = home(key);
        while (occupied(i)) {
            if (entry(i)->key == key) {
                slot = i;
                return true;
            }
            i = (i + 1) & mask_;
        }
        slot = i;
        return false;
    }

    void remove_at(std::uint32_t hole) noexcept
    {
        std::destroy_at(entry(hole));
        used_.data()[hole] = std::byte{ 0 };
        --size_;
        // Backward-shift: pull later members of the probe run into the hole
        // when the hole lies between their home slot and where they sit.
        std::uint32_t j = hole;
        for (;;) {
            j = (j + 1) & mask_;
            if (!occupied(j)) {
                return;
            }
            std::uint32_t k = home(entry(j)->key);
            bool movable    = (hole <= j) ? (k <= hole || k > j) : (k <= hole && k > j);
            if (!movable) {
                continue;
            }
            std::construct_at(entry(hole), std::move(*entry(j)));
            used_.data()[hole] = std::byte{ 1 };
            std::destroy_at(entry(j));
            used_.data()[j] = std::byte{ 0 };
            hole = j;
        }
    }

    Region entries_;
    Region used_;
    std::uint32_t mask_     = 0;
    std::uint32_t capacity_ = 0;
    std::uint32_t size_     = 0;
    std::uint64_t seed_     = 0;
};

template <class K, class V, class Hash = Hasher<K> >
class FixedLru {
public:
    FixedLru() noexcept = default;
    FixedLru(const FixedLru &)            = delete;
    FixedLru &operator=(const FixedLru &) = delete;
    ~FixedLru() { clear(); }

    Status reserve(std::uint32_t capacity, std::uint64_t seed = 0) noexcept
    {
        SS_TRY(index_.reserve(capacity, seed));
        auto nodes = Region::reserve(static_cast<std::size_t>(capacity) * sizeof(Node), alignof(Node));
        if (!nodes) {
            return fail(nodes.error());
        }
        nodes_    = std::move(*nodes);
        capacity_ = capacity;
        for (std::uint32_t i = 0; i < capacity; ++i) {
            std::construct_at(node(i))->next = (i + 1 < capacity) ? i + 1 : kNone;
        }
        free_ = 0;
        return {};
    }

    std::uint32_t size() const noexcept { return index_.size(); }
    std::uint32_t capacity() const noexcept { return capacity_; }
    bool empty() const noexcept { return size() == 0; }
    bool full() const noexcept { return free_ == kNone; }

    // Look up and mark as most recently used.
    V *find(const K &key) noexcept
    {
        std::uint32_t *slot = index_.find(key);
        if (slot == nullptr) {
            return nullptr;
        }
        touch(*slot);
        return value(*slot);
    }

    // Look up without changing the recency order.
    V *peek(const K &key) noexcept
    {
        std::uint32_t *slot = index_.find(key);
        return slot == nullptr ? nullptr : value(*slot);
    }

    // Insert as most recently used. Fails with Errc::exhausted when full
    // (evict with pop_oldest() first) and Errc::invalid for a duplicate key.
    template <class... Args>
    Result<V *> emplace(const K &key, Args &&...args) noexcept
    {
        if (free_ == kNone) {
            return fail(Errc::exhausted);
        }
        std::uint32_t slot = free_;
        auto indexed       = index_.emplace(key, slot);
        if (!indexed) {
            return fail(indexed.error());
        }
        Node *n = node(slot);
        free_   = n->next;
        std::construct_at(&n->key, key);
        std::construct_at(value(slot), std::forward<Args>(args)...);
        link_newest(slot);
        return value(slot);
    }

    std::optional<V> take(const K &key) noexcept
    {
        auto slot = index_.take(key);
        if (!slot) {
            return std::nullopt;
        }
        return std::optional<V>(release(*slot));
    }

    bool erase(const K &key) noexcept { return take(key).has_value(); }

    V *oldest() noexcept { return oldest_ == kNone ? nullptr : value(oldest_); }
    const K *oldest_key() const noexcept { return oldest_ == kNone ? nullptr : &node(oldest_)->key; }

    // Remove the least recently used entry and hand its key and value to
    // the caller, who decides how to dispose of it.
    std::optional<std::pair<K, V> > pop_oldest() noexcept
    {
        if (oldest_ == kNone) {
            return std::nullopt;
        }
        std::uint32_t slot = oldest_;
        K key(node(slot)->key);
        index_.erase(key);
        V v = release(slot);
        return std::pair<K, V>(std::move(key), std::move(v));
    }

    void clear() noexcept
    {
        while (oldest_ != kNone) {
            (void)pop_oldest();
        }
    }

    // Visit entries from oldest to newest. The callback may not modify the
    // container.
    template <class F>
    void for_each(F &&f)
    {
        for (std::uint32_t s = oldest_; s != kNone; s = node(s)->next) {
            f(static_cast<const K &>(node(s)->key), *value(s));
        }
    }

private:
    static constexpr std::uint32_t kNone = UINT32_MAX;

    struct Node {
        union {
            K key;
        };
        alignas(V) std::byte storage[sizeof(V)];
        std::uint32_t prev = kNone;
        std::uint32_t next = kNone;

        Node() noexcept {}
        ~Node() {}
    };

    Node *node(std::uint32_t slot) const noexcept { return reinterpret_cast<Node *>(nodes_.data()) + slot; }
    V *value(std::uint32_t slot) const noexcept { return reinterpret_cast<V *>(node(slot)->storage); }

    void link_newest(std::uint32_t slot) noexcept
    {
        Node *n = node(slot);
        n->prev = newest_;
        n->next = kNone;
        if (newest_ != kNone) {
            node(newest_)->next = slot;
        } else {
            oldest_ = slot;
        }
        newest_ = slot;
    }

    void unlink(std::uint32_t slot) noexcept
    {
        Node *n = node(slot);
        if (n->prev != kNone) {
            node(n->prev)->next = n->next;
        } else {
            oldest_ = n->next;
        }
        if (n->next != kNone) {
            node(n->next)->prev = n->prev;
        } else {
            newest_ = n->prev;
        }
        n->prev = n->next = kNone;
    }

    void touch(std::uint32_t slot) noexcept
    {
        if (slot != newest_) {
            unlink(slot);
            link_newest(slot);
        }
    }

    V release(std::uint32_t slot) noexcept
    {
        unlink(slot);
        Node *n = node(slot);
        V out(std::move(*value(slot)));
        std::destroy_at(value(slot));
        std::destroy_at(&n->key);
        n->next = free_;
        free_   = slot;
        return out;
    }

    FixedHashMap<K, std::uint32_t, Hash> index_;
    Region nodes_;
    std::uint32_t capacity_ = 0;
    std::uint32_t free_     = kNone;
    std::uint32_t oldest_   = kNone;
    std::uint32_t newest_   = kNone;
};

} // namespace ss

#endif
