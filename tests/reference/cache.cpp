/*
 * cache.cpp - Fixed-capacity LRU cache for the UDP relay and AEAD-2022
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

// Layout: one slab of `capacity` nodes, each holding its key inline, linked
// in least-recently-used order, plus an open-addressing index of node ids
// (linear probing, backward-shift deletion, at most half full). Keys are
// stored once, in the slab; the index hashes through it. Both blocks are
// reserved by cache_create() and only touched as entries are used: nodes
// are handed out in order before recycled ones, and the index stores
// node id + 1 so that zero-filled memory reads as empty.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>

#include <sodium.h>

#include "cache.h"
#include "core/fixed_map.hpp"
#include "core/region.hpp"
#include "platform.h"

namespace {

constexpr std::uint32_t kNone = UINT32_MAX;

struct Node {
    std::uint32_t prev = kNone;
    std::uint32_t next = kNone;
    double ts          = 0;
    void *data         = nullptr;
    std::uint16_t key_len = 0;
    bool used          = false;
    // key bytes (max_key_len + 1, NUL-terminated for free_cb) follow
};

std::size_t align_up(std::size_t n, std::size_t a)
{
    return (n + a - 1) & ~(a - 1);
}

} // namespace

struct cache {
    std::size_t capacity    = 0; // as requested; eviction threshold
    std::size_t max_key_len = 0;
    std::size_t stride      = 0; // bytes per node, key included
    void (*free_cb)(void *key, void *element) = nullptr;
    ss::Region nodes;
    ss::Region index; // node id + 1 per slot, 0 when empty
    std::uint32_t node_count = 0; // slab size (capacity, at least 1)
    std::uint32_t fresh      = 0; // nodes [fresh, node_count) were never used
    std::uint32_t mask       = 0; // index slots - 1
    std::uint32_t size       = 0;
    std::uint32_t free_head  = kNone;
    std::uint32_t oldest     = kNone;
    std::uint32_t newest     = kNone;
    std::uint64_t seed       = 0;

    Node *node(std::uint32_t id) const
    {
        return reinterpret_cast<Node *>(nodes.data() + static_cast<std::size_t>(id) * stride);
    }
    char *key(std::uint32_t id) const { return reinterpret_cast<char *>(node(id)) + sizeof(Node); }
    std::uint32_t *slots() const { return reinterpret_cast<std::uint32_t *>(index.data()); }
    bool empty_slot(std::uint32_t i) const { return slots()[i] == 0; }
    std::uint32_t at(std::uint32_t i) const { return slots()[i] - 1; }
    void put(std::uint32_t i, std::uint32_t id) const { slots()[i] = id + 1; }

    std::uint32_t home(const char *k, std::size_t len) const
    {
        return static_cast<std::uint32_t>(ss::hash_bytes(k, len, seed)) & mask;
    }

    bool matches(std::uint32_t id, const char *k, std::size_t len) const
    {
        const Node *n = node(id);
        return n->key_len == len && std::memcmp(key(id), k, len) == 0;
    }

    // Index slot holding the key, or the empty slot that ends its probe run.
    std::uint32_t probe(const char *k, std::size_t len, bool &found) const
    {
        std::uint32_t i = home(k, len);
        while (!empty_slot(i)) {
            if (matches(at(i), k, len)) {
                found = true;
                return i;
            }
            i = (i + 1) & mask;
        }
        found = false;
        return i;
    }

    void unindex(std::uint32_t hole)
    {
        slots()[hole] = 0;
        for (std::uint32_t j = (hole + 1) & mask; !empty_slot(j); j = (j + 1) & mask) {
            std::uint32_t id = at(j);
            std::uint32_t k  = home(key(id), node(id)->key_len);
            bool movable     = (hole <= j) ? (k <= hole || k > j) : (k <= hole && k > j);
            if (movable) {
                put(hole, id);
                slots()[j] = 0;
                hole       = j;
            }
        }
    }

    void unlink(std::uint32_t id)
    {
        Node *n = node(id);
        if (n->prev != kNone) {
            node(n->prev)->next = n->next;
        } else {
            oldest = n->next;
        }
        if (n->next != kNone) {
            node(n->next)->prev = n->prev;
        } else {
            newest = n->prev;
        }
        n->prev = n->next = kNone;
    }

    void link_newest(std::uint32_t id)
    {
        Node *n = node(id);
        n->prev = newest;
        n->next = kNone;
        if (newest != kNone) {
            node(newest)->next = id;
        } else {
            oldest = id;
        }
        newest = id;
    }

    void touch(std::uint32_t id)
    {
        node(id)->ts = ss_monotonic_time();
        if (id != newest) {
            unlink(id);
            link_newest(id);
        }
    }

    // Unlink the entry in index slot `slot` and release its data. The node
    // is back on the free list before free_cb runs, so free_cb may use the
    // cache.
    void drop(std::uint32_t slot, bool release_data)
    {
        std::uint32_t id = at(slot);
        Node *n          = node(id);
        char key_copy[256];
        std::size_t len = n->key_len;
        std::memcpy(key_copy, key(id), len);
        key_copy[len] = '\0';
        void *data    = n->data;

        unindex(slot);
        unlink(id);
        n->used   = false;
        n->data   = nullptr;
        n->next   = free_head;
        free_head = id;
        --size;

        if (release_data && data != nullptr) {
            if (free_cb != nullptr) {
                free_cb(key_copy, data);
            } else {
                std::free(data); // heap-ok: caller-owned data, per the C API contract
            }
        }
    }

    void drop_id(std::uint32_t id, bool release_data)
    {
        bool found         = false;
        std::uint32_t slot = probe(key(id), node(id)->key_len, found);
        if (!found) {
            std::abort(); // index and slab disagree
        }
        drop(slot, release_data);
    }
};

extern "C" {

int
cache_create_keyed(struct cache **dst, size_t capacity, size_t max_key_len,
                   void (*free_cb)(void *key, void *element))
{
    if (dst == nullptr || max_key_len == 0 || max_key_len > 255 || capacity > (UINT32_MAX >> 2)) {
        return EINVAL;
    }
    auto *c = static_cast<struct cache *>(std::malloc(sizeof(struct cache))); // heap-ok: created at startup
    if (c == nullptr) {
        return ENOMEM;
    }
    new (c) struct cache();
    c->capacity    = capacity;
    c->max_key_len = max_key_len;
    c->free_cb     = free_cb;
    c->node_count  = capacity == 0 ? 1 : static_cast<std::uint32_t>(capacity);
    c->stride      = align_up(sizeof(Node) + max_key_len + 1, alignof(Node));
    std::uint32_t slots = 2;
    while (slots < c->node_count * 2U) {
        slots <<= 1;
    }
    c->mask = slots - 1;
    c->seed = (static_cast<std::uint64_t>(randombytes_random()) << 32) | randombytes_random();

    auto nodes = ss::Region::reserve(static_cast<std::size_t>(c->node_count) * c->stride, alignof(Node));
    auto index = ss::Region::reserve(static_cast<std::size_t>(slots) * sizeof(std::uint32_t), alignof(std::uint32_t));
    if (!nodes || !index) {
        c->~cache();
        std::free(c); // heap-ok: failed startup reservation
        return ENOMEM;
    }
    c->nodes = std::move(*nodes);
    c->index = std::move(*index);
    *dst     = c;
    return 0;
}

int
cache_create(struct cache **dst, const size_t capacity,
             void (*free_cb)(void *key, void *element))
{
    return cache_create_keyed(dst, capacity, CACHE_DEFAULT_MAX_KEY, free_cb);
}

int
cache_delete(struct cache *cache, int keep_data)
{
    if (cache == nullptr) {
        return EINVAL;
    }
    while (cache->oldest != kNone) {
        cache->drop_id(cache->oldest, !keep_data);
    }
    cache->~cache();
    std::free(cache); // heap-ok: created at startup
    return 0;
}

int
cache_clear(struct cache *cache, double age)
{
    if (cache == nullptr) {
        return EINVAL;
    }
    double now = ss_monotonic_time();
    // Entries are in last-use order, so the stale ones are at the front.
    while (cache->oldest != kNone && now - cache->node(cache->oldest)->ts > age) {
        cache->drop_id(cache->oldest, true);
    }
    return 0;
}

int
cache_remove(struct cache *cache, char *key, size_t key_len)
{
    if (cache == nullptr || key == nullptr) {
        return EINVAL;
    }
    bool found         = false;
    std::uint32_t slot = cache->probe(key, key_len, found);
    if (found) {
        cache->drop(slot, true);
    }
    return 0;
}

int
cache_lookup(struct cache *cache, char *key, size_t key_len, void *result)
{
    if (cache == nullptr || key == nullptr || result == nullptr) {
        return EINVAL;
    }
    void **out         = static_cast<void **>(result);
    bool found         = false;
    std::uint32_t slot = cache->probe(key, key_len, found);
    if (!found) {
        *out = nullptr;
        return 0;
    }
    std::uint32_t id = cache->at(slot);
    cache->touch(id);
    *out = cache->node(id)->data;
    return 0;
}

int
cache_key_exist(struct cache *cache, char *key, size_t key_len)
{
    if (cache == nullptr || key == nullptr) {
        return 0;
    }
    bool found         = false;
    std::uint32_t slot = cache->probe(key, key_len, found);
    if (!found) {
        return 0;
    }
    cache->touch(cache->at(slot));
    return 1;
}

int
cache_insert(struct cache *cache, char *key, size_t key_len, void *data)
{
    if (cache == nullptr || key == nullptr || key_len > cache->max_key_len) {
        return EINVAL;
    }
    bool found         = false;
    std::uint32_t slot = cache->probe(key, key_len, found);
    if (found) {
        // Re-inserting a key replaces its data; the old data is released
        // as if the entry had been evicted.
        std::uint32_t id = cache->at(slot);
        Node *n          = cache->node(id);
        void *old        = n->data;
        n->data          = data;
        cache->touch(id);
        if (old != nullptr && old != data) {
            char key_copy[256];
            std::memcpy(key_copy, key, key_len);
            key_copy[key_len] = '\0';
            if (cache->free_cb != nullptr) {
                cache->free_cb(key_copy, old);
            } else {
                std::free(old); // heap-ok: caller-owned data, per the C API contract
            }
        }
        return 0;
    }
    std::uint32_t id;
    if (cache->free_head != kNone) {
        id               = cache->free_head;
        cache->free_head = cache->node(id)->next;
    } else if (cache->fresh < cache->node_count) {
        id = cache->fresh++;
        new (cache->node(id)) Node();
    } else {
        std::abort(); // eviction below keeps at least one node free
    }
    Node *n          = cache->node(id);
    n->used          = true;
    n->data          = data;
    n->ts            = ss_monotonic_time();
    n->key_len       = static_cast<std::uint16_t>(key_len);
    std::memcpy(cache->key(id), key, key_len);
    cache->key(id)[key_len] = '\0';
    cache->put(slot, id);
    cache->link_newest(id);
    ++cache->size;

    if (cache->size >= cache->capacity) {
        cache->drop_id(cache->oldest, true);
    }
    return 0;
}

size_t
cache_size(const struct cache *cache)
{
    return cache == nullptr ? 0 : cache->size;
}

} // extern "C"
