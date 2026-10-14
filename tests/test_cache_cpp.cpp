/* SPDX-License-Identifier: GPL-3.0-or-later */
// Edge cases of the fixed-capacity cache (src/cache.cpp) beyond
// test_cache_reference_cpp.cpp, and proof that a full cache churns without allocating.
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "alloc_audit/alloc_probe.hpp"
#include "cache.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

int g_freed            = 0;
struct cache *g_victim = nullptr;

void count_free(void *, void *) { ++g_freed; }

// Re-enters the cache it belongs to, as udprelay's callbacks may.
void reentrant_free(void *key, void *)
{
    ++g_freed;
    char probe[] = "other";
    (void)cache_key_exist(g_victim, probe, 5);
    (void)cache_remove(g_victim, static_cast<char *>(key), std::strlen(static_cast<char *>(key)));
}

void key(char (&buf)[16], int i)
{
    std::snprintf(buf, sizeof(buf), "k%d", i);
}

void test_capacity_boundary()
{
    // The AEAD-2022 session table relies on this: a cache of N keeps N - 1.
    struct cache *c = nullptr;
    SS_CHECK(cache_create(&c, 4096, count_free) == 0);
    g_freed = 0;
    static int token;
    char k[16];
    for (int i = 0; i < 4095; ++i) {
        key(k, i);
        SS_CHECK(cache_insert(c, k, std::strlen(k), &token) == 0);
    }
    SS_CHECK(cache_size(c) == 4095 && g_freed == 0);
    key(k, 4095);
    SS_CHECK(cache_insert(c, k, std::strlen(k), &token) == 0);
    SS_CHECK(cache_size(c) == 4095 && g_freed == 1);
    key(k, 0);
    SS_CHECK(cache_key_exist(c, k, std::strlen(k)) == 0); // the oldest went
    SS_CHECK(cache_delete(c, 0) == 0);
    SS_CHECK(g_freed == 4096);
}

void test_lru_order_and_replace()
{
    struct cache *c = nullptr;
    SS_CHECK(cache_create(&c, 4, count_free) == 0);
    g_freed = 0;
    static int a, b, d, e, f;
    SS_CHECK(cache_insert(c, (char *)"a", 1, &a) == 0);
    SS_CHECK(cache_insert(c, (char *)"b", 1, &b) == 0);
    SS_CHECK(cache_insert(c, (char *)"d", 1, &d) == 0);
    // Touching "a" makes "b" the eviction candidate.
    void *found = nullptr;
    SS_CHECK(cache_lookup(c, (char *)"a", 1, &found) == 0 && found == &a);
    SS_CHECK(cache_insert(c, (char *)"e", 1, &e) == 0);
    SS_CHECK(cache_key_exist(c, (char *)"b", 1) == 0);
    SS_CHECK(cache_key_exist(c, (char *)"a", 1) == 1);
    // Re-inserting replaces the data and releases the old one.
    SS_CHECK(cache_insert(c, (char *)"a", 1, &f) == 0);
    SS_CHECK(cache_lookup(c, (char *)"a", 1, &found) == 0 && found == &f);
    SS_CHECK(g_freed == 2);
    SS_CHECK(cache_lookup(c, (char *)"zz", 2, &found) == 0 && found == nullptr);
    // keep_data skips the callbacks.
    SS_CHECK(cache_delete(c, 1) == 0);
    SS_CHECK(g_freed == 2);
}

void test_clear_by_age()
{
    struct cache *c = nullptr;
    SS_CHECK(cache_create(&c, 8, count_free) == 0);
    g_freed = 0;
    static int x;
    SS_CHECK(cache_insert(c, (char *)"old", 3, &x) == 0);
    SS_CHECK(cache_clear(c, 3600) == 0);
    SS_CHECK(cache_size(c) == 1 && g_freed == 0);
    SS_CHECK(cache_clear(c, -1) == 0); // everything is older than -1 s
    SS_CHECK(cache_size(c) == 0 && g_freed == 1);
    SS_CHECK(cache_delete(c, 0) == 0);
}

void test_reentrant_callback_and_limits()
{
    struct cache *c = nullptr;
    SS_CHECK(cache_create_keyed(&c, 2, 8, reentrant_free) == 0);
    g_victim = c;
    g_freed  = 0;
    static int x;
    SS_CHECK(cache_insert(c, (char *)"one", 3, &x) == 0);
    SS_CHECK(cache_insert(c, (char *)"two", 3, &x) == 0); // evicts "one" -> callback re-enters
    SS_CHECK(g_freed == 1 && cache_size(c) == 1);
    SS_CHECK(cache_insert(c, (char *)"too-long-key", 12, &x) == EINVAL);
    SS_CHECK(cache_create_keyed(&c, 2, 0, nullptr) == EINVAL);
    SS_CHECK(cache_create_keyed(&c, 2, 256, nullptr) == EINVAL);
    SS_CHECK(cache_delete(g_victim, 0) == 0);
    SS_CHECK(cache_insert(nullptr, (char *)"x", 1, &x) == EINVAL);
}

void test_zero_capacity()
{
    // Matches the uthash version: every insert evicts immediately.
    struct cache *c = nullptr;
    SS_CHECK(cache_create(&c, 0, count_free) == 0);
    g_freed = 0;
    static int x;
    SS_CHECK(cache_insert(c, (char *)"a", 1, &x) == 0);
    SS_CHECK(cache_insert(c, (char *)"b", 1, &x) == 0);
    SS_CHECK(cache_size(c) == 0 && g_freed == 2);
    SS_CHECK(cache_delete(c, 0) == 0);
}

void test_steady_churn_without_allocation()
{
    struct cache *c = nullptr;
    SS_CHECK(cache_create(&c, 512, count_free) == 0);
    static int x;
    char k[16];
    for (int i = 0; i < 2048; ++i) { // warm-up touches every node
        key(k, i);
        SS_CHECK(cache_insert(c, k, std::strlen(k), &x) == 0);
    }
    ss::test::alloc_mark();
    void *found = nullptr;
    for (int i = 0; i < 100000; ++i) {
        key(k, i);
        SS_CHECK(cache_insert(c, k, std::strlen(k), &x) == 0);
        SS_CHECK(cache_lookup(c, k, std::strlen(k), &found) == 0 && found == &x);
        if (i % 7 == 0) {
            SS_CHECK(cache_remove(c, k, std::strlen(k)) == 0);
        }
    }
    (void)cache_clear(c, -1);
    ss::test::alloc_mark();
    SS_CHECK(cache_size(c) == 0);
    SS_CHECK(cache_delete(c, 0) == 0);
}

} // namespace

int main()
{
    SS_RUN(test_capacity_boundary);
    SS_RUN(test_lru_order_and_replace);
    SS_RUN(test_clear_by_age);
    SS_RUN(test_reentrant_callback_and_limits);
    SS_RUN(test_zero_capacity);
    SS_RUN(test_steady_churn_without_allocation);
    return 0;
}
