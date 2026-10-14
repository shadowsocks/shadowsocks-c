// SPDX-License-Identifier: GPL-3.0-or-later
// Basic behaviour of the legacy cache (tests/reference/cache.cpp): create,
// insert, lookup, remove and eviction.
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "cache.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

char *dup_string(const char *text)
{
    const size_t size = std::strlen(text) + 1;
    auto *copy        = static_cast<char *>(std::malloc(size));
    SS_CHECK(copy != nullptr);
    std::memcpy(copy, text, size);
    return copy;
}

// The legacy API takes writable keys; copy literals into a buffer.
struct Key {
    char text[16];
    size_t length;
    explicit Key(const char *literal) : text{}, length(std::strlen(literal))
    {
        SS_CHECK(length < sizeof(text));
        std::memcpy(text, literal, length);
    }
};

void insert(struct cache *c, const char *key, const char *value)
{
    Key k(key);
    cache_insert(c, k.text, k.length, dup_string(value));
}

void lookup(struct cache *c, const char *key, char **result)
{
    Key k(key);
    cache_lookup(c, k.text, k.length, result);
}

int exists(struct cache *c, const char *key)
{
    Key k(key);
    return cache_key_exist(c, k.text, k.length);
}

void remove_key(struct cache *c, const char *key)
{
    Key k(key);
    cache_remove(c, k.text, k.length);
}

void test_create_delete()
{
    struct cache *c = nullptr;
    SS_CHECK(cache_create(&c, 100, nullptr) == 0);
    SS_CHECK(c != nullptr);
    SS_CHECK(cache_delete(c, 0) == 0);
}

void test_create_null()
{
    SS_CHECK(cache_create(nullptr, 100, nullptr) == EINVAL);
}

void test_insert_lookup()
{
    struct cache *c = nullptr;
    cache_create(&c, 100, nullptr);

    insert(c, "key1", "test_data");

    char *result = nullptr;
    lookup(c, "key1", &result);
    SS_CHECK(result != nullptr);
    SS_CHECK(std::strcmp(result, "test_data") == 0);

    cache_delete(c, 0);
}

void test_key_exist()
{
    struct cache *c = nullptr;
    cache_create(&c, 100, nullptr);

    insert(c, "mykey", "value");

    SS_CHECK(exists(c, "mykey") == 1);
    SS_CHECK(exists(c, "nokey") == 0);

    cache_delete(c, 0);
}

void test_remove()
{
    struct cache *c = nullptr;
    cache_create(&c, 100, nullptr);

    insert(c, "rmkey", "to_remove");
    SS_CHECK(exists(c, "rmkey") == 1);

    remove_key(c, "rmkey");
    SS_CHECK(exists(c, "rmkey") == 0);

    cache_delete(c, 0);
}

void test_lookup_missing()
{
    struct cache *c = nullptr;
    cache_create(&c, 100, nullptr);

    char *result = reinterpret_cast<char *>(static_cast<uintptr_t>(0xdeadbeef));
    lookup(c, "missing", &result);
    SS_CHECK(result == nullptr);

    cache_delete(c, 0);
}

void test_eviction()
{
    struct cache *c = nullptr;
    cache_create(&c, 3, nullptr);

    // Fill the cache.
    insert(c, "k1", "v1");
    insert(c, "k2", "v2");
    insert(c, "k3", "v3");

    // This triggers eviction of the oldest entry.
    insert(c, "k4", "v4");

    SS_CHECK(exists(c, "k1") == 0);
    SS_CHECK(exists(c, "k4") == 1);

    cache_delete(c, 0);
}

} // namespace

int main()
{
    SS_RUN(test_create_delete);
    SS_RUN(test_create_null);
    SS_RUN(test_insert_lookup);
    SS_RUN(test_key_exist);
    SS_RUN(test_remove);
    SS_RUN(test_lookup_missing);
    SS_RUN(test_eviction);
    return 0;
}
