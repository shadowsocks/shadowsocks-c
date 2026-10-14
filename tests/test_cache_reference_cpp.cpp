#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int verbose = 0;

#include "cache.h"

static void
test_create_delete(void)
{
    struct cache *c = NULL;
    int ret = cache_create(&c, 100, NULL);
    assert(ret == 0);
    assert(c != NULL);

    ret = cache_delete(c, 0);
    assert(ret == 0);
    (void)ret;
}

static void
test_create_null(void)
{
    int ret = cache_create(NULL, 100, NULL);
    assert(ret == EINVAL);
    (void)ret;
}

static void
test_insert_lookup(void)
{
    struct cache *c = NULL;
    cache_create(&c, 100, NULL);

    char *data = strdup("test_data");
    cache_insert(c, "key1", 4, data);

    char *result = NULL;
    cache_lookup(c, "key1", 4, &result);
    assert(result != NULL);
    assert(strcmp(result, "test_data") == 0);

    cache_delete(c, 0);
}

static void
test_key_exist(void)
{
    struct cache *c = NULL;
    cache_create(&c, 100, NULL);

    char *data = strdup("value");
    cache_insert(c, "mykey", 5, data);

    assert(cache_key_exist(c, "mykey", 5) == 1);
    assert(cache_key_exist(c, "nokey", 5) == 0);

    cache_delete(c, 0);
}

static void
test_remove(void)
{
    struct cache *c = NULL;
    cache_create(&c, 100, NULL);

    char *data = strdup("to_remove");
    cache_insert(c, "rmkey", 5, data);
    assert(cache_key_exist(c, "rmkey", 5) == 1);

    cache_remove(c, "rmkey", 5);
    assert(cache_key_exist(c, "rmkey", 5) == 0);

    cache_delete(c, 0);
}

static void
test_lookup_missing(void)
{
    struct cache *c = NULL;
    cache_create(&c, 100, NULL);

    char *result = (char *)0xdeadbeef;
    cache_lookup(c, "missing", 7, &result);
    assert(result == NULL);

    cache_delete(c, 0);
}

static void
test_eviction(void)
{
    struct cache *c = NULL;
    cache_create(&c, 3, NULL);

    /* Insert 3 entries to fill cache */
    cache_insert(c, "k1", 2, strdup("v1"));
    cache_insert(c, "k2", 2, strdup("v2"));
    cache_insert(c, "k3", 2, strdup("v3"));

    /* This should trigger eviction of the oldest entry */
    cache_insert(c, "k4", 2, strdup("v4"));

    /* k1 should have been evicted */
    assert(cache_key_exist(c, "k1", 2) == 0);
    /* k4 should exist */
    assert(cache_key_exist(c, "k4", 2) == 1);

    cache_delete(c, 0);
}

int
main(void)
{
    test_create_delete();
    test_create_null();
    test_insert_lookup();
    test_key_exist();
    test_remove();
    test_lookup_missing();
    test_eviction();
    return 0;
}
