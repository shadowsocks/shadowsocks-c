#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>

int verbose = 0;

#include "crypto.h"

/* Provide nonce_cache symbol needed by crypto.cpp */
struct cache *nonce_cache = NULL;

static void
test_balloc(void)
{
    buffer_t buf;
    memset(&buf, 0, sizeof(buf));

    int ret = balloc(&buf, 100);
    assert(ret == 100);
    (void)ret;
    assert(buf.data != NULL);
    assert(buf.capacity >= 100);
    assert(buf.len == 0);
    assert(buf.idx == 0);

    bfree(&buf);
    assert(buf.data == NULL);
    assert(buf.capacity == 0);
}

static void
test_brealloc(void)
{
    buffer_t buf;
    memset(&buf, 0, sizeof(buf));

    balloc(&buf, 50);
    buf.len = 10;

    /* Grow the buffer */
    int ret = brealloc(&buf, 10, 200);
    assert(ret == 200);
    (void)ret;
    assert(buf.capacity >= 200);
    assert(buf.len == 10);

    bfree(&buf);
}

static void
test_bprepend(void)
{
    buffer_t dst, src;
    memset(&dst, 0, sizeof(dst));
    memset(&src, 0, sizeof(src));

    balloc(&dst, 100);
    balloc(&src, 100);

    /* Put some data in src */
    memcpy(src.data, "HEADER", 6);
    src.len = 6;

    /* Put some data in dst */
    memcpy(dst.data, "BODY", 4);
    dst.len = 4;

    int ret = bprepend(&dst, &src, 200);
    assert(ret == 10);
    (void)ret;
    assert(dst.len == 10);
    assert(memcmp(dst.data, "HEADERBODY", 10) == 0);

    bfree(&dst);
    bfree(&src);
}

static void
test_balloc_zero(void)
{
    buffer_t buf;
    memset(&buf, 0, sizeof(buf));

    int ret = balloc(&buf, 0);
    assert(ret == 0);
    (void)ret;
    /* A zero-capacity buffer should still succeed */
    bfree(&buf);
}

int
main(void)
{
    test_balloc();
    test_brealloc();
    test_bprepend();
    test_balloc_zero();
    return 0;
}
