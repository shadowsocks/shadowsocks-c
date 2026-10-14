#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

int verbose = 0;

#include "ppbloom.h"

static void
test_init_free(void)
{
    int ret = ppbloom_init(1000, 0.01);
    assert(ret == 0);
    (void)ret;
    ppbloom_free();
}

static void
test_add_check(void)
{
    ppbloom_init(1000, 0.01);

    const char *item1 = "hello";
    const char *item2 = "world";
    const char *item3 = "missing";

    /* Not in filter initially */
    assert(ppbloom_check(item1, strlen(item1)) == 0);
    assert(ppbloom_check(item2, strlen(item2)) == 0);

    /* Add items */
    ppbloom_add(item1, strlen(item1));
    ppbloom_add(item2, strlen(item2));

    /* Should be found */
    assert(ppbloom_check(item1, strlen(item1)) == 1);
    assert(ppbloom_check(item2, strlen(item2)) == 1);

    /* Should not be found */
    assert(ppbloom_check(item3, strlen(item3)) == 0);
    (void)item3;

    ppbloom_free();
}

static void
test_binary_data(void)
{
    ppbloom_init(1000, 0.01);

    const uint8_t data1[] = { 0x00, 0x01, 0x02, 0x03 };
    const uint8_t data2[] = { 0xFF, 0xFE, 0xFD, 0xFC };

    ppbloom_add(data1, sizeof(data1));
    assert(ppbloom_check(data1, sizeof(data1)) == 1);
    assert(ppbloom_check(data2, sizeof(data2)) == 0);
    (void)data2;

    ppbloom_free();
}

int
main(void)
{
    test_init_free();
    test_add_check();
    test_binary_data();
    return 0;
}
