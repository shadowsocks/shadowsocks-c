#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>

int verbose = 0;

#include "utils.h"

static void
test_ss_itoa(void)
{
    char *s;

    s = ss_itoa(0);
    assert(s != NULL);
    assert(strcmp(s, "0") == 0);

    s = ss_itoa(42);
    assert(s != NULL);
    assert(strcmp(s, "42") == 0);

    s = ss_itoa(-1);
    assert(s != NULL);
    assert(strcmp(s, "-1") == 0);

    s = ss_itoa(12345);
    assert(s != NULL);
    assert(strcmp(s, "12345") == 0);
    (void)s;
}

static void
test_ss_isnumeric(void)
{
    assert(ss_isnumeric("12345") == 1);
    assert(ss_isnumeric("0") == 1);
    assert(ss_isnumeric("") == 0);
    assert(ss_isnumeric("abc") == 0);
    assert(ss_isnumeric("123abc") == 0);
    assert(ss_isnumeric("12.34") == 0);
}

static void
test_ss_strndup(void)
{
    char *s;

    s = ss_strndup("hello world", 5);
    assert(s != NULL);
    assert(strcmp(s, "hello") == 0);
    assert(strlen(s) == 5);
    free(s);

    s = ss_strndup("short", 10);
    assert(s != NULL);
    assert(strcmp(s, "short") == 0);
    free(s);

    s = ss_strndup("", 0);
    assert(s != NULL);
    assert(strcmp(s, "") == 0);
    free(s);

    char raw[3] = { 'a', 'b', 'c' };
    s = ss_strndup(raw, sizeof(raw));
    assert(s != NULL);
    assert(strcmp(s, "abc") == 0);
    free(s);
}

static void
test_ss_parse_int(void)
{
    int value = -1;
    uint16_t port = 0;

    assert(ss_parse_int("0", 0, 10, &value) == 0);
    assert(value == 0);

    assert(ss_parse_int("10", 0, 10, &value) == 0);
    assert(value == 10);

    assert(ss_parse_int("-1", 0, 10, &value) == -1);
    assert(ss_parse_int("11", 0, 10, &value) == -1);
    assert(ss_parse_int("12x", 0, 100, &value) == -1);
    assert(ss_parse_int("", 0, 100, &value) == -1);
    assert(ss_parse_int("999999999999999999999999", 0, INT_MAX, &value) == -1);
    assert(ss_parse_int("1", 10, 0, &value) == -1);
    assert(ss_parse_int("1", 0, 10, NULL) == -1);

    assert(ss_parse_uint16_port("1", &port) == 0);
    assert(port == 1);
    assert(ss_parse_uint16_port("65535", &port) == 0);
    assert(port == 65535);
    assert(ss_parse_uint16_port("0", &port) == -1);
    assert(ss_parse_uint16_port("65536", &port) == -1);
    assert(ss_parse_uint16_port("22x", &port) == -1);
    assert(ss_parse_uint16_port("22", NULL) == -1);
}

int
main(void)
{
    test_ss_itoa();
    test_ss_isnumeric();
    test_ss_strndup();
    test_ss_parse_int();
    return 0;
}
