// SPDX-License-Identifier: GPL-3.0-or-later
// String and number helpers (src/utils.cpp).
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "test_helpers.hpp"
#include "utils.h"

extern "C" {
int verbose = 0;
}

namespace {

void test_ss_itoa()
{
    char *s = ss_itoa(0);
    SS_CHECK(s != nullptr && std::strcmp(s, "0") == 0);

    s = ss_itoa(42);
    SS_CHECK(s != nullptr && std::strcmp(s, "42") == 0);

    s = ss_itoa(-1);
    SS_CHECK(s != nullptr && std::strcmp(s, "-1") == 0);

    s = ss_itoa(12345);
    SS_CHECK(s != nullptr && std::strcmp(s, "12345") == 0);
}

void test_ss_isnumeric()
{
    SS_CHECK(ss_isnumeric("12345") == 1);
    SS_CHECK(ss_isnumeric("0") == 1);
    SS_CHECK(ss_isnumeric("") == 0);
    SS_CHECK(ss_isnumeric("abc") == 0);
    SS_CHECK(ss_isnumeric("123abc") == 0);
    SS_CHECK(ss_isnumeric("12.34") == 0);
}

void test_ss_strndup()
{
    char *s = ss_strndup("hello world", 5);
    SS_CHECK(s != nullptr && std::strcmp(s, "hello") == 0 && std::strlen(s) == 5);
    std::free(s);

    s = ss_strndup("short", 10);
    SS_CHECK(s != nullptr && std::strcmp(s, "short") == 0);
    std::free(s);

    s = ss_strndup("", 0);
    SS_CHECK(s != nullptr && std::strcmp(s, "") == 0);
    std::free(s);

    const char raw[3] = { 'a', 'b', 'c' };
    s                 = ss_strndup(raw, sizeof(raw));
    SS_CHECK(s != nullptr && std::strcmp(s, "abc") == 0);
    std::free(s);
}

void test_ss_parse_int()
{
    int value     = -1;
    uint16_t port = 0;

    SS_CHECK(ss_parse_int("0", 0, 10, &value) == 0);
    SS_CHECK(value == 0);

    SS_CHECK(ss_parse_int("10", 0, 10, &value) == 0);
    SS_CHECK(value == 10);

    SS_CHECK(ss_parse_int("-1", 0, 10, &value) == -1);
    SS_CHECK(ss_parse_int("11", 0, 10, &value) == -1);
    SS_CHECK(ss_parse_int("12x", 0, 100, &value) == -1);
    SS_CHECK(ss_parse_int("", 0, 100, &value) == -1);
    SS_CHECK(ss_parse_int("999999999999999999999999", 0, INT_MAX, &value) == -1);
    SS_CHECK(ss_parse_int("1", 10, 0, &value) == -1);
    SS_CHECK(ss_parse_int("1", 0, 10, nullptr) == -1);

    SS_CHECK(ss_parse_uint16_port("1", &port) == 0);
    SS_CHECK(port == 1);
    SS_CHECK(ss_parse_uint16_port("65535", &port) == 0);
    SS_CHECK(port == 65535);
    SS_CHECK(ss_parse_uint16_port("0", &port) == -1);
    SS_CHECK(ss_parse_uint16_port("65536", &port) == -1);
    SS_CHECK(ss_parse_uint16_port("22x", &port) == -1);
    SS_CHECK(ss_parse_uint16_port("22", nullptr) == -1);
}

} // namespace

int main()
{
    SS_RUN(test_ss_itoa);
    SS_RUN(test_ss_isnumeric);
    SS_RUN(test_ss_strndup);
    SS_RUN(test_ss_parse_int);
    return 0;
}
