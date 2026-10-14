// SPDX-License-Identifier: GPL-3.0-or-later
// Ping-pong bloom filter (src/ppbloom.cpp): add and membership checks.
#include <cstdint>
#include <cstring>

#include "ppbloom.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

void test_init_free()
{
    SS_CHECK(ppbloom_init(1000, 0.01) == 0);
    ppbloom_free();
}

void test_add_check()
{
    ppbloom_init(1000, 0.01);

    const char *item1 = "hello";
    const char *item2 = "world";
    const char *item3 = "missing";

    // Not in the filter initially.
    SS_CHECK(ppbloom_check(item1, std::strlen(item1)) == 0);
    SS_CHECK(ppbloom_check(item2, std::strlen(item2)) == 0);

    ppbloom_add(item1, std::strlen(item1));
    ppbloom_add(item2, std::strlen(item2));

    SS_CHECK(ppbloom_check(item1, std::strlen(item1)) == 1);
    SS_CHECK(ppbloom_check(item2, std::strlen(item2)) == 1);

    SS_CHECK(ppbloom_check(item3, std::strlen(item3)) == 0);

    ppbloom_free();
}

void test_binary_data()
{
    ppbloom_init(1000, 0.01);

    const uint8_t data1[] = { 0x00, 0x01, 0x02, 0x03 };
    const uint8_t data2[] = { 0xFF, 0xFE, 0xFD, 0xFC };

    ppbloom_add(data1, sizeof(data1));
    SS_CHECK(ppbloom_check(data1, sizeof(data1)) == 1);
    SS_CHECK(ppbloom_check(data2, sizeof(data2)) == 0);

    ppbloom_free();
}

} // namespace

int main()
{
    SS_RUN(test_init_free);
    SS_RUN(test_add_check);
    SS_RUN(test_binary_data);
    return 0;
}
