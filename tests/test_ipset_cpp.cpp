// SPDX-License-Identifier: GPL-3.0-or-later
// IP prefix set (src/ipset.cpp) checked against an exhaustive bitmap oracle.
#include <cstdint>
#include <cstring>

#include "ipset.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

uint32_t g_state = 42;

uint32_t next_random()
{
    g_state = g_state * 1664525u + 1013904223u;
    return g_state;
}

void check_family(unsigned width)
{
    ss_ipset set{};
    uint8_t address[16] = {};
    bool oracle[256]    = {};
    const unsigned last = width / 8 - 1;
    // Independent exhaustive bitmap oracle over a /24 or /120. Prefix writes
    // can cover the whole space; host deletion must punch holes in them.
    for (unsigned round = 0; round < 2000; round++) {
        const unsigned host = next_random() >> 24;
        const unsigned bits = next_random() % 9;
        const bool present  = (next_random() >> 31) != 0;
        const unsigned mask = bits == 0 ? 0 : (255u << (8 - bits)) & 255u;
        address[last]       = static_cast<uint8_t>(host);
        ss_ipset_assign(&set, address, width, width - 8 + bits, present);
        for (unsigned i = 0; i < 256; i++) {
            if ((i & mask) == (host & mask)) {
                oracle[i] = present;
            }
            address[last] = static_cast<uint8_t>(i);
            SS_CHECK(ss_ipset_contains(&set, address, width) == oracle[i]);
        }
    }
    ss_ipset_assign(&set, address, width, 0, true);
    std::memset(address, 255, sizeof(address));
    SS_CHECK(ss_ipset_contains(&set, address, width));
    ss_ipset_assign(&set, address, width, width, false);
    SS_CHECK(!ss_ipset_contains(&set, address, width));
    address[last]--;
    SS_CHECK(ss_ipset_contains(&set, address, width));
    ss_ipset_assign(&set, address, width, width + 1, false);
    SS_CHECK(ss_ipset_contains(&set, address, width));
    ss_ipset_clear(&set);
    ss_ipset_clear(&set);
    SS_CHECK(!ss_ipset_contains(&set, address, width));
}

void test_ipv4()
{
    check_family(32);
}

void test_ipv6()
{
    check_family(128);
}

} // namespace

int main()
{
    SS_RUN(test_ipv4);
    SS_RUN(test_ipv6);
    return 0;
}
