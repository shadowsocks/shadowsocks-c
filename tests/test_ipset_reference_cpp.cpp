// SPDX-License-Identifier: GPL-3.0-or-later
// Optional migration differential test. Link against the pre-migration ipset
// and cork archives; these are intentionally not production dependencies.
#include <cstdint>
#include <cstdio>
#include <cstring>

#include <ipset/ipset.h>

#include "ipset.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

uint32_t g_state = 0x725cab91;

uint32_t next_random()
{
    g_state ^= g_state << 13;
    g_state ^= g_state >> 17;
    g_state ^= g_state << 5;
    return g_state;
}

void check_family(unsigned width)
{
    ss_ipset current{};
    ip_set reference;
    ipset_init(&reference);
    for (unsigned round = 0; round < 2000; round++) {
        uint8_t bytes[16];
        for (unsigned i = 0; i < sizeof(bytes); i++) {
            bytes[i] = static_cast<uint8_t>(next_random());
        }
        const unsigned prefix = next_random() % (width + 1);
        const bool present    = (next_random() & 1) != 0;
        ss_ipset_assign(&current, bytes, width, prefix, present);
        cork_ipv4 v4;
        cork_ipv6 v6;
        std::memcpy(v4._.u8, bytes, sizeof(v4._.u8));
        std::memcpy(v6._.u8, bytes, sizeof(v6._.u8));
        if (width == 32) {
            if (present) {
                ipset_ipv4_add_network(&reference, &v4, prefix);
            } else {
                ipset_ipv4_remove_network(&reference, &v4, prefix);
            }
        } else {
            if (present) {
                ipset_ipv6_add_network(&reference, &v6, prefix);
            } else {
                ipset_ipv6_remove_network(&reference, &v6, prefix);
            }
        }
        for (unsigned sample = 0; sample < 257; sample++) {
            if (sample != 0) {
                for (unsigned i = 0; i < sizeof(bytes); i++) {
                    bytes[i] = static_cast<uint8_t>(next_random());
                }
            }
            std::memcpy(v4._.u8, bytes, sizeof(v4._.u8));
            std::memcpy(v6._.u8, bytes, sizeof(v6._.u8));
            const bool old = width == 32 ? ipset_contains_ipv4(&reference, &v4) : ipset_contains_ipv6(&reference, &v6);
            SS_CHECK(old == ss_ipset_contains(&current, bytes, width));
        }
    }
    ipset_done(&reference);
    ss_ipset_clear(&current);
}

} // namespace

int main()
{
    ipset_init_library();
    check_family(32);
    check_family(128);
    std::puts("1,028,000 IPv4/IPv6 membership comparisons matched the original libipset");
    return 0;
}
