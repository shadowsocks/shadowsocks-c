/* Optional migration differential test. Link against the pre-migration ipset
 * and cork archives; these are intentionally not production dependencies. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ipset/ipset.h>
#include "ipset.h"
int verbose = 0;
static uint32_t state = 0x725cab91;
static uint32_t next_random(void)
{
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}
static void check_family(unsigned width)
{
    struct ss_ipset current = {0};
    struct ip_set reference;
    ipset_init(&reference);
    for (unsigned round = 0; round < 2000; round++) {
        uint8_t bytes[16];
        for (unsigned i = 0; i < sizeof(bytes); i++) bytes[i] = (uint8_t)next_random();
        unsigned prefix = next_random() % (width + 1);
        bool present = (next_random() & 1) != 0;
        ss_ipset_assign(&current, bytes, width, prefix, present);
        struct cork_ipv4 v4;
        struct cork_ipv6 v6;
        memcpy(v4._.u8, bytes, sizeof(v4._.u8));
        memcpy(v6._.u8, bytes, sizeof(v6._.u8));
        if (width == 32) {
            if (present) ipset_ipv4_add_network(&reference, &v4, prefix);
            else ipset_ipv4_remove_network(&reference, &v4, prefix);
        } else {
            if (present) ipset_ipv6_add_network(&reference, &v6, prefix);
            else ipset_ipv6_remove_network(&reference, &v6, prefix);
        }
        for (unsigned sample = 0; sample < 257; sample++) {
            if (sample != 0) {
                for (unsigned i = 0; i < sizeof(bytes); i++) bytes[i] = (uint8_t)next_random();
            }
            memcpy(v4._.u8, bytes, sizeof(v4._.u8));
            memcpy(v6._.u8, bytes, sizeof(v6._.u8));
            bool old = width == 32 ? ipset_contains_ipv4(&reference, &v4) : ipset_contains_ipv6(&reference, &v6);
            assert(old == ss_ipset_contains(&current, bytes, width));
        }
    }
    ipset_done(&reference);
    ss_ipset_clear(&current);
}
int main(void)
{
    ipset_init_library();
    check_family(32);
    check_family(128);
    puts("1,028,000 IPv4/IPv6 membership comparisons matched the original libipset");
    return 0;
}
