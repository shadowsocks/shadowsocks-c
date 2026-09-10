#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "ipset.h"
int verbose = 0;

static uint32_t state = 42;
static uint32_t
next_random(void)
{
    state = state * 1664525u + 1013904223u;
    return state;
}

static void
check_family(unsigned width)
{
    struct ss_ipset set = {0};
    uint8_t address[16] = {0};
    bool oracle[256] = {false};
    unsigned last = width / 8 - 1;
    /* Independent exhaustive bitmap oracle over a /24 or /120. Prefix writes
     * can cover the whole space; host deletion must punch holes in them. */
    for (unsigned round = 0; round < 2000; round++) {
        unsigned host = next_random() >> 24;
        unsigned bits = next_random() % 9;
        bool present = (next_random() >> 31) != 0;
        unsigned mask = bits == 0 ? 0 : (255u << (8 - bits)) & 255u;
        address[last] = (uint8_t)host;
        ss_ipset_assign(&set, address, width, width - 8 + bits, present);
        for (unsigned i = 0; i < 256; i++) {
            if ((i & mask) == (host & mask)) {
                oracle[i] = present;
            }
            address[last] = (uint8_t)i;
            assert(ss_ipset_contains(&set, address, width) == oracle[i]);
        }
    }
    ss_ipset_assign(&set, address, width, 0, true);
    memset(address, 255, sizeof(address));
    assert(ss_ipset_contains(&set, address, width));
    ss_ipset_assign(&set, address, width, width, false);
    assert(!ss_ipset_contains(&set, address, width));
    address[last]--;
    assert(ss_ipset_contains(&set, address, width));
    ss_ipset_assign(&set, address, width, width + 1, false);
    assert(ss_ipset_contains(&set, address, width));
    ss_ipset_clear(&set);
    ss_ipset_clear(&set);
    assert(!ss_ipset_contains(&set, address, width));
}

int
main(void)
{
    check_family(32);
    check_family(128);
    return 0;
}
