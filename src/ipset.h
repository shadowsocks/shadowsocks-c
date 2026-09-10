/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_IPSET_H
#define SS_IPSET_H
#include <stdbool.h>
#include <stdint.h>

struct ss_ipset_node;
struct ss_ipset {
    struct ss_ipset_node *root;
};

/* Addresses are network-order bytes; width is 32 or 128. A set stores one
 * address family. Removing a host from a network creates a hole in that net. */
void ss_ipset_clear(struct ss_ipset *set);
void ss_ipset_assign(struct ss_ipset *set, const uint8_t *address,
                     unsigned width, unsigned prefix, bool present);
bool ss_ipset_contains(const struct ss_ipset *set, const uint8_t *address, unsigned width);
#endif
