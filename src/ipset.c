/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "ipset.h"
#include <assert.h>
#include <stdlib.h>
#include "utils.h"

/* NULL is an empty subtree. A full node represents every address below it.
 * Recursion is bounded by the address width, never by the number of rules. */
struct ss_ipset_node {
    struct ss_ipset_node *child[2];
    bool full;
};

static struct ss_ipset_node *
node_new(bool full)
{
    struct ss_ipset_node *node = ss_malloc(sizeof(*node));
    node->child[0] = node->child[1] = NULL;
    node->full = full;
    return node;
}

static void
node_free(struct ss_ipset_node *node)
{
    if (node != NULL) {
        node_free(node->child[0]);
        node_free(node->child[1]);
        free(node);
    }
}

void
ss_ipset_clear(struct ss_ipset *set)
{
    node_free(set->root);
    set->root = NULL;
}

static struct ss_ipset_node *
node_assign(struct ss_ipset_node *node, const uint8_t *address,
            unsigned bit, unsigned prefix, bool present)
{
    if ((node == NULL && !present) || (node != NULL && node->full && present)) {
        return node;
    }
    if (bit == prefix) {
        node_free(node);
        return present ? node_new(true) : NULL;
    }
    if (node == NULL) {
        node = node_new(false);
    } else if (node->full) {
        node->child[0] = node_new(true);
        node->child[1] = node_new(true);
        node->full = false;
    }
    unsigned side = (address[bit / 8] >> (7 - bit % 8)) & 1;
    node->child[side] = node_assign(node->child[side], address, bit + 1, prefix, present);
    if (node->child[0] == NULL && node->child[1] == NULL) {
        free(node);
        return NULL;
    }
    if (node->child[0] != NULL && node->child[0]->full &&
        node->child[1] != NULL && node->child[1]->full) {
        node_free(node->child[0]);
        node_free(node->child[1]);
        node->child[0] = node->child[1] = NULL;
        node->full = true;
    }
    return node;
}

void
ss_ipset_assign(struct ss_ipset *set, const uint8_t *address,
                unsigned width, unsigned prefix, bool present)
{
    assert(width == 32 || width == 128);
    if (prefix <= width) {
        set->root = node_assign(set->root, address, 0, prefix, present);
    }
}

bool
ss_ipset_contains(const struct ss_ipset *set, const uint8_t *address, unsigned width)
{
    const struct ss_ipset_node *node = set->root;
    for (unsigned bit = 0; node != NULL; bit++) {
        if (node->full) {
            return true;
        }
        if (bit == width) {
            break;
        }
        unsigned side = (address[bit / 8] >> (7 - bit % 8)) & 1;
        node = node->child[side];
    }
    return false;
}
