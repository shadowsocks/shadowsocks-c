/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_H
#define SS_CORE_H
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "platform.h"

#define ss_container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

struct ss_list_item {
    struct ss_list_item *next, *prev;
};
struct ss_list {
    struct ss_list_item head;
};
static inline void
ss_list_init(struct ss_list *list)
{
    list->head.next = list->head.prev = &list->head;
}
static inline void
ss_list_add(struct ss_list *list, struct ss_list_item *item)
{
    item->prev = list->head.prev;
    item->next = &list->head;
    item->prev->next = item;
    list->head.prev = item;
}
static inline void
ss_list_remove(struct ss_list_item *item)
{
    item->prev->next = item->next;
    item->next->prev = item->prev;
}
static inline struct ss_list_item *
ss_list_start(const struct ss_list *list)
{
    return list->head.next;
}
static inline bool
ss_list_is_end(const struct ss_list *list, const struct ss_list_item *item)
{
    return item == &list->head;
}
static inline struct ss_list_item *
ss_list_head(const struct ss_list *list)
{
    return ss_list_is_end(list, list->head.next) ? NULL : list->head.next;
}
/* Cache the next link before the body so the current item may be freed. */
#define ss_list_foreach_void(list, item, after) \
    for ((item) = ss_list_start(list), (after) = (item)->next; \
         !ss_list_is_end((list), (item)); (item) = (after), (after) = (item)->next)

struct ss_ip {
    unsigned version;
    uint8_t bytes[16];
};
static inline int
ss_ip_init(struct ss_ip *ip, const char *text)
{
    if (inet_pton(AF_INET, text, ip->bytes) == 1) {
        ip->version = 4;
        return 0;
    }
    if (inet_pton(AF_INET6, text, ip->bytes) == 1) {
        ip->version = 6;
        return 0;
    }
    ip->version = 0;
    return -1;
}
#endif
