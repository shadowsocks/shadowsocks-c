/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_H
#define SS_CORE_H
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "platform.h"

#ifdef __cplusplus
extern "C" {
#endif

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
#ifdef __cplusplus
}
#endif

#endif
