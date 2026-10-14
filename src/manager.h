/*
 * server.h - Define shadowsocks server's buffers and callbacks
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _MANAGER_H
#define _MANAGER_H

#include <time.h>
#include "core.h"
#include "core/intrusive_list.hpp"

#include "jconf.h"

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct manager_ctx {
    int fd;
    int fast_open;
    int no_delay;
    int reuse_port;
    int verbose;
    int mode;
    char *password;
    char *key;
    char *timeout;
    char *method;
    char *iface;
    char *acl;
    char *user;
    char *plugin;
    char *plugin_opts;
    char *manager_address;
    char **hosts;
    int host_num;
    char *nameservers;
    int mtu;
    int ipv6first;
    char *workdir;
#ifdef HAVE_SETRLIMIT
    int nofile;
#endif
};

/* A managed ss-server, linked into server_table (at most MAX_PORT_NUM). */
struct server : ss::ListNode<> {
    char port[8]          = {};
    char password[128]    = {};
    char fast_open[8]     = {};
    char no_delay[8]      = {};
    char *mode            = nullptr;
    char *method          = nullptr;
    char *plugin          = nullptr;
    char *plugin_opts     = nullptr;
    uint64_t traffic      = 0;
};

#ifdef __cplusplus
}
#endif

#endif // _MANAGER_H
