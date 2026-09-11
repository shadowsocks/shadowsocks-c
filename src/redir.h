/* * redir.h - Define the redirector's buffers and callbacks
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

#ifndef _REDIR_H
#define _REDIR_H

#include "ss_event.h"

#include "crypto.h"
#include "jconf.h"

typedef struct listen_ctx {
    ss_io io;
    int remote_num;
    int timeout;
    int fd;
    int mptcp;
    int tos;
    struct sockaddr **remote_addr;
} listen_ctx_t;

typedef struct server_ctx {
    ss_io io;
    int connected;
    struct server *server;
} server_ctx_t;

typedef struct server {
    int fd;

    buffer_t *buf;

    cipher_ctx_t *e_ctx;
    cipher_ctx_t *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct remote *remote;

    struct sockaddr_storage destaddr;
    ss_timer delayed_connect_watcher;
} server_t;

typedef struct remote_ctx {
    ss_io io;
    ss_timer watcher;
    int connected;
    struct remote *remote;
} remote_ctx_t;

typedef struct remote {
    int fd;
    buffer_t *buf;
    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
    uint32_t counter;
    struct sockaddr *addr;
} remote_t;

#endif // _REDIR_H
