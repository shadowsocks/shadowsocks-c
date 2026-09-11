/*
 * redir.c - Provide a transparent TCP proxy through remote shadowsocks
 *           server
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

#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6/ip6_tables.h>

#include "core.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugin.h"
#include "netutils.h"
#include "utils.h"
#include "common.h"
#include "redir.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT       19
#endif

#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT     75
#endif

static void accept_cb(SS_P_ ss_io *w, int revents);
static void server_recv_cb(SS_P_ ss_io *w, int revents);
static void server_send_cb(SS_P_ ss_io *w, int revents);
static void remote_recv_cb(SS_P_ ss_io *w, int revents);
static void remote_send_cb(SS_P_ ss_io *w, int revents);

static remote_t *new_remote(int fd, int timeout);
static server_t *new_server(int fd);

static void free_remote(remote_t *remote);
static void close_and_free_remote(SS_P_ remote_t *remote);
static void free_server(server_t *server);
static void close_and_free_server(SS_P_ server_t *server);

int verbose    = 0;
int reuse_port = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

static crypto_t *crypto;

static int ipv6first = 0;
static int mode      = TCP_ONLY;
#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif
int fast_open       = 0;
static int no_delay = 0;
static int ret_val  = 0;

static struct ss_signal sigint_watcher;
static struct ss_signal sigterm_watcher;
static struct ss_signal sigchld_watcher;

static int tcp_tproxy = 0; /* use tproxy instead of redirect (for tcp) */

static int
getdestaddr(int fd, struct sockaddr_storage *destaddr)
{
    socklen_t socklen = sizeof(*destaddr);
    int error         = 0;

    if (tcp_tproxy) {
        error = getsockname(fd, (void *)destaddr, &socklen);
    } else {
        error = getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, destaddr, &socklen);
        if (error) { // Didn't find a proper way to detect IP version.
            error = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, destaddr, &socklen);
        }
    }

    if (error) {
        return -1;
    }
    return 0;
}

int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int
create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    result = NULL;

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0) {
        LOGI("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    if (result == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        listen_sock = ss_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        int opt = 1;
        ss_setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        ss_setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif
        if (reuse_port) {
            int err = set_reuseport(listen_sock);
            if (err == 0) {
                LOGI("tcp port reuse enabled");
            }
        }

        if (tcp_tproxy) {
            int level = 0, optname = 0;
            if (rp->ai_family == AF_INET) {
                level = IPPROTO_IP;
                optname = IP_TRANSPARENT;
            } else {
                level = IPPROTO_IPV6;
                optname = IPV6_TRANSPARENT;
            }

            if (ss_setsockopt(listen_sock, level, optname, &opt, sizeof(opt)) != 0) {
                ERROR("setsockopt IP_TRANSPARENT");
                exit(EXIT_FAILURE);
            }
            LOGI("tcp tproxy mode enabled");
        }

        if (tcp_incoming_sndbuf > 0) {
            ss_setsockopt(listen_sock, SOL_SOCKET, SO_SNDBUF, &tcp_incoming_sndbuf, sizeof(int));
        }

        if (tcp_incoming_rcvbuf > 0) {
            ss_setsockopt(listen_sock, SOL_SOCKET, SO_RCVBUF, &tcp_incoming_rcvbuf, sizeof(int));
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        ss_socket_close(listen_sock);
        listen_sock = -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static void
server_recv_cb(SS_P_ ss_io *w, int revents)
{
    server_ctx_t *server_recv_ctx = (server_ctx_t *)w;
    server_t *server              = server_recv_ctx->server;
    remote_t *remote              = server->remote;

    ss_timer_stop(SS_A_ & server->delayed_connect_watcher);

    ssize_t r = recv(server->fd, remote->buf->data + remote->buf->len,
                     SOCKET_BUF_SIZE - remote->buf->len, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(SS_A_ remote);
        close_and_free_server(SS_A_ server);
        return;
    } else if (r == -1) {
        if (ss_socket_error() == EAGAIN || ss_socket_error() == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("server recv");
            close_and_free_remote(SS_A_ remote);
            close_and_free_server(SS_A_ server);
            return;
        }
    }

    remote->buf->len += r;

    if (verbose) {
        uint16_t port = 0;
        char ipstr[INET6_ADDRSTRLEN];
        memset(&ipstr, 0, INET6_ADDRSTRLEN);

        if (AF_INET == server->destaddr.ss_family) {
            struct sockaddr_in *sa = (struct sockaddr_in *)&(server->destaddr);
            ss_inet_ntop(AF_INET, &(sa->sin_addr), ipstr, INET_ADDRSTRLEN);
            port = ntohs(sa->sin_port);
        } else {
            struct sockaddr_in6 *sa = (struct sockaddr_in6 *)&(server->destaddr);
            ss_inet_ntop(AF_INET6, &(sa->sin6_addr), ipstr, INET6_ADDRSTRLEN);
            port = ntohs(sa->sin6_port);
        }

        LOGI("redir to %s:%d, len=%zu, recv=%zd", ipstr, port, remote->buf->len, r);
    }

    if (!remote->send_ctx->connected) {
        ss_io_stop(SS_A_ & server_recv_ctx->io);
        ss_io_start(SS_A_ & remote->send_ctx->io);
        return;
    }

    int err = crypto->encrypt(remote->buf, server->e_ctx, SOCKET_BUF_SIZE);

    if (err) {
        LOGE("invalid password or cipher");
        close_and_free_remote(SS_A_ remote);
        close_and_free_server(SS_A_ server);
        return;
    }

    int s = send(remote->fd, remote->buf->data, remote->buf->len, 0);

    if (s == -1) {
        if (ss_socket_error() == EAGAIN || ss_socket_error() == EWOULDBLOCK) {
            // no data, wait for send
            remote->buf->idx = 0;
            ss_io_stop(SS_A_ & server_recv_ctx->io);
            ss_io_start(SS_A_ & remote->send_ctx->io);
            return;
        } else {
            ERROR("send");
            close_and_free_remote(SS_A_ remote);
            close_and_free_server(SS_A_ server);
            return;
        }
    } else if (s < remote->buf->len) {
        remote->buf->len -= s;
        remote->buf->idx  = s;
        ss_io_stop(SS_A_ & server_recv_ctx->io);
        ss_io_start(SS_A_ & remote->send_ctx->io);
        return;
    } else {
        remote->buf->idx = 0;
        remote->buf->len = 0;
    }
}

static void
server_send_cb(SS_P_ ss_io *w, int revents)
{
    server_ctx_t *server_send_ctx = (server_ctx_t *)w;
    server_t *server              = server_send_ctx->server;
    remote_t *remote              = server->remote;
    if (server->buf->len == 0) {
        // close and free
        close_and_free_remote(SS_A_ remote);
        close_and_free_server(SS_A_ server);
        return;
    } else {
        // has data to send
        ssize_t s = send(server->fd, server->buf->data + server->buf->idx,
                         server->buf->len, 0);
        if (s == -1) {
            if (ss_socket_error() != EAGAIN && ss_socket_error() != EWOULDBLOCK) {
                ERROR("send");
                close_and_free_remote(SS_A_ remote);
                close_and_free_server(SS_A_ server);
            }
            return;
        } else if (s < server->buf->len) {
            // partly sent, move memory, wait for the next time to send
            server->buf->len -= s;
            server->buf->idx += s;
            return;
        } else {
            // all sent out, wait for reading
            server->buf->len = 0;
            server->buf->idx = 0;
            ss_io_stop(SS_A_ & server_send_ctx->io);
            ss_io_start(SS_A_ & remote->recv_ctx->io);
        }
    }
}

static void
delayed_connect_cb(SS_P_ ss_timer *watcher, int revents)
{
    server_t *server = ss_container_of(watcher, server_t,
                                         delayed_connect_watcher);
    remote_t *remote = server->remote;

    int r = connect(remote->fd, remote->addr,
                    get_sockaddr_len(remote->addr));

    remote->addr = NULL;

    if (r == -1 && ss_socket_error() != CONNECT_IN_PROGRESS) {
        ERROR("connect");
        close_and_free_remote(SS_A_ remote);
        close_and_free_server(SS_A_ server);
        return;
    } else {
        // listen to remote connected event
        ss_io_start(SS_A_ & remote->send_ctx->io);
        ss_timer_start(SS_A_ & remote->send_ctx->watcher);
    }
}

static void
remote_timeout_cb(SS_P_ ss_timer *watcher, int revents)
{
    remote_ctx_t *remote_ctx
        = ss_container_of(watcher, remote_ctx_t, watcher);

    remote_t *remote = remote_ctx->remote;
    server_t *server = remote->server;

    ss_timer_stop(SS_A_ watcher);

    close_and_free_remote(SS_A_ remote);
    close_and_free_server(SS_A_ server);
}

static void
remote_recv_cb(SS_P_ ss_io *w, int revents)
{
    remote_ctx_t *remote_recv_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_recv_ctx->remote;
    server_t *server              = remote->server;

    ssize_t r = recv(remote->fd, server->buf->data, SOCKET_BUF_SIZE, 0);

    if (r == 0) {
        // connection closed
        close_and_free_remote(SS_A_ remote);
        close_and_free_server(SS_A_ server);
        return;
    } else if (r == -1) {
        if (ss_socket_error() == EAGAIN || ss_socket_error() == EWOULDBLOCK) {
            // no data
            // continue to wait for recv
            return;
        } else {
            ERROR("remote recv");
            close_and_free_remote(SS_A_ remote);
            close_and_free_server(SS_A_ server);
            return;
        }
    }

    server->buf->len = r;

    int err = crypto->decrypt(server->buf, server->d_ctx, SOCKET_BUF_SIZE);
    if (err == CRYPTO_ERROR) {
        LOGE("invalid password or cipher");
        close_and_free_remote(SS_A_ remote);
        close_and_free_server(SS_A_ server);
        return;
    } else if (err == CRYPTO_NEED_MORE) {
        return; // Wait for more
    }

    int s = send(server->fd, server->buf->data, server->buf->len, 0);

    if (s == -1) {
        if (ss_socket_error() == EAGAIN || ss_socket_error() == EWOULDBLOCK) {
            // no data, wait for send
            server->buf->idx = 0;
            ss_io_stop(SS_A_ & remote_recv_ctx->io);
            ss_io_start(SS_A_ & server->send_ctx->io);
        } else {
            ERROR("send");
            close_and_free_remote(SS_A_ remote);
            close_and_free_server(SS_A_ server);
            return;
        }
    } else if (s < server->buf->len) {
        server->buf->len -= s;
        server->buf->idx  = s;
        ss_io_stop(SS_A_ & remote_recv_ctx->io);
        ss_io_start(SS_A_ & server->send_ctx->io);
    }

    // Disable TCP_NODELAY after the first response are sent
    if (!remote->recv_ctx->connected && !no_delay) {
        int opt = 0;
        ss_setsockopt(server->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
        ss_setsockopt(remote->fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    }
    remote->recv_ctx->connected = 1;
}

static void
remote_send_cb(SS_P_ ss_io *w, int revents)
{
    remote_ctx_t *remote_send_ctx = (remote_ctx_t *)w;
    remote_t *remote              = remote_send_ctx->remote;
    server_t *server              = remote->server;

    ss_timer_stop(SS_A_ & remote_send_ctx->watcher);

    if (!remote_send_ctx->connected) {
        int r = 0;
        if (remote->addr == NULL) {
            struct sockaddr_storage addr;
            memset(&addr, 0, sizeof(struct sockaddr_storage));
            socklen_t len = sizeof addr;
            r = getpeername(remote->fd, (struct sockaddr *)&addr, &len);
        }
        if (r == 0) {
            remote_send_ctx->connected = 1;

            ss_io_stop(SS_A_ & remote_send_ctx->io);
            ss_io_stop(SS_A_ & server->recv_ctx->io);
            ss_io_start(SS_A_ & remote->recv_ctx->io);

            // send destaddr
            buffer_t ss_addr_to_send;
            buffer_t *abuf = &ss_addr_to_send;
            balloc(abuf, SOCKET_BUF_SIZE);

            if (AF_INET6 == server->destaddr.ss_family) { // IPv6
                abuf->data[abuf->len++] = 4;          // Type 4 is IPv6 address

                size_t in6_addr_len = sizeof(struct in6_addr);
                memcpy(abuf->data + abuf->len,
                       &(((struct sockaddr_in6 *)&(server->destaddr))->sin6_addr),
                       in6_addr_len);
                abuf->len += in6_addr_len;
                memcpy(abuf->data + abuf->len,
                       &(((struct sockaddr_in6 *)&(server->destaddr))->sin6_port),
                       2);
            } else {                             // IPv4
                abuf->data[abuf->len++] = 1; // Type 1 is IPv4 address

                size_t in_addr_len = sizeof(struct in_addr);
                memcpy(abuf->data + abuf->len,
                       &((struct sockaddr_in *)&(server->destaddr))->sin_addr, in_addr_len);
                abuf->len += in_addr_len;
                memcpy(abuf->data + abuf->len,
                       &((struct sockaddr_in *)&(server->destaddr))->sin_port, 2);
            }

            abuf->len += 2;

            int err = crypto->encrypt(abuf, server->e_ctx, SOCKET_BUF_SIZE);
            if (err) {
                LOGE("invalid password or cipher");
                bfree(abuf);
                close_and_free_remote(SS_A_ remote);
                close_and_free_server(SS_A_ server);
                return;
            }

            err = crypto->encrypt(remote->buf, server->e_ctx, SOCKET_BUF_SIZE);
            if (err) {
                LOGE("invalid password or cipher");
                bfree(abuf);
                close_and_free_remote(SS_A_ remote);
                close_and_free_server(SS_A_ server);
                return;
            }

            bprepend(remote->buf, abuf, SOCKET_BUF_SIZE);
            bfree(abuf);
        } else {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(SS_A_ remote);
            close_and_free_server(SS_A_ server);
            return;
        }
    }

    if (remote->buf->len == 0) {
        // close and free
        close_and_free_remote(SS_A_ remote);
        close_and_free_server(SS_A_ server);
        return;
    } else {
        // has data to send
        int s = -1;

        if (remote->addr != NULL) {
#if defined(TCP_FASTOPEN_CONNECT)
            int optval = 1;
            if (ss_setsockopt(remote->fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT,
                           (void *)&optval, sizeof(optval)) < 0)
                FATAL("failed to set TCP_FASTOPEN_CONNECT");
            s = connect(remote->fd, remote->addr, get_sockaddr_len(remote->addr));
            if (s == 0)
                s = send(remote->fd, remote->buf->data, remote->buf->len, 0);
#elif defined(MSG_FASTOPEN)
            s = sendto(remote->fd, remote->buf->data + remote->buf->idx,
                       remote->buf->len, MSG_FASTOPEN, remote->addr,
                       get_sockaddr_len(remote->addr));
#else
            FATAL("tcp fast open is not supported on this platform");
#endif

            remote->addr = NULL;

            if (s == -1) {
                if (ss_socket_error() == CONNECT_IN_PROGRESS) {
                    ss_io_start(SS_A_ & remote_send_ctx->io);
                    ss_timer_start(SS_A_ & remote_send_ctx->watcher);
                } else {
                    if (ss_socket_error() == EOPNOTSUPP || ss_socket_error() == EPROTONOSUPPORT ||
                        ss_socket_error() == ENOPROTOOPT) {
                        fast_open = 0;
                        LOGE("fast open is not supported on this platform");
                    } else {
                        ERROR("fast_open_connect");
                    }
                    close_and_free_remote(SS_A_ remote);
                    close_and_free_server(SS_A_ server);
                }
                return;
            }
        } else {
            s = send(remote->fd, remote->buf->data + remote->buf->idx,
                     remote->buf->len, 0);
        }

        if (s == -1) {
            if (ss_socket_error() != EAGAIN && ss_socket_error() != EWOULDBLOCK) {
                ERROR("send");
                // close and free
                close_and_free_remote(SS_A_ remote);
                close_and_free_server(SS_A_ server);
            }
            return;
        } else if (s < remote->buf->len) {
            // partly sent, move memory, wait for the next time to send
            remote->buf->len -= s;
            remote->buf->idx += s;
            ss_io_start(SS_A_ & remote_send_ctx->io);
            return;
        } else {
            // all sent out, wait for reading
            remote->buf->len = 0;
            remote->buf->idx = 0;
            ss_io_stop(SS_A_ & remote_send_ctx->io);
            ss_io_start(SS_A_ & server->recv_ctx->io);
        }
    }
}

static remote_t *
new_remote(int fd, int timeout)
{
    remote_t *remote = ss_malloc(sizeof(remote_t));
    memset(remote, 0, sizeof(remote_t));

    remote->recv_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->send_ctx = ss_malloc(sizeof(remote_ctx_t));
    remote->buf      = ss_malloc(sizeof(buffer_t));
    balloc(remote->buf, SOCKET_BUF_SIZE);
    memset(remote->recv_ctx, 0, sizeof(remote_ctx_t));
    memset(remote->send_ctx, 0, sizeof(remote_ctx_t));
    remote->fd                  = fd;
    remote->recv_ctx->remote    = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote    = remote;
    remote->send_ctx->connected = 0;

    ss_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, SS_READ);
    ss_io_init(&remote->send_ctx->io, remote_send_cb, fd, SS_WRITE);
    ss_timer_init(&remote->send_ctx->watcher, remote_timeout_cb,
                  min(MAX_CONNECT_TIMEOUT, timeout), 0);

    return remote;
}

static void
free_remote(remote_t *remote)
{
    if (remote->server != NULL) {
        remote->server->remote = NULL;
    }
    if (remote->buf != NULL) {
        bfree(remote->buf);
        ss_free(remote->buf);
    }
    ss_free(remote->recv_ctx);
    ss_free(remote->send_ctx);
    ss_free(remote);
}

static void
close_and_free_remote(SS_P_ remote_t *remote)
{
    if (remote != NULL) {
        ss_timer_stop(SS_A_ & remote->send_ctx->watcher);
        ss_io_stop(SS_A_ & remote->send_ctx->io);
        ss_io_stop(SS_A_ & remote->recv_ctx->io);
        ss_socket_close(remote->fd);
        free_remote(remote);
    }
}

static server_t *
new_server(int fd)
{
    server_t *server = ss_malloc(sizeof(server_t));
    memset(server, 0, sizeof(server_t));

    server->recv_ctx = ss_malloc(sizeof(server_ctx_t));
    server->send_ctx = ss_malloc(sizeof(server_ctx_t));
    server->buf      = ss_malloc(sizeof(buffer_t));
    balloc(server->buf, SOCKET_BUF_SIZE);
    memset(server->recv_ctx, 0, sizeof(server_ctx_t));
    memset(server->send_ctx, 0, sizeof(server_ctx_t));
    server->fd                  = fd;
    server->recv_ctx->server    = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server    = server;
    server->send_ctx->connected = 0;

    server->e_ctx = ss_malloc(sizeof(cipher_ctx_t));
    server->d_ctx = ss_malloc(sizeof(cipher_ctx_t));
    crypto->ctx_init(crypto->cipher, server->e_ctx, 1);
    crypto->ctx_init(crypto->cipher, server->d_ctx, 0);
    cipher_ctx_pair(server->e_ctx, server->d_ctx);

    ss_io_init(&server->recv_ctx->io, server_recv_cb, fd, SS_READ);
    ss_io_init(&server->send_ctx->io, server_send_cb, fd, SS_WRITE);

    ss_timer_init(&server->delayed_connect_watcher, delayed_connect_cb, 0.05,
                  0);

    return server;
}

static void
free_server(server_t *server)
{
    if (server->remote != NULL) {
        server->remote->server = NULL;
    }
    if (server->e_ctx != NULL) {
        crypto->ctx_release(server->e_ctx);
        ss_free(server->e_ctx);
    }
    if (server->d_ctx != NULL) {
        crypto->ctx_release(server->d_ctx);
        ss_free(server->d_ctx);
    }
    if (server->buf != NULL) {
        bfree(server->buf);
        ss_free(server->buf);
    }
    ss_free(server->recv_ctx);
    ss_free(server->send_ctx);
    ss_free(server);
}

static void
close_and_free_server(SS_P_ server_t *server)
{
    if (server != NULL) {
        ss_io_stop(SS_A_ & server->send_ctx->io);
        ss_io_stop(SS_A_ & server->recv_ctx->io);
        ss_timer_stop(SS_A_ & server->delayed_connect_watcher);
        ss_socket_close(server->fd);
        free_server(server);
    }
}

static void
accept_cb(SS_P_ ss_io *w, int revents)
{
    listen_ctx_t *listener = (listen_ctx_t *)w;
    struct sockaddr_storage destaddr;
    memset(&destaddr, 0, sizeof(struct sockaddr_storage));

    int err;

    int serverfd = ss_accept(listener->fd, NULL, NULL);
    if (serverfd == -1) {
        ERROR("accept");
        return;
    }

    err = getdestaddr(serverfd, &destaddr);
    if (err) {
        ERROR("getdestaddr");
        return;
    }

    setnonblocking(serverfd);
    int opt = 1;
    ss_setsockopt(serverfd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    ss_setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    int index                    = (int)randombytes_uniform((uint32_t)listener->remote_num);
    struct sockaddr *remote_addr = listener->remote_addr[index];

    int protocol = IPPROTO_TCP;
    if (listener->mptcp < 0) {
        protocol = IPPROTO_MPTCP; // Enable upstream MPTCP
    }
    int remotefd = ss_socket(remote_addr->sa_family, SOCK_STREAM, protocol);
    if (remotefd == -1) {
        ERROR("socket");
        return;
    }

    // Set flags
    ss_setsockopt(remotefd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    ss_setsockopt(remotefd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Enable TCP keepalive feature
    int keepAlive    = 1;
    int keepIdle     = 40;
    int keepInterval = 20;
    int keepCount    = 5;
    ss_setsockopt(remotefd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(keepAlive));
    ss_setsockopt(remotefd, SOL_TCP, TCP_KEEPIDLE, (void *)&keepIdle, sizeof(keepIdle));
    ss_setsockopt(remotefd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
    ss_setsockopt(remotefd, SOL_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

    // Set non blocking
    setnonblocking(remotefd);

    if (listener->tos >= 0) {
        int rc = ss_setsockopt(remotefd, IPPROTO_IP, IP_TOS, &listener->tos, sizeof(listener->tos));
        if (rc < 0 && ss_socket_error() != ENOPROTOOPT) {
            LOGE("setting ipv4 dscp failed: %d", ss_socket_error());
        }
#ifdef IPV6_TCLASS
        rc = ss_setsockopt(remotefd, IPPROTO_IPV6, IPV6_TCLASS, &listener->tos, sizeof(listener->tos));
        if (rc < 0 && ss_socket_error() != ENOPROTOOPT) {
            LOGE("setting ipv6 dscp failed: %d", ss_socket_error());
        }
#endif
    }

    // Enable out-of-tree MPTCP
    if (listener->mptcp > 1) {
        int err = ss_setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
        if (err == -1) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    } else if (listener->mptcp == 1) {
        int i = 0;
        while ((listener->mptcp = mptcp_enabled_values[i]) > 0) {
            int err = ss_setsockopt(remotefd, SOL_TCP, listener->mptcp, &opt, sizeof(opt));
            if (err != -1) {
                break;
            }
            i++;
        }
        if (listener->mptcp == 0) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    }

    if (tcp_outgoing_sndbuf > 0) {
        ss_setsockopt(remotefd, SOL_SOCKET, SO_SNDBUF, &tcp_outgoing_sndbuf, sizeof(int));
    }

    if (tcp_outgoing_rcvbuf > 0) {
        ss_setsockopt(remotefd, SOL_SOCKET, SO_RCVBUF, &tcp_outgoing_rcvbuf, sizeof(int));
    }

    server_t *server = new_server(serverfd);
    remote_t *remote = new_remote(remotefd, listener->timeout);
    server->remote   = remote;
    remote->server   = server;
    server->destaddr = destaddr;

    if (fast_open) {
        // save remote addr for fast open
        remote->addr = remote_addr;
        ss_timer_start(SS_A_ & server->delayed_connect_watcher);
    } else {
        int r = connect(remotefd, remote_addr, get_sockaddr_len(remote_addr));

        if (r == -1 && ss_socket_error() != CONNECT_IN_PROGRESS) {
            ERROR("connect");
            close_and_free_remote(SS_A_ remote);
            close_and_free_server(SS_A_ server);
            return;
        }
        // listen to remote connected event
        ss_io_start(SS_A_ & remote->send_ctx->io);
        ss_timer_start(SS_A_ & remote->send_ctx->watcher);
    }
    ss_io_start(SS_A_ & server->recv_ctx->io);
}

static void
signal_cb(SS_P_ ss_signal *w, int revents)
{
    if (revents & SS_SIGNAL) {
        switch (w->signum) {
        case SIGCHLD:
            if (!is_plugin_running()) {
                LOGE("plugin service exit unexpectedly");
                ret_val = -1;
            } else
                return;
        case SIGINT:
        case SIGTERM:
            ss_signal_stop(SS_DEFAULT, &sigint_watcher);
            ss_signal_stop(SS_DEFAULT, &sigterm_watcher);
            ss_signal_stop(SS_DEFAULT, &sigchld_watcher);

            ss_unloop(SS_A_ SS_UNLOOP_ALL);
        }
    }
}

int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags    = 0;
    int mptcp        = 0;
    int mtu          = 0;
    int timeout_secs = 0;
    char *user       = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password   = NULL;
    char *key        = NULL;
    char *timeout    = NULL;
    char *method     = NULL;
    char *pid_path   = NULL;
    char *conf_path  = NULL;

    char *plugin      = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    char tmp_port[8];

    int dscp_num    = 0;
    ss_dscp_t *dscp = NULL;

    int remote_num    = 0;
    char *remote_port = NULL;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];

    memset(remote_addr, 0, sizeof(ss_addr_t) * MAX_REMOTE_NUM);

    static struct option long_options[] = {
        { "fast-open",   no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "mtu",         required_argument, NULL, GETOPT_VAL_MTU         },
        { "mptcp",       no_argument,       NULL, GETOPT_VAL_MPTCP       },
        { "plugin",      required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts", required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "reuse-port",  no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "tcp-incoming-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_SNDBUF },
        { "tcp-incoming-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_RCVBUF },
        { "tcp-outgoing-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_SNDBUF },
        { "tcp-outgoing-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_RCVBUF },
        { "no-delay",    no_argument,       NULL, GETOPT_VAL_NODELAY     },
        { "password",    required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "key",         required_argument, NULL, GETOPT_VAL_KEY         },
        { "help",        no_argument,       NULL, GETOPT_VAL_HELP        },
        { NULL,          0,                 NULL, 0                      }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:p:l:k:t:m:c:b:a:n:huUTv6A",
                            long_options, NULL)) != -1) {
        switch (c) {
        case GETOPT_VAL_FAST_OPEN:
            fast_open = 1;
            break;
        case GETOPT_VAL_MTU:
            if (ss_parse_int(optarg, 0, INT_MAX, &mtu) == -1) {
                FATAL("invalid MTU");
            }
            LOGI("set MTU to %d", mtu);
            break;
        case GETOPT_VAL_MPTCP:
            mptcp = get_mptcp(1);
            if (mptcp)
                LOGI("enable multipath TCP (%s)", mptcp > 0 ? "out-of-tree" : "upstream");
            break;
        case GETOPT_VAL_NODELAY:
            no_delay = 1;
            LOGI("enable TCP no-delay");
            break;
        case GETOPT_VAL_PLUGIN:
            plugin = optarg;
            break;
        case GETOPT_VAL_PLUGIN_OPTS:
            plugin_opts = optarg;
            break;
        case GETOPT_VAL_KEY:
            key = optarg;
            break;
        case GETOPT_VAL_REUSE_PORT:
            reuse_port = 1;
            break;
        case GETOPT_VAL_TCP_INCOMING_SNDBUF:
            if (ss_parse_int(optarg, 0, INT_MAX, &tcp_incoming_sndbuf) == -1) {
                FATAL("invalid TCP incoming send buffer size");
            }
            break;
        case GETOPT_VAL_TCP_INCOMING_RCVBUF:
            if (ss_parse_int(optarg, 0, INT_MAX, &tcp_incoming_rcvbuf) == -1) {
                FATAL("invalid TCP incoming receive buffer size");
            }
            break;
        case GETOPT_VAL_TCP_OUTGOING_SNDBUF:
            if (ss_parse_int(optarg, 0, INT_MAX, &tcp_outgoing_sndbuf) == -1) {
                FATAL("invalid TCP outgoing send buffer size");
            }
            break;
        case GETOPT_VAL_TCP_OUTGOING_RCVBUF:
            if (ss_parse_int(optarg, 0, INT_MAX, &tcp_outgoing_rcvbuf) == -1) {
                FATAL("invalid TCP outgoing receive buffer size");
            }
            break;
        case 's':
            if (remote_num < MAX_REMOTE_NUM) {
                parse_addr(optarg, &remote_addr[remote_num++]);
            }
            break;
        case 'p':
            remote_port = optarg;
            break;
        case 'l':
            local_port = optarg;
            break;
        case GETOPT_VAL_PASSWORD:
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path  = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'b':
            local_addr = optarg;
            break;
        case 'a':
            user = optarg;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n':
            if (ss_parse_int(optarg, 0, INT_MAX, &nofile) == -1) {
                FATAL("invalid nofile");
            }
            break;
#endif
        case 'u':
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode = UDP_ONLY;
            break;
        case 'T':
            tcp_tproxy = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case GETOPT_VAL_HELP:
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case '6':
            ipv6first = 1;
            break;
        case 'A':
            FATAL("One time auth has been deprecated. Try AEAD ciphers instead.");
            break;
        case '?':
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }
    }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = get_default_conf();
        }
    }

    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (remote_num == 0) {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++)
                remote_addr[i] = conf->remote_addr[i];
        }
        if (remote_port == NULL) {
            remote_port = conf->remote_port;
        }
        if (local_addr == NULL) {
            local_addr = conf->local_addr;
        }
        if (local_port == NULL) {
            local_port = conf->local_port;
        }
        if (password == NULL) {
            password = conf->password;
        }
        if (key == NULL) {
            key = conf->key;
        }
        if (method == NULL) {
            method = conf->method;
        }
        if (timeout == NULL) {
            timeout = conf->timeout;
        }
        if (user == NULL) {
            user = conf->user;
        }
        if (plugin == NULL) {
            plugin = conf->plugin;
        }
        if (plugin_opts == NULL) {
            plugin_opts = conf->plugin_opts;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
        if (tcp_tproxy == 0) {
            tcp_tproxy = conf->tcp_tproxy;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (mptcp == 0) {
            mptcp = conf->mptcp;
        }
        if (no_delay == 0) {
            no_delay = conf->no_delay;
        }
        if (reuse_port == 0) {
            reuse_port = conf->reuse_port;
        }
        if (tcp_incoming_sndbuf == 0) {
            tcp_incoming_sndbuf = conf->tcp_incoming_sndbuf;
        }
        if (tcp_incoming_rcvbuf == 0) {
            tcp_incoming_rcvbuf = conf->tcp_incoming_rcvbuf;
        }
        if (tcp_outgoing_sndbuf == 0) {
            tcp_outgoing_sndbuf = conf->tcp_outgoing_sndbuf;
        }
        if (tcp_outgoing_rcvbuf == 0) {
            tcp_outgoing_rcvbuf = conf->tcp_outgoing_rcvbuf;
        }
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        if (ipv6first == 0) {
            ipv6first = conf->ipv6_first;
        }
        dscp_num = conf->dscp_num;
        dscp     = conf->dscp;
    }

    if (remote_num == 0 || remote_port == NULL || local_port == NULL
        || (password == NULL && key == NULL)) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (plugin != NULL) {
        uint16_t port = get_local_port();
        if (port == 0) {
            FATAL("failed to find a free port");
        }
        snprintf(tmp_port, 8, "%d", port);
        if (is_ipv6only(remote_addr, remote_num, ipv6first)) {
            plugin_host = "::1";
        } else {
            plugin_host = "127.0.0.1";
        }
        plugin_port = tmp_port;

        LOGI("plugin \"%s\" enabled", plugin);
    }

    if (method == NULL) {
        method = "chacha20-ietf-poly1305";
    }

    if (timeout == NULL) {
        timeout = "600";
    }
    if (ss_parse_int(timeout, 1, INT_MAX, &timeout_secs) == -1) {
        FATAL("invalid timeout");
    }

#ifdef HAVE_SETRLIMIT
    /*
     * no need to check the return value here since we will show
     * the user an error message if setrlimit(2) fails
     */
    if (nofile > 1024) {
        if (verbose) {
            LOGI("setting NOFILE to %d", nofile);
        }
        set_nofile(nofile);
    }
#endif

    if (local_addr == NULL) {
        if (is_ipv6only(remote_addr, remote_num, ipv6first)) {
            local_addr = "::1";
        } else {
            local_addr = "127.0.0.1";
        }
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(pid_path);
    }

    if (no_delay) {
        LOGI("enable TCP no-delay");
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    if (tcp_incoming_sndbuf != 0 && tcp_incoming_sndbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_sndbuf = 0;
    }

    if (tcp_incoming_sndbuf != 0) {
        LOGI("set TCP incoming connection send buffer size to %d", tcp_incoming_sndbuf);
    }

    if (tcp_incoming_rcvbuf != 0 && tcp_incoming_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_incoming_rcvbuf = 0;
    }

    if (tcp_incoming_rcvbuf != 0) {
        LOGI("set TCP incoming connection receive buffer size to %d", tcp_incoming_rcvbuf);
    }

    if (tcp_outgoing_sndbuf != 0 && tcp_outgoing_sndbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_sndbuf = 0;
    }

    if (tcp_outgoing_sndbuf != 0) {
        LOGI("set TCP outgoing connection send buffer size to %d", tcp_outgoing_sndbuf);
    }

    if (tcp_outgoing_rcvbuf != 0 && tcp_outgoing_rcvbuf < SOCKET_BUF_SIZE) {
        tcp_outgoing_rcvbuf = 0;
    }

    if (tcp_outgoing_rcvbuf != 0) {
        LOGI("set TCP outgoing connection receive buffer size to %d", tcp_outgoing_rcvbuf);
    }

    if (plugin != NULL) {
        int len          = 0;
        size_t buf_size  = 256 * remote_num;
        char *remote_str = ss_malloc(buf_size);

        snprintf(remote_str, buf_size, "%s", remote_addr[0].host);
        len = strlen(remote_str);
        for (int i = 1; i < remote_num; i++) {
            snprintf(remote_str + len, buf_size - len, "|%s", remote_addr[i].host);
            len = strlen(remote_str);
        }
        int err = start_plugin(plugin, plugin_opts, remote_str,
                               remote_port, plugin_host, plugin_port, MODE_CLIENT);
        if (err) {
            FATAL("failed to start the plugin");
        }
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    ss_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ss_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ss_signal_init(&sigchld_watcher, signal_cb, SIGCHLD);
    ss_signal_start(SS_DEFAULT, &sigint_watcher);
    ss_signal_start(SS_DEFAULT, &sigterm_watcher);
    ss_signal_start(SS_DEFAULT, &sigchld_watcher);

    // Setup keys
    LOGI("initializing ciphers... %s", method);
    crypto = crypto_init(password, key, method);
    if (crypto == NULL)
        FATAL("failed to initialize ciphers");

    // Setup proxy context
    struct listen_ctx listen_ctx;
    memset(&listen_ctx, 0, sizeof(struct listen_ctx));
    listen_ctx.remote_num  = remote_num;
    listen_ctx.remote_addr = ss_malloc(sizeof(struct sockaddr *) * remote_num);
    memset(listen_ctx.remote_addr, 0, sizeof(struct sockaddr *) * remote_num);
    for (i = 0; i < remote_num; i++) {
        char *host = remote_addr[i].host;
        char *port = remote_addr[i].port == NULL ? remote_port :
                     remote_addr[i].port;
        if (plugin != NULL) {
            host = plugin_host;
            port = plugin_port;
        }
        struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
        memset(storage, 0, sizeof(struct sockaddr_storage));
        if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        listen_ctx.remote_addr[i] = (struct sockaddr *)storage;

        if (plugin != NULL)
            break;
    }
    listen_ctx.timeout = timeout_secs;
    listen_ctx.mptcp   = mptcp;

    struct ss_loop *loop = SS_DEFAULT;

    listen_ctx_t *listen_ctx_current = &listen_ctx;
    do {
        if (listen_ctx_current->tos) {
            LOGI("listening at %s:%s (TOS 0x%x)", local_addr, local_port, listen_ctx_current->tos);
        } else {
            LOGI("listening at %s:%s", local_addr, local_port);
        }

        if (mode != UDP_ONLY) {
            // Setup socket
            int listenfd;
            listenfd = create_and_bind(local_addr, local_port);
            if (listenfd == -1) {
                FATAL("bind() error");
            }
            if (listen(listenfd, SOMAXCONN) == -1) {
                FATAL("listen() error");
            }
            setnonblocking(listenfd);

            listen_ctx_current->fd = listenfd;

            ss_io_init(&listen_ctx_current->io, accept_cb, listenfd, SS_READ);
            ss_io_start(loop, &listen_ctx_current->io);
        }

        // Setup UDP
        if (mode != TCP_ONLY) {
            LOGI("UDP relay enabled");
            char *host                       = remote_addr[0].host;
            char *port                       = remote_addr[0].port == NULL ? remote_port : remote_addr[0].port;
            struct sockaddr_storage *storage = ss_malloc(sizeof(struct sockaddr_storage));
            memset(storage, 0, sizeof(struct sockaddr_storage));
            if (get_sockaddr(host, port, storage, 1, ipv6first) == -1) {
                FATAL("failed to resolve the provided hostname");
            }
            struct sockaddr *addr = (struct sockaddr *)storage;
            if (init_udprelay(local_addr, local_port, addr,
                              get_sockaddr_len(addr), mtu, crypto,
                              listen_ctx_current->timeout, NULL) == -1) {
                FATAL("failed to initialize UDP relay");
            }
        }

        if (mode == UDP_ONLY) {
            LOGI("TCP relay disabled");
        }

        // Handle additionals TOS/DSCP listening ports
        if (dscp_num > 0) {
            listen_ctx_current      = (listen_ctx_t *)ss_malloc(sizeof(listen_ctx_t));
            listen_ctx_current      = memcpy(listen_ctx_current, &listen_ctx, sizeof(listen_ctx_t));
            local_port              = dscp[dscp_num - 1].port;
            listen_ctx_current->tos = dscp[dscp_num - 1].dscp << 2;
        }
    } while (dscp_num-- > 0);

    // setuid
    if (user != NULL && !run_as(user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("running from root user");
    }

    ss_run(loop, 0);

    if (plugin != NULL) {
        stop_plugin();
    }

    for (i = 0; i < remote_num; i++)
        ss_free(listen_ctx.remote_addr[i]);
    ss_free(listen_ctx.remote_addr);

    return ret_val;
}
