/*
 * server.cpp - Provide shadowsocks service
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>
#ifndef __MINGW32__
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/un.h>
#endif
#include "core.h"
#include <inttypes.h>

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#ifdef USE_NFTABLES
#include <ctype.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <libnftnl/set.h>
/* the datatypes enum is picked from libnftables/datatype.h
   to avoid to depend libnftables */
enum datatypes {
    TYPE_IPADDR = 7,
    TYPE_IP6ADDR
};
#endif

#include "netutils.h"
#include "utils.h"
#include "acl.h"
#include "plugin.h"
#include "jconf.h"
#include "common.h"
#include "ss_windows.h"

#ifdef USE_NFCONNTRACK_TOS
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>
#endif

#include "core/heap_guard.hpp"
#include "event/program.hpp"
#include "relay/tcp.hpp"
#include "relay/udp.hpp"

#undef min
#undef max

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef SSMAXCONN
#define SSMAXCONN 1024
#endif

#ifdef USE_NFCONNTRACK_TOS

#ifndef MARK_MAX_PACKET
#define MARK_MAX_PACKET 10
#endif

#ifndef MARK_MASK_PREFIX
#define MARK_MASK_PREFIX 0xDC00
#endif

#endif


int verbose    = 0;
int reuse_port = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

int is_bind_local_addr = 0;
struct sockaddr_storage local_addr_v4;
struct sockaddr_storage local_addr_v6;


static int acl       = 0;
static int mode      = TCP_ONLY;
static int ipv6first = 0;
int fast_open        = 0;
static int no_delay  = 0;
static int max_connections  = 0;
static int max_udp_sessions = 0;
static int max_dns_queries  = 0;
static int ret_val   = 0;

#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif

static char *plugin       = NULL;
static char *remote_port  = NULL;
static char *manager_addr = NULL;
uint64_t tx               = 0;
uint64_t rx               = 0;

#ifndef __MINGW32__
#endif

#ifndef __MINGW32__
#else
static struct plugin_watcher_t {
    SOCKET fd;
    uint16_t port;
    int valid;
} plugin_watcher;
#endif

#ifndef __MINGW32__
static int setnonblocking(int fd);
// Resolves the manager's address when it is given by name.
static ss::relay::Resolver *stat_resolver = NULL;

static void stat_resolved(const ss::relay::ResolveCallback &cb, const sockaddr *address) noexcept
{
    char *message = (char *)cb.ctx;
    if (address) {
        int fd = ss_socket(address->sa_family, SOCK_DGRAM, 0);
        if (fd != -1) {
            setnonblocking(fd);
            size_t length = strlen(message) + 1;
            if (sendto(fd, message, length, 0, address, get_sockaddr_len((struct sockaddr *)address)) != (ssize_t)length)
                ERROR("stat_sendto");
            ss_socket_close(fd);
        }
    }
    free(message); // heap-ok: one stats datagram every few seconds
}

static void
stat_update_cb(void *) noexcept
{
    struct sockaddr_un svaddr, claddr;
    int sfd = -1;
    size_t msgLen;
    char resp[SOCKET_BUF_SIZE];

    if (verbose) {
        LOGI("update traffic stat: tx: %" PRIu64 " rx: %" PRIu64 "", tx, rx);
    }

    snprintf(resp, SOCKET_BUF_SIZE, "stat: {\"%s\":%" PRIu64 "}", remote_port, tx + rx);
    msgLen = strlen(resp) + 1;

    ss_addr_t ip_addr = { .host = NULL, .port = NULL };
    parse_addr(manager_addr, &ip_addr);

    if (ip_addr.host == NULL || ip_addr.port == NULL) {
        ss_free(ip_addr.host);
        ss_free(ip_addr.port);
        sfd = ss_socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sfd == -1) {
            ERROR("stat_socket");
            return;
        }

        memset(&claddr, 0, sizeof(struct sockaddr_un));
        claddr.sun_family = AF_UNIX;
        snprintf(claddr.sun_path, sizeof(claddr.sun_path), "/tmp/shadowsocks.%s", remote_port);

        unlink(claddr.sun_path);

        if (bind(sfd, (struct sockaddr *)&claddr, sizeof(struct sockaddr_un)) == -1) {
            ERROR("stat_bind");
            ss_socket_close(sfd);
            return;
        }

        memset(&svaddr, 0, sizeof(struct sockaddr_un));
        svaddr.sun_family = AF_UNIX;
        if (strlen(manager_addr) >= sizeof(svaddr.sun_path)) {
            LOGE("manager unix socket path is too long");
            ss_socket_close(sfd);
            unlink(claddr.sun_path);
            return;
        }
        strncpy(svaddr.sun_path, manager_addr, sizeof(svaddr.sun_path) - 1);

        if (sendto(sfd, resp, strlen(resp) + 1, 0, (struct sockaddr *)&svaddr,
                   sizeof(struct sockaddr_un)) != (ssize_t)msgLen) {
            ERROR("stat_sendto");
            ss_socket_close(sfd);
            return;
        }

        unlink(claddr.sun_path);
    } else {
        uint16_t port;
        if (parse_numeric_port(ip_addr.port, &port) == 0) {
            char *message = strdup(resp); // heap-ok: one stats datagram every few seconds
            if (!message) FATAL("out of memory");
            ss::relay::ResolveCallback cb;
            cb.fn  = &stat_resolved;
            cb.ctx = message;
            if (stat_resolver == NULL || !stat_resolver->resolve(ip_addr.host, htons(port), cb))
                free(message); // heap-ok: see above
        }
        ss_free(ip_addr.host);
        ss_free(ip_addr.port);
        return;
    }

    ss_socket_close(sfd);
}

#endif

static char *
get_peer_name(int fd)
{
    static char peer_name[INET6_ADDRSTRLEN] = { 0 };
    struct sockaddr_storage addr;
    socklen_t len = sizeof(struct sockaddr_storage);
    memset(&addr, 0, len);
    memset(peer_name, 0, INET6_ADDRSTRLEN);
    int err = getpeername(fd, (struct sockaddr *)&addr, &len);
    if (err == 0) {
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&addr;
            ss_inet_ntop(AF_INET, &s->sin_addr, peer_name, INET_ADDRSTRLEN);
        } else if (addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
            ss_inet_ntop(AF_INET6, &s->sin6_addr, peer_name, INET6_ADDRSTRLEN);
        }
    } else {
        return NULL;
    }
    return peer_name;
}

#ifdef USE_NFTABLES
struct nftbl_set_info {
    uint32_t family;
    char *table;
    char *name;
    uint32_t type;
}* nftbl_badip_sets[16];

static struct nftnl_set *
nftbl_build_set(const char* table, const char* name, void* addr, size_t len)
{
    struct nftnl_set *set = nftnl_set_alloc();
    if (set == NULL) return NULL;
    nftnl_set_set_str(set, NFTNL_SET_TABLE, table);
    nftnl_set_set_str(set, NFTNL_SET_NAME, name);

    struct nftnl_set_elem *elem = nftnl_set_elem_alloc();
    if (elem == NULL) {
        nftnl_set_free(set);
        return NULL;
    }
    nftnl_set_elem_set(elem, NFTNL_SET_ELEM_KEY, addr, len);
    nftnl_set_elem_add(set, elem);
    return set;
}

static uint32_t
nftbl_build_nlmsg(void* buf, size_t *len, uint32_t family,
                  struct nftnl_set *set)
{
    uint32_t seq = time(NULL);
    struct nlmsghdr *nlh;
    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, *len);
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq);
    mnl_nlmsg_batch_next(batch);
    nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                NFT_MSG_NEWSETELEM, family,
                                NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                                ++seq);
    nftnl_set_elems_nlmsg_build_payload(nlh, set);
    mnl_nlmsg_batch_next(batch);
    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq + 1);
    mnl_nlmsg_batch_next(batch);
    *len = mnl_nlmsg_batch_size(batch);
    mnl_nlmsg_batch_stop(batch);
    return seq;
}

static int
nftbl_send_request(void *request, size_t len, uint32_t seq,
                   mnl_cb_t cb, void *data)
{
    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) return -1;

    int ret = -1;
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) == 0 &&
        mnl_socket_sendto(nl, request, len) >= 0) {
        uint32_t portid = mnl_socket_get_portid(nl);
        while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
            ret = mnl_cb_run(buf, ret, seq, portid, cb, data);
            if (ret != MNL_CB_OK)
                break;
        }
        mnl_socket_close(nl);
    }
    return ret;
}

static void
nftbl_report_addr(const struct sockaddr* addr)
{
    uint32_t type;
    void* data;
    size_t size;
    if (addr->sa_family == AF_INET) {
        type = TYPE_IPADDR;
        data = &((struct sockaddr_in*)addr)->sin_addr;
        size = sizeof(struct in_addr);
    } else if (addr->sa_family == AF_INET6) {
        type = TYPE_IP6ADDR;
        data = &((struct sockaddr_in6*)addr)->sin6_addr;
        size = sizeof(struct in6_addr);
    } else {
        return;
    }

    char buf[MNL_SOCKET_BUFFER_SIZE];
    for (int i = 0; nftbl_badip_sets[i]; ++i) {
        struct nftbl_set_info* si = nftbl_badip_sets[i];
        struct nftnl_set *set;
        if (si->type == type &&
            (set = nftbl_build_set(si->table, si->name, data, size))) {
            size_t len = sizeof(buf);
            uint32_t seq = nftbl_build_nlmsg(buf, &len, si->family, set);
            nftnl_set_free(set);
            if (nftbl_send_request(buf, len, seq, NULL, NULL) < 0 &&
                errno != EEXIST)
                ERROR("nftbl_report_addr");
        }
    }
}

static int
nftbl_check_cb(const struct nlmsghdr *nlh, void *data)
{
    struct nftnl_set *set = (struct nftnl_set*)data;
    if (nftnl_set_nlmsg_parse(nlh, set) < 0)
        return MNL_CB_ERROR;

    uint32_t type = nftnl_set_get_u32(set, NFTNL_SET_KEY_TYPE);
    if (type != TYPE_IPADDR && type != TYPE_IP6ADDR)
        return MNL_CB_OK;

    uint32_t len;
    const char *name = nftnl_set_get_data(set, NFTNL_SET_NAME, &len);
    for (int i = 0; nftbl_badip_sets[i]; ++i) {
        struct nftbl_set_info* si = nftbl_badip_sets[i];
        if (!memcmp(name, si->name, len)) {
            name = nftnl_set_get_data(set, NFTNL_SET_TABLE, &len);
            if (!si->table) {
                size_t l = strlen(si->name) + 1;
                si = realloc(si, sizeof(*si) + l + len);
                si->name = (char*)(si + 1);
                si->table = memcpy(si->name + l, name, len);
                nftbl_badip_sets[i] = si;
            } else if (memcmp(name, si->table, len)) {
                continue;  /* table name not match */
            }
            si->family = nftnl_set_get_u32(set, NFTNL_SET_FAMILY);
            si->type = type;
        }
    }
    return MNL_CB_OK;
}

static int
nftbl_check(void)
{
    struct nftnl_set *set = nftnl_set_alloc();
    if (!set) return -1;

    int ret;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    uint32_t seq = time(NULL);
    struct nlmsghdr *nlh;
    nlh = nftnl_set_nlmsg_build_hdr(buf, NFT_MSG_GETSET, NFPROTO_UNSPEC,
                                    NLM_F_DUMP|NLM_F_ACK, seq);
    nftnl_set_nlmsg_build_payload(nlh, set);
    ret = nftbl_send_request(nlh, nlh->nlmsg_len, seq, nftbl_check_cb, set);
    nftnl_set_free(set);
    if (ret < 0) return ret;

    for (int i = 0; nftbl_badip_sets[i]; ++i) {
        struct nftbl_set_info* si = nftbl_badip_sets[i];
        if (si->family == NFPROTO_UNSPEC) {
            if (si->table)
                LOGE("set '%s' not found in table '%s'", si->name, si->table);
            else
                LOGE("set '%s' not found", si->name);
            ret = -1;
        }
    }
    if (ret < 0)
        FATAL("Check nftables configuration.");
    return ret;
}

static int
nftbl_init(const char* set_str)
{
    struct nftbl_set_info* si;
    const char *p0 = set_str, *p = p0, *d = NULL;
    int i = 0;
    do {
        if (*p == ':') {
            d = p;
        } else if (*p == ',' || *p == '\0') {
            size_t l = p - p0 + 1;
            si = malloc(sizeof(*si) + l);
            memset(si, 0, sizeof(*si));
            si->name = memcpy(si + 1, p0, l);
            si->name[l - 1] = '\0';
            if (d) {
                si->table = si->name;
                si->name = si->table + (d - p0);
                *(si->name++) = '\0';
                d = NULL;
            }
            nftbl_badip_sets[i++] = si;
            if (i == sizeof(nftbl_badip_sets) / sizeof(*si) - 1)
                break;
            while (*p && isspace(*(++p)));
            p0 = p;
        }
    } while (*(p++));
    return nftbl_check();
}
#endif

static void
report_addr(int fd, const char *info)
{
    char *peer_name;
    peer_name = get_peer_name(fd);
    if (peer_name != NULL) {
        LOGE("failed to handshake with %s: %s", peer_name, info);
    }

#ifdef USE_NFTABLES
    struct sockaddr_in6 addr;
    socklen_t len = sizeof(struct sockaddr_in6);
    if (!getpeername(fd, (struct sockaddr *)&addr, &len))
        nftbl_report_addr((struct sockaddr *)&addr);
#endif
}

int
setfastopen(int fd)
{
    int s = 0;
#ifdef TCP_FASTOPEN
    if (fast_open) {
#if defined(__APPLE__) || defined(__MINGW32__)
        int opt = 1;
#else
        int opt = 5;
#endif
        s = ss_setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &opt, sizeof(opt));

        if (s == -1) {
            if (ss_socket_error() == EPROTONOSUPPORT || ss_socket_error() == ENOPROTOOPT) {
                LOGE("fast open is not supported on this platform");
                fast_open = 0;
            } else {
                ERROR("setsockopt");
            }
        }
    }
#endif
    return s;
}

#ifndef __MINGW32__
int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#endif

int
create_and_bind(const char *host, const char *port, int mptcp)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp, *ipv4v6bindall;
    int s, listen_sock = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM;             /* We want a TCP socket */
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_TCP;

    result = NULL;

    s = getaddrinfo(host, port, &hints, &result);

    if (s != 0) {
        LOGE("failed to resolve server name %s", host);
        return -1;
    }

    if (result == NULL) {
        LOGE("Cannot bind");
        return -1;
    }

    rp = result;

    /*
     * On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
     * AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
     * return a list of addresses to listen on, but it is impossible to listen on
     * 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
     */
    if (!host) {
        ipv4v6bindall = result;

        /* Loop over all address infos found until a IPV6 address is found. */
        while (ipv4v6bindall) {
            if (ipv4v6bindall->ai_family == AF_INET6) {
                rp = ipv4v6bindall; /* Take first IPV6 address available */
                break;
            }
            ipv4v6bindall = ipv4v6bindall->ai_next; /* Get next address info, if any */
        }
    }

    for (/*rp = result*/; rp != NULL; rp = rp->ai_next) {
        int protocol = rp->ai_protocol;
        if (mptcp < 0) {
            protocol = IPPROTO_MPTCP; // Enable upstream MPTCP
        }
        listen_sock = ss_socket(rp->ai_family, rp->ai_socktype, protocol);
        if (listen_sock == -1) {
            continue;
        }

        if (rp->ai_family == AF_INET6) {
            int opt = host ? 1 : 0;
            ss_setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
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

        if (tcp_incoming_sndbuf > 0) {
            ss_setsockopt(listen_sock, SOL_SOCKET, SO_SNDBUF, &tcp_incoming_sndbuf, sizeof(int));
        }

        if (tcp_incoming_rcvbuf > 0) {
            ss_setsockopt(listen_sock, SOL_SOCKET, SO_RCVBUF, &tcp_incoming_rcvbuf, sizeof(int));
        }

        // Enable out-of-tree mptcp
        if (mptcp == 1) {
            int i = 0;
            while ((mptcp = mptcp_enabled_values[i]) > 0) {
                int err = ss_setsockopt(listen_sock, IPPROTO_TCP, mptcp, &opt, sizeof(opt));
                if (err != -1) {
                    break;
                }
                i++;
            }
            if (mptcp == 0) {
                ERROR("failed to enable out-of-tree multipath TCP");
            }
        }

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
            FATAL("failed to bind address");
        }

        ss_socket_close(listen_sock);
        listen_sock = -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

#ifdef USE_NFCONNTRACK_TOS
// Connmark to TOS: copy the DSCP bits of the upstream connection's
// netfilter mark onto the client socket. The tracker is the relay hook's
// per-connection state.
struct dscptracker {
    struct nf_conntrack *ct;
    long unsigned int mark;
    unsigned int dscp;
    unsigned int packet_count;
    int client_fd;
};

static int
setMarkDscpCallback(enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
    struct dscptracker *tracker = (struct dscptracker *)data;

    tracker->mark = nfct_get_attr_u32(ct, ATTR_MARK);
    if ((tracker->mark & 0xff00) == MARK_MASK_PREFIX) {
        // Extract DSCP value from mark value
        tracker->dscp = tracker->mark & 0x00ff;
        int tos = (tracker->dscp) << 2;
        if (ss_setsockopt(tracker->client_fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) != 0) {
            ERROR("iptable setsockopt IP_TOS");
        }
    }
    return NFCT_CB_CONTINUE;
}

static void
conntrackQuery(struct dscptracker *tracker)
{
    if (tracker && tracker->ct) {
        // Trying query mark from nf conntrack
        struct nfct_handle *h = nfct_open(CONNTRACK, 0);
        if (h) {
            nfct_callback_register(h, NFCT_T_ALL, setMarkDscpCallback, (void *)tracker);
            int x = nfct_query(h, NFCT_Q_GET, tracker->ct);
            if (x == -1) {
                LOGE("QOS: Failed to retrieve connection mark %s", strerror(ss_socket_error()));
            }
            nfct_close(h);
        } else {
            LOGE("QOS: Failed to open conntrack handle for upstream netfilter mark retrieval.");
        }
    }
}

static void
setTosFromConnmark(void **state, ss_socket_t client_fd, ss_socket_t remote_fd)
{
    struct dscptracker *tracker = (struct dscptracker *)*state;
    if (tracker && tracker->ct) {
        if (tracker->mark == 0 && tracker->packet_count < MARK_MAX_PACKET) {
            tracker->packet_count++;
            conntrackQuery(tracker);
        }
        return;
    }
    if (tracker) {
        return; // no conntrack entry could be built for this connection
    }
    socklen_t len;
    struct sockaddr_storage sin;
    len = sizeof(sin);
    if (getpeername(remote_fd, (struct sockaddr *)&sin, &len) != 0) {
        return;
    }
    struct sockaddr_storage from_addr;
    len = sizeof from_addr;
    if (getsockname(remote_fd, (struct sockaddr *)&from_addr, &len) != 0) {
        return;
    }
    tracker = (struct dscptracker *)calloc(1, sizeof(struct dscptracker)); // heap-ok: optional netfilter feature
    if (!tracker) {
        return;
    }
    tracker->client_fd = client_fd;
    *state             = tracker;
    if ((tracker->ct = nfct_new())) {
        // Build conntrack query SELECT
        if (from_addr.ss_family == AF_INET) {
            struct sockaddr_in *src = (struct sockaddr_in *)&from_addr;
            struct sockaddr_in *dst = (struct sockaddr_in *)&sin;

            nfct_set_attr_u8(tracker->ct, ATTR_L3PROTO, AF_INET);
            nfct_set_attr_u32(tracker->ct, ATTR_IPV4_DST, dst->sin_addr.s_addr);
            nfct_set_attr_u32(tracker->ct, ATTR_IPV4_SRC, src->sin_addr.s_addr);
            nfct_set_attr_u16(tracker->ct, ATTR_PORT_DST, dst->sin_port);
            nfct_set_attr_u16(tracker->ct, ATTR_PORT_SRC, src->sin_port);
        } else if (from_addr.ss_family == AF_INET6) {
            struct sockaddr_in6 *src = (struct sockaddr_in6 *)&from_addr;
            struct sockaddr_in6 *dst = (struct sockaddr_in6 *)&sin;

            nfct_set_attr_u8(tracker->ct, ATTR_L3PROTO, AF_INET6);
            nfct_set_attr(tracker->ct, ATTR_IPV6_DST, dst->sin6_addr.s6_addr);
            nfct_set_attr(tracker->ct, ATTR_IPV6_SRC, src->sin6_addr.s6_addr);
            nfct_set_attr_u16(tracker->ct, ATTR_PORT_DST, dst->sin6_port);
            nfct_set_attr_u16(tracker->ct, ATTR_PORT_SRC, src->sin6_port);
        }
        nfct_set_attr_u8(tracker->ct, ATTR_L4PROTO, IPPROTO_TCP);
        conntrackQuery(tracker);
    } else {
        LOGE("Failed to allocate new conntrack for upstream netfilter mark retrieval.");
    }
}

static void
releaseTracker(void *state)
{
    struct dscptracker *tracker = (struct dscptracker *)state;
    if (tracker->ct) {
        nfct_destroy(tracker->ct);
    }
    free(tracker); // heap-ok: optional netfilter feature
}

#endif

static void
report_failure(ss_socket_t fd, const char *reason)
{
    report_addr((int)fd, reason);
}


#ifdef __MINGW32__
static void
plugin_watcher_cb(void *ctx) noexcept
{
    char buf[1];
    SOCKET fd = ss_accept(plugin_watcher.fd, NULL, NULL);
    if (fd == INVALID_SOCKET) {
        return;
    }
    recv(fd, buf, 1, 0);
    closesocket(fd);
    LOGE("plugin service exit unexpectedly");
    static_cast<ss::event::Program *>(ctx)->stop(-1);
}

#endif

static bool
plugin_alive()
{
    return is_plugin_running() != 0;
}

int
main(int argc, char **argv)
{
    // Bounded heaps for libuv, c-ares and Mbed TLS before any of them runs.
    if (!ss::install_library_heaps())
        FATAL("failed to reserve the library heaps");
    ss::event::Program program;
    if (!program.init())
        FATAL("failed to set up the event loop");

    int i, c;
    int pid_flags   = 0;
    int mptcp       = 0;
    int mtu         = 0;
    int timeout_secs = 0;
    char *user      = NULL;
    char *password  = NULL;
    char *key       = NULL;
    char *timeout   = NULL;
    char *method    = NULL;
    char *pid_path  = NULL;
    char *conf_path = NULL;
    char *iface     = NULL;

    char *server_port = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    char tmp_port[8];
    char *nameservers = NULL;

    int server_num = 0;
    ss_addr_t server_addr[MAX_REMOTE_NUM];
    memset(server_addr, 0, sizeof(ss_addr_t) * MAX_REMOTE_NUM);
    memset(&local_addr_v4, 0, sizeof(struct sockaddr_storage));
    memset(&local_addr_v6, 0, sizeof(struct sockaddr_storage));

/* [cli_short_s]
\par `-s <server_host>`
Set a server listening hostname or IP address. May be repeated.
[cli_short_s] */

/* [cli_short_p]
\par `-p <server_port>`
Set the server listening port.
[cli_short_p] */

/* [cli_short_b]
\par `-b <local_address>`
Set the local address for outbound connections to destination servers.
[cli_short_b] */

/* [cli_long_config]
\par `--config <config_file>`
Read JSON configuration. See the CLI conventions for precedence and default-value behavior. Short alias: `-c`.
[cli_long_config] */

/* [cli_long_cipher]
\par `--cipher <encrypt_method>`
Select the encryption cipher. See `-m` for supported cipher names and key requirements. Short alias: `-m`.
[cli_long_cipher] */

/* [cli_long_timeout]
\par `--timeout <timeout>`
Same behavior as `-t`; see that option for details. Short alias: `-t`.
[cli_long_timeout] */

/* [cli_long_user]
\par `--user <user_name>`
Same behavior as `-a`; see that option for details. Short alias: `-a`.
[cli_long_user] */

/* [cli_long_pid_file]
\par `--pid-file <pid_file>`
Same behavior as `-f`; see that option for details. Short alias: `-f`.
[cli_long_pid_file] */

/* [cli_long_nofile]
\par `--nofile <number>`
Same behavior as `-n`; see that option for details. Short alias: `-n`.
[cli_long_nofile] */

/* [cli_long_udp]
\par `--udp`
Enable both TCP and UDP relay, overriding the configured mode. Short alias: `-u`.
[cli_long_udp] */

/* [cli_long_udp_only]
\par `--udp-only`
Enable UDP relay only, overriding the configured mode. Short alias: `-U`.
[cli_long_udp_only] */

/* [cli_long_ipv6_first]
\par `--ipv6-first`
Prefer IPv6 DNS results; overrides configuration. This does not restrict connections to IPv6. Short alias: `-6`.
[cli_long_ipv6_first] */

/* [cli_long_verbose]
\par `--verbose`
Same behavior as `-v`; see that option for details. Short alias: `-v`.
[cli_long_verbose] */

/* [cli_long_listen_address]
\par `--listen-address <server_host>`
Set the listening address. Server and manager addresses may be repeated. Short alias: `-s`.
[cli_long_listen_address] */

/* [cli_long_listen_port]
\par `--listen-port <server_port>`
Set the listening port. Short alias: `-p`.
[cli_long_listen_port] */

/* [cli_long_outbound_address]
\par `--outbound-address <local_address>`
Set the source address for connections to destination servers. Short alias: `-b`.
[cli_long_outbound_address] */

/* [cli_long_interface]
\par `--interface <interface>`
Same behavior as `-i`; see that option for details. Short alias: `-i`.
[cli_long_interface] */

/* [cli_long_nameserver]
\par `--nameserver <addr>`
Same behavior as `-d`; see that option for details. Short alias: `-d`.
[cli_long_nameserver] */

/* [cli-options]
\snippet{doc} utils.cpp cli_short_f
\snippet{doc} server.cpp cli_short_s
\snippet{doc} server.cpp cli_short_p
\snippet{doc} utils.cpp cli_short_k
\snippet{doc} utils.cpp cli_short_t
\snippet{doc} utils.cpp cli_short_m
\snippet{doc} server.cpp cli_short_b
\snippet{doc} utils.cpp cli_short_c
\snippet{doc} utils.cpp cli_short_i
\snippet{doc} utils.cpp cli_short_d
\snippet{doc} utils.cpp cli_short_a
\snippet{doc} utils.cpp cli_short_n
\snippet{doc} utils.cpp cli_short_h
\snippet{doc} utils.cpp cli_short_u
\snippet{doc} utils.cpp cli_short_U
\snippet{doc} utils.cpp cli_short_v
\snippet{doc} utils.cpp cli_short_6
\snippet{doc} utils.cpp cli_short_A
\snippet{doc} server.cpp cli_long_config
\snippet{doc} server.cpp cli_long_cipher
\snippet{doc} server.cpp cli_long_timeout
\snippet{doc} server.cpp cli_long_user
\snippet{doc} server.cpp cli_long_pid_file
\snippet{doc} server.cpp cli_long_nofile
\snippet{doc} server.cpp cli_long_udp
\snippet{doc} server.cpp cli_long_udp_only
\snippet{doc} server.cpp cli_long_ipv6_first
\snippet{doc} server.cpp cli_long_verbose
\snippet{doc} server.cpp cli_long_listen_address
\snippet{doc} server.cpp cli_long_listen_port
\snippet{doc} server.cpp cli_long_outbound_address
\snippet{doc} server.cpp cli_long_interface
\snippet{doc} server.cpp cli_long_nameserver
\snippet{doc} utils.cpp cli_long_version
\snippet{doc} utils.cpp cli_long_tcp_only
\snippet{doc} utils.cpp cli_long_ipv4_first
\snippet{doc} utils.cpp cli_long_fast_open
\snippet{doc} utils.cpp cli_long_reuse_port
\snippet{doc} utils.cpp cli_long_tcp_incoming_sndbuf
\snippet{doc} utils.cpp cli_long_tcp_incoming_rcvbuf
\snippet{doc} utils.cpp cli_long_tcp_outgoing_sndbuf
\snippet{doc} utils.cpp cli_long_tcp_outgoing_rcvbuf
\snippet{doc} utils.cpp cli_long_no_delay
\snippet{doc} utils.cpp cli_long_max_connections
\snippet{doc} utils.cpp cli_long_max_udp_sessions
\snippet{doc} utils.cpp cli_long_max_dns_queries
\snippet{doc} utils.cpp cli_long_acl
\snippet{doc} utils.cpp cli_long_manager_address
\snippet{doc} utils.cpp cli_long_mtu
\snippet{doc} utils.cpp cli_long_help
\snippet{doc} utils.cpp cli_long_plugin
\snippet{doc} utils.cpp cli_long_plugin_opts
\snippet{doc} utils.cpp cli_long_password
\snippet{doc} utils.cpp cli_long_key
\snippet{doc} utils.cpp cli_long_mptcp
\snippet{doc} utils.cpp cli_long_nftables_sets
[cli-options] */
    static struct option long_options[] = {
        { "config", required_argument, NULL, 'c' },
        { "cipher", required_argument, NULL, 'm' },
        { "timeout", required_argument, NULL, 't' },
        { "user", required_argument, NULL, 'a' },
        { "pid-file", required_argument, NULL, 'f' },
        { "nofile", required_argument, NULL, 'n' },
        { "udp", no_argument, NULL, 'u' },
        { "udp-only", no_argument, NULL, 'U' },
        { "ipv6-first", no_argument, NULL, '6' },
        { "verbose", no_argument, NULL, 'v' },
        { "listen-address", required_argument, NULL, 's' },
        { "listen-port", required_argument, NULL, 'p' },
        { "outbound-address", required_argument, NULL, 'b' },
        { "interface", required_argument, NULL, 'i' },
        { "nameserver", required_argument, NULL, 'd' },
        { "version", no_argument, NULL, GETOPT_VAL_VERSION },
        { "tcp-only", no_argument, NULL, GETOPT_VAL_TCP_ONLY },
        { "ipv4-first", no_argument, NULL, GETOPT_VAL_IPV4_FIRST },
        { "fast-open",       no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "reuse-port",      no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "tcp-incoming-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_SNDBUF },
        { "tcp-incoming-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_RCVBUF },
        { "tcp-outgoing-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_SNDBUF },
        { "tcp-outgoing-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_RCVBUF },
        { "no-delay",        no_argument,       NULL, GETOPT_VAL_NODELAY     },
        { "max-connections", required_argument, NULL, GETOPT_VAL_MAX_CONNECTIONS },
        { "max-udp-sessions", required_argument, NULL, GETOPT_VAL_MAX_UDP_SESSIONS },
        { "max-dns-queries", required_argument, NULL, GETOPT_VAL_MAX_DNS_QUERIES },
        { "acl",             required_argument, NULL, GETOPT_VAL_ACL         },
        { "manager-address", required_argument, NULL,
          GETOPT_VAL_MANAGER_ADDRESS },
        { "mtu",             required_argument, NULL, GETOPT_VAL_MTU         },
        { "help",            no_argument,       NULL, GETOPT_VAL_HELP        },
        { "plugin",          required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts",     required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "password",        required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "key",             required_argument, NULL, GETOPT_VAL_KEY         },
#ifdef __linux__
        { "mptcp",           no_argument,       NULL, GETOPT_VAL_MPTCP       },
#ifdef USE_NFTABLES
        { "nftables-sets",   required_argument, NULL, GETOPT_VAL_NFTABLES_SETS },
#endif
#endif
        { NULL,              0,                 NULL, 0                      }
    };

    int mode_set = 0;
    int ipv6first_set = 0;
    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, ":f:s:p:k:t:m:b:c:i:d:a:n:huUv6A",
                            long_options, NULL)) != -1) {
        switch (c) {
        case GETOPT_VAL_VERSION:
            cli_version();
            exit(EXIT_SUCCESS);
        case GETOPT_VAL_TCP_ONLY:
            mode = TCP_ONLY;
            mode_set = 1;
            break;
        case GETOPT_VAL_IPV4_FIRST:
            ipv6first = 0;
            ipv6first_set = 1;
            break;
        case GETOPT_VAL_FAST_OPEN:
            fast_open = 1;
            break;
        case GETOPT_VAL_MAX_CONNECTIONS:
            if (ss_parse_int(optarg, 1, 1 << 20, &max_connections) == -1) {
                cli_error("invalid connection limit", c, NULL);
            }
            break;
        case GETOPT_VAL_MAX_UDP_SESSIONS:
            if (ss_parse_int(optarg, 1, 1 << 20, &max_udp_sessions) == -1) {
                cli_error("invalid UDP session limit", c, NULL);
            }
            break;
        case GETOPT_VAL_MAX_DNS_QUERIES:
            if (ss_parse_int(optarg, 1, 1 << 20, &max_dns_queries) == -1) {
                cli_error("invalid DNS query limit", c, NULL);
            }
            break;
        case GETOPT_VAL_NODELAY:
            no_delay = 1;
            LOGI("enable TCP no-delay");
            break;
        case GETOPT_VAL_ACL:
            LOGI("initializing acl...");
            acl = !init_acl(optarg);
            break;
        case GETOPT_VAL_MANAGER_ADDRESS:
            manager_addr = optarg;
            break;
        case GETOPT_VAL_MTU:
            if (ss_parse_int(optarg, 0, INT_MAX, &mtu) == -1) {
                cli_error("invalid MTU", c, NULL);
            }
            LOGI("set MTU to %d", mtu);
            break;
        case GETOPT_VAL_PLUGIN:
            plugin = optarg;
            break;
        case GETOPT_VAL_PLUGIN_OPTS:
            plugin_opts = optarg;
            break;
        case GETOPT_VAL_MPTCP:
            mptcp = get_mptcp(1);
            if (mptcp)
                LOGI("enable multipath TCP (%s)", mptcp > 0 ? "out-of-tree" : "upstream");
            break;
        case GETOPT_VAL_KEY:
            key = optarg;
            break;
        case GETOPT_VAL_REUSE_PORT:
            reuse_port = 1;
            break;
        case GETOPT_VAL_TCP_INCOMING_SNDBUF:
            if (ss_parse_int(optarg, 0, INT_MAX, &tcp_incoming_sndbuf) == -1) {
                cli_error("invalid TCP incoming send buffer size", c, NULL);
            }
            break;
        case GETOPT_VAL_TCP_INCOMING_RCVBUF:
            if (ss_parse_int(optarg, 0, INT_MAX, &tcp_incoming_rcvbuf) == -1) {
                cli_error("invalid TCP incoming receive buffer size", c, NULL);
            }
            break;
        case GETOPT_VAL_TCP_OUTGOING_SNDBUF:
            if (ss_parse_int(optarg, 0, INT_MAX, &tcp_outgoing_sndbuf) == -1) {
                cli_error("invalid TCP outgoing send buffer size", c, NULL);
            }
            break;
        case GETOPT_VAL_TCP_OUTGOING_RCVBUF:
            if (ss_parse_int(optarg, 0, INT_MAX, &tcp_outgoing_rcvbuf) == -1) {
                cli_error("invalid TCP outgoing receive buffer size", c, NULL);
            }
            break;
#ifdef USE_NFTABLES
        case GETOPT_VAL_NFTABLES_SETS:
            nftbl_init(optarg);
            break;
#endif
        case 's':
            if (server_num < MAX_REMOTE_NUM) {
                parse_addr(optarg, &server_addr[server_num++]);
            }
            break;
        case 'b':
            is_bind_local_addr += parse_local_addr(&local_addr_v4, &local_addr_v6, optarg);
            break;
        case 'p':
            {
                uint16_t checked_port;
                if (ss_parse_uint16_port(optarg, &checked_port) != 0)
                    cli_error("port must be an integer from 1 to 65535", c, NULL);
            }
            server_port = optarg;
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
            {
                int checked_timeout;
                if (ss_parse_int(optarg, 1, INT_MAX, &checked_timeout) != 0)
                    cli_error("timeout must be a positive integer", c, NULL);
            }
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'd':
            nameservers = optarg;
            break;
        case 'a':
            user = optarg;
            break;
#ifdef HAVE_SETRLIMIT
        case 'n':
            if (ss_parse_int(optarg, 0, INT_MAX, &nofile) == -1) {
                cli_error("invalid nofile", c, NULL);
            }
            break;
#endif
        case 'u':
            mode_set = 1;
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode_set = 1;
            mode = UDP_ONLY;
            break;
        case 'v':
            verbose = 1;
            break;
        case GETOPT_VAL_HELP:
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case '6':
            ipv6first_set = 1;
            ipv6first = 1;
            break;
        case 'A':
            cli_error("one-time authentication was removed; use an AEAD cipher", 'A', NULL);
            break;
        case ':':
            cli_error("missing required argument for option", optopt, argv[optind - 1]);
            break;
        case '?':
            cli_error("unrecognized or invalid option", optopt, argv[optind - 1]);
            break;
        default:
            cli_error("option is unsupported on this platform", c, NULL);
            break;
        }
    }

    if (optind < argc) {
        cli_error("unexpected positional argument", 0, NULL);
    }

    if (argc == 1) {
        if (conf_path == NULL) {
            conf_path = get_default_conf();
        }
    }

    if (conf_path != NULL) {
        jconf_t *conf = read_jconf(conf_path);
        if (server_num == 0) {
            server_num = conf->remote_num;
            for (i = 0; i < server_num; i++)
                server_addr[i] = conf->remote_addr[i];
        }
        if (server_port == NULL) {
            server_port = conf->remote_port;
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
        if (!mode_set) {
            mode = conf->mode;
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
        if (max_connections == 0) {
            max_connections = conf->max_connections;
        }
        if (max_udp_sessions == 0) {
            max_udp_sessions = conf->max_udp_sessions;
        }
        if (max_dns_queries == 0) {
            max_dns_queries = conf->max_dns_queries;
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
        if (is_bind_local_addr == 0) {
            is_bind_local_addr += parse_local_addr(&local_addr_v4, &local_addr_v6, conf->local_addr);
        }
        if (is_bind_local_addr == 0) {
            is_bind_local_addr += parse_local_addr(&local_addr_v4, &local_addr_v6, conf->local_addr_v4);
            is_bind_local_addr += parse_local_addr(&local_addr_v4, &local_addr_v6, conf->local_addr_v6);
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        if (nameservers == NULL) {
            nameservers = conf->nameserver;
        }
        if (!ipv6first_set) {
            ipv6first = conf->ipv6_first;
        }
        if (acl == 0 && conf->acl != NULL) {
            LOGI("initializing acl...");
            acl = !init_acl(conf->acl);
        }
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

    if (server_num == 0) {
        server_addr[server_num++].host = (char *)"0.0.0.0";
    }

    if (server_num == 0 || server_port == NULL
        || (password == NULL && key == NULL)) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (is_ipv6only(server_addr, server_num, ipv6first)) {
        plugin_host = (char *)"::1";
    } else {
        plugin_host = (char *)"127.0.0.1";
    }

    remote_port = server_port;

#ifdef __MINGW32__
    winsock_init();
#endif

    if (plugin != NULL) {
        uint16_t port = get_local_port();
        if (port == 0) {
            FATAL("failed to find a free port");
        }
        snprintf(tmp_port, 8, "%d", port);
        plugin_port = server_port;
        server_port = tmp_port;

#ifdef __MINGW32__
        memset(&plugin_watcher, 0, sizeof(plugin_watcher));
        plugin_watcher.port = get_local_port();
        if (plugin_watcher.port == 0) {
            LOGE("failed to assign a control port for plugin");
        }
#endif
    }

    if (method == NULL) {
        method = (char *)"chacha20-ietf-poly1305";
    }

    if (timeout == NULL) {
        timeout = (char *)"60";
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

    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(pid_path);
        if (!program.after_fork())
            FATAL("failed to reinitialize the event loop");
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    if (plugin != NULL) {
        LOGI("plugin \"%s\" enabled", plugin);
    }

    if (mode != TCP_ONLY) {
        LOGI("UDP relay enabled");
    }

    if (mode == UDP_ONLY) {
        LOGI("TCP relay disabled");
    }

    if (no_delay) {
        LOGI("enable TCP no-delay");
    }

#ifndef __MINGW32__
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    if (!program.handle_signals(false, plugin != NULL ? &plugin_alive : NULL))
        FATAL("failed to watch signals");

    // setup keys
    LOGI("initializing ciphers... %s", method);
    ss::relay::Method relay_method;
    if (!relay_method.init(method, password, key, ss::crypto::Role::server))
        FATAL("failed to initialize ciphers");
    if (relay_method.is_2022() && !relay_method.reserve_salt_pool(65536, randombytes_random()))
        FATAL("failed to set up the AEAD-2022 salt pool");

    // initialize ev loop

    // setup dns
    if (nameservers != NULL)
        LOGI("using nameserver: %s", nameservers);

#ifdef __MINGW32__
    // Listen on plugin control port
    if (plugin != NULL && plugin_watcher.port != 0) {
        SOCKET fd;
        fd = ss_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd != INVALID_SOCKET) {
            plugin_watcher.valid = 0;
            do {
                struct sockaddr_in addr;
                memset(&addr, 0, sizeof(addr));
                addr.sin_family      = AF_INET;
                addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                addr.sin_port        = htons(plugin_watcher.port);
                if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
                    LOGE("failed to bind plugin control port");
                    break;
                }
                if (listen(fd, 1)) {
                    LOGE("failed to listen on plugin control port");
                    break;
                }
                plugin_watcher.fd = fd;
                if (!program.watch(fd, plugin_watcher_cb, &program))
                    break;
                plugin_watcher.valid = 1;
            } while (0);
            if (!plugin_watcher.valid) {
                closesocket(fd);
                plugin_watcher.port = 0;
            }
        }
    }
#endif

    // Start plugin server
    if (plugin != NULL) {
        int len          = 0;
        size_t buf_size  = 256 * server_num;
        char *server_str = (char *)ss_malloc(buf_size);

        snprintf(server_str, buf_size, "%s", server_addr[0].host);
        len = strlen(server_str);
        for (int i = 1; i < server_num; i++) {
            snprintf(server_str + len, buf_size - len, "|%s", server_addr[i].host);
            len = strlen(server_str);
        }

        int err = start_plugin(plugin, plugin_opts, server_str,
                               plugin_port, plugin_host, server_port,
#ifdef __MINGW32__
                               plugin_watcher.port,
#endif
                               MODE_SERVER);
        if (err) {
            ERROR("start_plugin");
            FATAL("failed to start the plugin");
        }
    }

    // The relays share one resolver for targets given by name.
    ss::event::Loop &tcp_loop = program.loop();
    ss::relay::Resolver tcp_resolver;
    ss::relay::TcpRelay tcp_relay;
    ss::relay::UdpRelay udp_relay;
    bool tcp_running = false;
    if (max_dns_queries == 0)
        max_dns_queries = (max_connections > 0 ? max_connections : DEFAULT_MAX_CONNECTIONS) + 64;
    if (!tcp_resolver.init(tcp_loop, nameservers, ipv6first != 0, max_dns_queries)) {
        FATAL("failed to set up the resolver");
    }
#ifndef __MINGW32__
    stat_resolver = &tcp_resolver;
#endif
    if (mode != UDP_ONLY) {
        ss::relay::TcpConfig tcp_config;
        tcp_config.kind            = ss::relay::Kind::server;
        tcp_config.timeout_secs    = timeout_secs;
        tcp_config.max_connections = max_connections > 0 ? max_connections : DEFAULT_MAX_CONNECTIONS;
        tcp_config.fast_open       = fast_open != 0;
        tcp_config.no_delay        = no_delay != 0;
        tcp_config.acl             = acl != 0;
        tcp_config.acl_hooks.match_host       = &acl_match_host;
        tcp_config.acl_hooks.mode             = &get_acl_mode;
        tcp_config.acl_hooks.outbound_blocked = &outbound_block_match_host;
        tcp_config.label           = remote_port != NULL ? remote_port : "";
        tcp_config.upstream.sndbuf = tcp_outgoing_sndbuf;
        tcp_config.upstream.rcvbuf = tcp_outgoing_rcvbuf;
        tcp_config.upstream.iface  = iface;
        if (is_bind_local_addr) {
            tcp_config.upstream.bind_v4 = &local_addr_v4;
            tcp_config.upstream.bind_v6 = &local_addr_v6;
        }
        tcp_config.tx             = &tx;
        tcp_config.rx             = &rx;
        tcp_config.report_failure = &report_failure;
#ifdef USE_NFCONNTRACK_TOS
        tcp_config.downstream = &setTosFromConnmark;
        tcp_config.release    = &releaseTracker;
#endif
        if (!tcp_relay.init(tcp_loop, relay_method, tcp_config, &tcp_resolver)) {
            FATAL("failed to set up the TCP relay");
        }
        tcp_running = true;
    }

    // bind to each interface
    if (mode != UDP_ONLY) {
        int num_listen_ctx = 0;
        for (int i = 0; i < server_num; i++) {
            const char *host = server_addr[i].host;
            const char *port = server_addr[i].port ? server_addr[i].port : server_port;

            if (plugin != NULL) {
                host = plugin_host;
            }

            if (host && ss_is_ipv6addr(host))
                LOGI("tcp server listening at [%s]:%s", host, port);
            else
                LOGI("tcp server listening at %s:%s", host ? host : "0.0.0.0", port);

            // Bind to port
            int listenfd;
            listenfd = create_and_bind(host, port, mptcp);
            if (listenfd == -1) {
                continue;
            }
            if (listen(listenfd, SSMAXCONN) == -1) {
                ERROR("listen()");
                continue;
            }
            setfastopen(listenfd);
            if (!tcp_relay.listen(listenfd)) {
                ss_socket_close(listenfd);
                continue;
            }

            num_listen_ctx++;

            if (plugin != NULL)
                break;
        }

        if (num_listen_ctx == 0) {
            FATAL("failed to listen on any address");
        }
    }

    if (mode != TCP_ONLY) {
        ss::relay::UdpConfig udp_config;
        udp_config.kind         = ss::relay::Kind::server;
        udp_config.timeout_secs = timeout_secs;
        udp_config.max_sessions = max_udp_sessions > 0 ? max_udp_sessions : 512;
        udp_config.mtu          = mtu;
        udp_config.iface        = iface;
        udp_config.label        = remote_port != NULL ? remote_port : "";
        udp_config.tx           = &tx;
        udp_config.rx           = &rx;
        if (is_bind_local_addr) {
            udp_config.bind_v4 = &local_addr_v4;
            udp_config.bind_v6 = &local_addr_v6;
        }
        if (!udp_relay.init(tcp_loop, relay_method, udp_config, &tcp_resolver)) {
            FATAL("failed to initialize UDP relay");
        }
        int num_listen_ctx = 0;
        for (int i = 0; i < server_num; i++) {
            const char *host = server_addr[i].host;
            const char *port = server_addr[i].port ? server_addr[i].port : server_port;
            if (plugin != NULL) {
                port = plugin_port;
            }
            if (host && ss_is_ipv6addr(host))
                LOGI("udp server listening at [%s]:%s", host, port);
            else
                LOGI("udp server listening at %s:%s", host ? host : "0.0.0.0", port);
            // Setup UDP
            auto udp_fd = ss::relay::open_udp_listener(host, port, false, reuse_port != 0);
            if (!udp_fd)
                continue;
            if (!udp_relay.listen(*udp_fd)) {
                ss_socket_close(*udp_fd);
                continue;
            }
            num_listen_ctx++;
        }

        if (num_listen_ctx == 0) {
            FATAL("failed to listen on any address");
        }
    }

#ifdef __MINGW32__
    if (manager_addr != NULL) {
        LOGE("--manager-address is not supported on Windows; ignored");
    }
#endif

#ifndef __MINGW32__
    if (manager_addr != NULL) {
        if (!program.every(UPDATE_INTERVAL * 1000, stat_update_cb, NULL))
            FATAL("failed to start the traffic statistics timer");
    }
#endif

#ifndef __MINGW32__
    // setuid
    if (user != NULL && !run_as(user)) {
        FATAL("failed to switch user");
    }

    if (geteuid() == 0) {
        LOGI("running from root user");
    }
#endif

    // start ev loop
    ss::heap_seal();
    {
        int code = program.run();
        if (code != 0)
            ret_val = code;
    }

    if (verbose) {
        LOGI("closed gracefully");
    }

    if (plugin != NULL) {
        stop_plugin();
    }

    // Clean up

    {
        static bool resolver_closed;
        resolver_closed = false;
        tcp_relay.shutdown();
        udp_relay.shutdown();
        tcp_resolver.shutdown(ss::CloseCompletion([](void *, uint32_t) { resolver_closed = true; }, NULL, 0));
        while (!tcp_relay.closed() || !udp_relay.closed() || !resolver_closed) {
            tcp_loop.run_nowait();
        }
    }
    (void)tcp_running;
#ifndef __MINGW32__
    stat_resolver = NULL;
#endif
    program.close();

#ifdef __MINGW32__

    winsock_cleanup();
#endif

    if (verbose)
        ss::log_heap_report();

    return ret_val;
}
