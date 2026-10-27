/*
 * local.cpp - Setup a socks5 proxy through remote shadowsocks server
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
#include <unistd.h>
#include <getopt.h>
#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#endif
#ifdef LIB_ONLY
#include "shadowsocks.h"
#include "shadowsocks/control.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "core.h"

#include "netutils.h"
#include "ssurl.h"
#include "utils.h"
#include "socks5.h"
#include "acl.h"
#include "plugin.h"
#include "jconf.h"
#include "common.h"
#include "ss_windows.h"

#include "core/heap_guard.hpp"
#include "event/program.hpp"
#include "relay/tcp.hpp"
#include "relay/udp.hpp"

#undef min
#undef max

#ifndef LIB_ONLY
#ifdef __APPLE__
#include <AvailabilityMacros.h>
#if defined(MAC_OS_X_VERSION_10_10) && MAC_OS_X_VERSION_MIN_REQUIRED >= MAC_OS_X_VERSION_10_10
#include <launch.h>
#define HAVE_LAUNCHD
#endif
#endif
#endif

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

int verbose    = 0;
int reuse_port = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;

#ifdef __ANDROID__
int vpn        = 0;
uint64_t tx    = 0;
uint64_t rx    = 0;
ss_tstamp last = 0;

char *stat_path   = NULL;
#endif


static int acl       = 0;
static int mode      = TCP_ONLY;
static int ipv6first = 0;
int fast_open        = 0;
static int no_delay  = 0;
static int max_connections  = 0;
static int max_udp_sessions = 0;
static int max_dns_queries  = 0;
static int printable_salt = 0;
static int udp_fd    = 0;
static int ret_val   = 0;

#ifndef __MINGW32__
#else
#ifndef LIB_ONLY
static struct plugin_watcher_t {
    SOCKET fd;
    uint16_t port;
    int valid;
} plugin_watcher;
#endif
#endif

#ifdef HAVE_SETRLIMIT
#ifndef LIB_ONLY
static int nofile = 0;
#endif
#endif

#if defined(__MINGW32__) && !defined(LIB_ONLY)
#endif

static int create_and_bind(const char *addr, const char *port);
#ifdef HAVE_LAUNCHD
static int launch_or_create(const char *addr, const char *port);
#endif
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
create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    result            = NULL;

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

#ifdef HAVE_LAUNCHD
int
launch_or_create(const char *addr, const char *port)
{
    int *fds;
    size_t cnt;
    int error = launch_activate_socket("Listeners", &fds, &cnt);
    if (error == 0) {
        if (cnt == 1) {
            return fds[0];
        } else {
            FATAL("please don't specify multi entry");
        }
    } else if (error == ESRCH || error == ENOENT) {
        /* ESRCH:  The calling process is not managed by launchd(8).
         * ENOENT: The socket name specified does not exist
         *          in the caller's launchd.plist(5).
         */
        if (port == NULL) {
            usage();
            exit(EXIT_FAILURE);
        }
        return create_and_bind(addr, port);
    } else {
        FATAL("launch_activate_socket() error");
    }
    return -1;
}

#endif

#ifdef __ANDROID__
void
stat_update_cb()
{
    ss_tstamp now = ss_time();
    if (now - last > 0.5) {
        send_traffic_stat(tx, rx);
        last = now;
    }
}

#endif

// The relays of ss-local on the ss_event loop: TCP (with a resolver for
// host-name ACL rules) and UDP, sharing one cipher configuration.
namespace {

struct Relays {
    ss::event::Loop *loop = NULL;
    ss::relay::Method method;
    ss::relay::Resolver resolver;
    ss::relay::TcpRelay tcp;
    ss::relay::UdpRelay udp;
    bool resolving = false;
    bool tcp_on    = false;
    bool udp_on    = false;

    bool init(ss::event::Loop &event_loop, const char *cipher, const char *pass, const char *key)
    {
        loop = &event_loop;
        LOGI("initializing ciphers... %s", cipher);
        if (!method.init(cipher, pass, key, ss::crypto::Role::client)) {
            return false;
        }
        return true;
    }

    bool start_tcp(ss::relay::TcpConfig &config, int listenfd)
    {
        if (config.acl) {
            config.acl_hooks.match_host       = &acl_match_host;
            config.acl_hooks.mode             = &get_acl_mode;
            config.acl_hooks.outbound_blocked = &outbound_block_match_host;
            if (!resolver.init(*loop, NULL, ipv6first != 0,
                               max_dns_queries > 0 ? (uint32_t)max_dns_queries : config.max_connections)) {
                return false;
            }
            resolving = true;
        }
        if (!tcp.init(*loop, method, config, resolving ? &resolver : NULL)) {
            return false;
        }
        tcp_on = true; // stop() shuts it down, closing listenfd once it is taken
        return (bool)tcp.listen(listenfd);
    }

    // Returns the UDP socket, or -1.
    int start_udp(const char *host, const char *port, const struct sockaddr_storage *remote, int mtu, int timeout,
                  const char *iface)
    {
        ss::relay::UdpConfig config;
        config.kind         = ss::relay::Kind::local;
        config.remote       = *remote;
        config.timeout_secs = timeout;
        config.max_sessions = max_udp_sessions > 0 ? max_udp_sessions : 256;
        config.mtu          = mtu;
        config.iface        = iface;
#ifdef __ANDROID__
        config.vpn        = vpn != 0;
        config.protect    = protect_socket;
        config.tx         = &tx;
        config.rx         = &rx;
        config.on_traffic = &stat_update_cb;
#endif
        auto fd = ss::relay::open_udp_listener(host, port, false, reuse_port != 0);
        if (!fd || !udp.init(*loop, method, config, NULL)) {
            return -1;
        }
        if (!udp.listen(*fd)) {
            ss_socket_close(*fd);
            return -1;
        }
        udp_on = true;
        return (int)*fd;
    }

    void stop()
    {
        if (tcp_on) {
            tcp.shutdown();
        }
        if (udp_on) {
            udp.shutdown();
        }
        static bool resolver_closed;
        resolver_closed = !resolving;
        if (resolving) {
            resolver.shutdown(ss::CloseCompletion([](void *, uint32_t) { resolver_closed = true; }, NULL, 0));
        }
        while ((tcp_on && !tcp.closed()) || (udp_on && !udp.closed()) || !resolver_closed) {
            loop->run_nowait();
        }
        tcp_on = udp_on = resolving = false;
    }
};

void
fill_tcp_config(ss::relay::TcpConfig &config, const struct sockaddr_storage *remotes, int remote_count,
                int timeout, int mptcp, char *iface)
{
    config.kind             = ss::relay::Kind::local;
    config.remotes          = { remotes, (size_t)remote_count };
    config.timeout_secs     = timeout;
    config.max_connections  = max_connections > 0 ? max_connections : DEFAULT_MAX_CONNECTIONS;
    config.fast_open        = fast_open != 0;
    config.no_delay         = no_delay != 0;
    config.printable_salt   = printable_salt != 0;
    config.acl              = acl != 0;
    config.upstream.sndbuf  = tcp_outgoing_sndbuf;
    config.upstream.rcvbuf  = tcp_outgoing_rcvbuf;
    config.upstream.mptcp   = mptcp;
    config.upstream.iface   = iface;
#ifdef __ANDROID__
    config.vpn              = vpn != 0;
    config.upstream.protect = protect_socket;
    config.tx               = &tx;
    config.rx               = &rx;
    config.on_traffic       = &stat_update_cb;
#endif
}

} // namespace


#if defined(__MINGW32__) && !defined(LIB_ONLY)
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

#ifndef LIB_ONLY
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
    int pid_flags    = 0;
    int mtu          = 0;
    int mptcp        = 0;
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
    char *iface      = NULL;

    char *plugin      = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    char tmp_port[8];

    int remote_num = 0;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    /* Lives until exit; its strings are handed to the config above. */
    ss_url_t server_url = { 0 };

    memset(remote_addr, 0, sizeof(ss_addr_t) * MAX_REMOTE_NUM);

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

/* [cli_long_server]
\par `--server <HOST:PORT>`
Set a remote server endpoint; may be repeated with different ports. Use `HOST:PORT` for a hostname or IPv4, and `[IPv6]:PORT` for IPv6 (including `%scope` when needed). Bare IPv6 is always a host, never split into a port. Host-only values require the legacy `--server-port` fallback or a configured port. An endpoint port takes priority over the fallback regardless of option order. SIP003 plugins require the same port for all endpoints. Short alias: `-s`.
[cli_long_server] */

/* [cli_long_server_port]
\par `--server-port <server_port>`
Legacy fallback port for server values without an embedded port. Prefer `--server HOST:PORT`. Short alias: `-p`.
[cli_long_server_port] */

/* [cli_long_listen_address]
\par `--listen-address <local_address>`
Set the listening address. Server and manager addresses may be repeated. Short alias: `-b`.
[cli_long_listen_address] */

/* [cli_long_listen_port]
\par `--listen-port <local_port>`
Set the listening port. Short alias: `-l`.
[cli_long_listen_port] */

/* [cli_long_interface]
\par `--interface <interface>`
Same behavior as `-i`; see that option for details. Short alias: `-i`.
[cli_long_interface] */

/* [cli_long_vpn]
\par `--vpn`
Same behavior as `-V`; see that option for details. Short alias: `-V`.
[cli_long_vpn] */

/* [cli_long_stat_path]
\par `--stat-path <path>`
Same behavior as `-S`; see that option for details. Short alias: `-S`.
[cli_long_stat_path] */

/* [cli-options]
\snippet{doc} utils.cpp cli_short_f
\snippet{doc} utils.cpp cli_short_s
\snippet{doc} utils.cpp cli_short_p
\snippet{doc} utils.cpp cli_short_l
\snippet{doc} utils.cpp cli_short_k
\snippet{doc} utils.cpp cli_short_t
\snippet{doc} utils.cpp cli_short_m
\snippet{doc} utils.cpp cli_short_i
\snippet{doc} utils.cpp cli_short_c
\snippet{doc} utils.cpp cli_short_b
\snippet{doc} utils.cpp cli_short_a
\snippet{doc} utils.cpp cli_short_n
\snippet{doc} utils.cpp cli_short_S
\snippet{doc} utils.cpp cli_short_h
\snippet{doc} utils.cpp cli_short_u
\snippet{doc} utils.cpp cli_short_U
\snippet{doc} utils.cpp cli_short_v
\snippet{doc} utils.cpp cli_short_V
\snippet{doc} utils.cpp cli_short_6
\snippet{doc} utils.cpp cli_short_A
\snippet{doc} local.cpp cli_long_config
\snippet{doc} local.cpp cli_long_cipher
\snippet{doc} local.cpp cli_long_timeout
\snippet{doc} local.cpp cli_long_user
\snippet{doc} local.cpp cli_long_pid_file
\snippet{doc} local.cpp cli_long_nofile
\snippet{doc} local.cpp cli_long_udp
\snippet{doc} local.cpp cli_long_udp_only
\snippet{doc} local.cpp cli_long_ipv6_first
\snippet{doc} local.cpp cli_long_verbose
\snippet{doc} local.cpp cli_long_server
\snippet{doc} local.cpp cli_long_server_port
\snippet{doc} local.cpp cli_long_listen_address
\snippet{doc} local.cpp cli_long_listen_port
\snippet{doc} local.cpp cli_long_interface
\snippet{doc} utils.cpp cli_long_version
\snippet{doc} utils.cpp cli_long_tcp_only
\snippet{doc} utils.cpp cli_long_ipv4_first
\snippet{doc} local.cpp cli_long_vpn
\snippet{doc} local.cpp cli_long_stat_path
\snippet{doc} utils.cpp cli_long_reuse_port
\snippet{doc} utils.cpp cli_long_tcp_incoming_sndbuf
\snippet{doc} utils.cpp cli_long_tcp_incoming_rcvbuf
\snippet{doc} utils.cpp cli_long_tcp_outgoing_sndbuf
\snippet{doc} utils.cpp cli_long_tcp_outgoing_rcvbuf
\snippet{doc} utils.cpp cli_long_fast_open
\snippet{doc} utils.cpp cli_long_no_delay
\snippet{doc} utils.cpp cli_long_max_connections
\snippet{doc} utils.cpp cli_long_max_udp_sessions
\snippet{doc} utils.cpp cli_long_max_dns_queries
\snippet{doc} utils.cpp cli_long_acl
\snippet{doc} utils.cpp cli_long_mtu
\snippet{doc} utils.cpp cli_long_mptcp
\snippet{doc} utils.cpp cli_long_plugin
\snippet{doc} utils.cpp cli_long_plugin_opts
\snippet{doc} utils.cpp cli_long_password
\snippet{doc} utils.cpp cli_long_key
\snippet{doc} utils.cpp cli_long_server_url
\snippet{doc} utils.cpp cli_long_printable_salt
\snippet{doc} utils.cpp cli_long_help
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
        { "server", required_argument, NULL, 's' },
        { "server-port", required_argument, NULL, 'p' },
        { "listen-address", required_argument, NULL, 'b' },
        { "listen-port", required_argument, NULL, 'l' },
        { "interface", required_argument, NULL, 'i' },
        { "version", no_argument, NULL, GETOPT_VAL_VERSION },
        { "tcp-only", no_argument, NULL, GETOPT_VAL_TCP_ONLY },
        { "ipv4-first", no_argument, NULL, GETOPT_VAL_IPV4_FIRST },
#ifdef __ANDROID__
        { "vpn", no_argument, NULL, 'V' },
        { "stat-path", required_argument, NULL, 'S' },
#endif
        { "reuse-port",  no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "tcp-incoming-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_SNDBUF },
        { "tcp-incoming-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_RCVBUF },
        { "tcp-outgoing-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_SNDBUF },
        { "tcp-outgoing-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_RCVBUF },
        { "fast-open",   no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "printable-salt", no_argument, NULL, GETOPT_VAL_PRINTABLE_SALT },
        { "no-delay",    no_argument,       NULL, GETOPT_VAL_NODELAY     },
        { "max-connections", required_argument, NULL, GETOPT_VAL_MAX_CONNECTIONS },
        { "max-udp-sessions", required_argument, NULL, GETOPT_VAL_MAX_UDP_SESSIONS },
        { "max-dns-queries", required_argument, NULL, GETOPT_VAL_MAX_DNS_QUERIES },
        { "acl",         required_argument, NULL, GETOPT_VAL_ACL         },
        { "mtu",         required_argument, NULL, GETOPT_VAL_MTU         },
        { "mptcp",       no_argument,       NULL, GETOPT_VAL_MPTCP       },
        { "plugin",      required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts", required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "password",    required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "key",         required_argument, NULL, GETOPT_VAL_KEY         },
        { "server-url",  required_argument, NULL, GETOPT_VAL_SERVER_URL  },
        { "help",        no_argument,       NULL, GETOPT_VAL_HELP        },
        { NULL,          0,                 NULL, 0                      }
    };

    int mode_set = 0;
    int ipv6first_set = 0;
    opterr = 0;

    USE_TTY();

#ifdef __ANDROID__
    while ((c = getopt_long(argc, argv, ":f:s:p:l:k:t:m:i:c:b:a:n:S:huUvV6A",
                            long_options, NULL)) != -1) {
#else
    while ((c = getopt_long(argc, argv, ":f:s:p:l:k:t:m:i:c:b:a:n:huUv6A",
                            long_options, NULL)) != -1) {
#endif
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
        case GETOPT_VAL_ACL:
            LOGI("initializing acl...");
            if (init_acl(optarg) != 0) {
                LOGE("failed to load the ACL file %s", optarg);
                FATAL("invalid ACL");
            }
            acl = 1;
            break;
        case GETOPT_VAL_MTU:
            if (ss_parse_int(optarg, 0, INT_MAX, &mtu) == -1) {
                cli_error("invalid MTU", c, NULL);
            }
            LOGI("set MTU to %d", mtu);
            break;
        case GETOPT_VAL_MPTCP:
            mptcp = get_mptcp(1);
            if (mptcp)
                LOGI("enable multipath TCP (%s)", mptcp > 0 ? "out-of-tree" : "upstream");
            break;
        case GETOPT_VAL_PRINTABLE_SALT:
            printable_salt = 1;
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
        case GETOPT_VAL_PLUGIN:
            plugin = optarg;
            break;
        case GETOPT_VAL_PLUGIN_OPTS:
            plugin_opts = optarg;
            break;
        case GETOPT_VAL_KEY:
            key = optarg;
            break;
        case GETOPT_VAL_SERVER_URL:
            /*
             * An ss:// URI carries the server, credentials and plugin in one
             * argument. Options given later on the command line still win,
             * since they are applied as getopt reaches them.
             */
            if (ss_url_parse(optarg, &server_url) != 0) {
                cli_error("invalid ss:// server URL", c, NULL);
            }
            if (remote_num < MAX_REMOTE_NUM) {
                remote_addr[remote_num].host = server_url.host;
                remote_addr[remote_num].port = NULL;
                remote_num++;
            }
            remote_port = server_url.port;
            method      = server_url.method;
            password    = server_url.password;
            if (server_url.plugin != NULL)
                plugin = server_url.plugin;
            if (server_url.plugin_opts != NULL)
                plugin_opts = server_url.plugin_opts;
            if (server_url.tag != NULL)
                LOGI("using server \"%s\"", server_url.tag);
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
        case 's':
            if (remote_num < MAX_REMOTE_NUM) {
                if (parse_server_endpoint(optarg, &remote_addr[remote_num]) != 0)
                    cli_error("invalid server endpoint; use HOST:PORT or [IPv6]:PORT", 's', NULL);
                remote_num++;
            } else {
                cli_error("too many server endpoints", 's', NULL);
            }
            break;
        case 'p':
            {
                uint16_t checked_port;
                if (ss_parse_uint16_port(optarg, &checked_port) != 0)
                    cli_error("port must be an integer from 1 to 65535", c, NULL);
            }
            remote_port = optarg;
            break;
        case 'l':
            {
                uint16_t checked_port;
                if (ss_parse_uint16_port(optarg, &checked_port) != 0)
                    cli_error("port must be an integer from 1 to 65535", c, NULL);
            }
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
        case 'b':
            local_addr = optarg;
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
        case 'h':
        case GETOPT_VAL_HELP:
            usage();
            exit(EXIT_SUCCESS);
        case '6':
            ipv6first_set = 1;
            ipv6first = 1;
            break;
#ifdef __ANDROID__
        case 'S':
            stat_path = optarg;
            break;
        case 'V':
            vpn = 1;
            break;
#endif
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
        if (printable_salt == 0) {
            printable_salt = conf->printable_salt;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
        if (!ipv6first_set) {
            ipv6first = conf->ipv6_first;
        }
        if (acl == 0 && conf->acl != NULL) {
            LOGI("initializing acl...");
            if (init_acl(conf->acl) != 0) {
                LOGE("failed to load the ACL file %s", conf->acl);
                FATAL("invalid ACL");
            }
            acl = 1;
        }
    }

    if (complete_server_ports(remote_addr, remote_num, remote_port, plugin != NULL) != 0)
        cli_error("each server needs a port (1 to 65535); plugins require a shared port", 's', NULL);
    remote_port = remote_addr[0].port;

    if (remote_num == 0) {
        fprintf(stderr, "remote_num is 0\n");
        exit(EXIT_FAILURE);
    }
    if (!remote_port) {
        fprintf(stderr, "remote_port is NULL\n");
        exit(EXIT_FAILURE);
    }
#ifndef HAVE_LAUNCHD
    if (!local_port) {
        fprintf(stderr, "local_port is NULL\n");
        exit(EXIT_FAILURE);
    }
#endif
    if (!password && !key) {
        fprintf(stderr, "both password and key are NULL\n");
        exit(EXIT_FAILURE);
    }

#ifdef __MINGW32__
    winsock_init();
#endif

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
        uint16_t port = get_local_port();
        if (port == 0) {
            FATAL("failed to find a free port");
        }
        snprintf(tmp_port, 8, "%d", port);
        if (is_ipv6only(remote_addr, remote_num, ipv6first)) {
            plugin_host = (char *)"::1";
        } else {
            plugin_host = (char *)"127.0.0.1";
        }
        plugin_port = tmp_port;

#ifdef __MINGW32__
        memset(&plugin_watcher, 0, sizeof(plugin_watcher));
        plugin_watcher.port = get_local_port();
        if (plugin_watcher.port == 0) {
            LOGE("failed to assign a control port for plugin");
        }
#endif

        LOGI("plugin \"%s\" enabled", plugin);
    }

    if (method == NULL) {
        method = (char *)"chacha20-ietf-poly1305";
    }
    if (printable_salt && strcmp(method, "chacha20-ietf-poly1305") != 0
        && strcmp(method, "aes-256-gcm") != 0) {
        FATAL("--printable-salt (printable_salt) requires chacha20-ietf-poly1305 or aes-256-gcm");
    }
    if (printable_salt) {
        LOGI("enable experimental printable TCP salt");
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

    if (local_addr == NULL) {
        if (is_ipv6only(remote_addr, remote_num, ipv6first)) {
            local_addr = (char *)"::1";
        } else {
            local_addr = (char *)"127.0.0.1";
        }
    }

    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(pid_path);
        if (!program.after_fork())
            FATAL("failed to reinitialize the event loop");
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
        fast_open = 0;
#endif
    }

    if (no_delay) {
        LOGI("enable TCP no-delay");
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

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

    if (plugin != NULL) {
        int len          = 0;
        size_t buf_size  = 256 * remote_num;
        char *remote_str = (char *)ss_malloc(buf_size);

        snprintf(remote_str, buf_size, "%s", remote_addr[0].host);
        len = strlen(remote_str);
        for (int i = 1; i < remote_num; i++) {
            snprintf(remote_str + len, buf_size - len, "|%s", remote_addr[i].host);
            len = strlen(remote_str);
        }
        set_plugin_user(user); // it drops root along with us
        int err = start_plugin(plugin, plugin_opts, remote_str,
                               remote_port, plugin_host, plugin_port,
#ifdef __MINGW32__
                               plugin_watcher.port,
#endif
                               MODE_CLIENT);
        if (err) {
            ERROR("start_plugin");
            FATAL("failed to start the plugin");
        }
    }

#ifndef __MINGW32__
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    // Setup keys
    Relays relays;
    if (!relays.init(program.loop(), method, password, key))
        FATAL("failed to initialize ciphers");

    // Setup proxy context
    struct sockaddr_storage remote_storage[MAX_REMOTE_NUM];
    int remote_count = 0;
    memset(remote_storage, 0, sizeof(remote_storage));
    for (i = 0; i < remote_num; i++) {
        char *host = remote_addr[i].host;
        char *port = remote_addr[i].port == NULL ? remote_port :
                     remote_addr[i].port;
        if (plugin != NULL) {
            host = plugin_host;
            port = plugin_port;
        }
        if (get_sockaddr(host, port, &remote_storage[i], 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        ++remote_count;

        if (plugin != NULL)
            break;
    }
    ss::relay::TcpConfig tcp_config;
    fill_tcp_config(tcp_config, remote_storage, remote_count, timeout_secs, mptcp, iface);

    // Setup signal handler
    if (!program.handle_signals(false, plugin != NULL ? &plugin_alive : NULL))
        FATAL("failed to watch signals");

    if (ss_is_ipv6addr(local_addr))
        LOGI("listening at [%s]:%s", local_addr, local_port);
    else
        LOGI("listening at %s:%s", local_addr, local_port);


    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
#ifdef HAVE_LAUNCHD
        listenfd = launch_or_create(local_addr, local_port);
#else
        listenfd = create_and_bind(local_addr, local_port);
#endif
        if (listenfd == -1) {
            FATAL("bind() error");
        }
        if (listen(listenfd, SOMAXCONN) == -1) {
            FATAL("listen() error");
        }
        if (!relays.start_tcp(tcp_config, listenfd)) {
            FATAL("failed to set up the TCP relay");
        }
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("udprelay enabled");
        char *host = remote_addr[0].host;
        char *port = remote_addr[0].port == NULL ? remote_port : remote_addr[0].port;
        struct sockaddr_storage udp_remote;
        memset(&udp_remote, 0, sizeof(udp_remote));
        if (get_sockaddr(host, port, &udp_remote, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        udp_fd = relays.start_udp(local_addr, local_port, &udp_remote, mtu, timeout_secs, iface);
        if (udp_fd == -1) {
            FATAL("failed to initialize UDP relay");
        }
    }

#ifdef HAVE_LAUNCHD
    if (local_port == NULL)
        LOGI("listening through launchd");
    else
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

    daemon_ready();
    // Enter the loop
    ss::heap_seal();
    {
        int code = program.run();
        if (code != 0)
            ret_val = code;
    }

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    if (plugin != NULL) {
        stop_plugin();
    }

    relays.stop();
    program.close();

#ifdef __MINGW32__

    winsock_cleanup();
#endif

    if (verbose)
        ss::log_heap_report();

    return ret_val;
}

#else

// ------------------------------------------------------------ library API

int _start_ss_local_server(profile_t profile, ss_local_callback callback, void *udata, bool embedded);

struct ss_local_handle {
    profile_t profile;
    ss_local_callback callback;
    void *udata;
    uv_thread_t thread;
    uv_mutex_t join_lock; // serialises ss_local_wait() callers
    int result;
    bool waited;
    bool stop_requested; // guarded by control_lock
};

namespace {

// The running server's loop. ss_local_stop() and the server thread take
// the lock around it, so a stop never wakes a loop that is gone.
uv_mutex_t control_lock;
uv_once_t control_once = UV_ONCE_INIT;
ss::event::Program *running_program = NULL;
ss_local_handle *running_handle = NULL;
bool server_busy                = false;

void control_init(void) { uv_mutex_init(&control_lock); }

char *copy_string(const char *s)
{
    return s == NULL ? NULL : strdup(s); // heap-ok: startup, library only
}

void free_profile(profile_t *p)
{
    free(p->remote_host); // heap-ok: library API, startup
    free(p->local_addr);  // heap-ok: library API, startup
    free(p->method);      // heap-ok: library API, startup
    free(p->password);    // heap-ok: library API, startup
    free(p->acl);         // heap-ok: library API, startup
    free(p->log);         // heap-ok: library API, startup
}

void server_thread(void *arg)
{
    ss_local_handle *h = (ss_local_handle *)arg;
    h->result          = _start_ss_local_server(h->profile, h->callback, h->udata, true);
    uv_mutex_lock(&control_lock);
    running_handle = NULL;
    server_busy    = false;
    uv_mutex_unlock(&control_lock);
}

} // namespace

extern "C" int
ss_local_start(const profile_t *profile, ss_local_callback callback, void *udata, ss_local_handle **handle)
{
    if (profile == NULL || handle == NULL || profile->remote_host == NULL || profile->method == NULL
        || profile->password == NULL) {
        return EINVAL;
    }
    uv_once(&control_once, control_init);
    uv_mutex_lock(&control_lock);
    if (server_busy) {
        uv_mutex_unlock(&control_lock);
        return EBUSY;
    }
    ss_local_handle *h = (ss_local_handle *)calloc(1, sizeof(*h)); // heap-ok: startup, library only
    if (h == NULL) {
        uv_mutex_unlock(&control_lock);
        return ENOMEM;
    }
    h->profile             = *profile;
    h->profile.remote_host = copy_string(profile->remote_host);
    h->profile.local_addr  = copy_string(profile->local_addr);
    h->profile.method      = copy_string(profile->method);
    h->profile.password    = copy_string(profile->password);
    h->profile.acl         = copy_string(profile->acl);
    h->profile.log         = copy_string(profile->log);
    h->callback            = callback;
    h->udata               = udata;
    if (uv_mutex_init(&h->join_lock) != 0) {
        uv_mutex_unlock(&control_lock);
        free_profile(&h->profile);
        free(h); // heap-ok: library API, startup
        return ENOMEM;
    }
    server_busy            = true;
    running_handle         = h;
    uv_mutex_unlock(&control_lock);
    if (uv_thread_create(&h->thread, server_thread, h) != 0) {
        uv_mutex_lock(&control_lock);
        server_busy    = false;
        running_handle = NULL;
        uv_mutex_unlock(&control_lock);
        uv_mutex_destroy(&h->join_lock);
        free_profile(&h->profile);
        free(h); // heap-ok: library API, startup
        return ENOMEM;
    }
    *handle = h;
    return 0;
}

extern "C" void
ss_local_stop(ss_local_handle *handle)
{
    if (handle == NULL) {
        return;
    }
    uv_once(&control_once, control_init);
    uv_mutex_lock(&control_lock);
    handle->stop_requested = true;
    if (running_handle == handle && running_program != NULL) {
        running_program->request_stop();
    }
    uv_mutex_unlock(&control_lock);
}

extern "C" int
ss_local_wait(ss_local_handle *handle)
{
    if (handle == NULL) {
        return EINVAL;
    }
    uv_mutex_lock(&handle->join_lock);
    if (!handle->waited) {
        uv_thread_join(&handle->thread);
        handle->waited = true;
    }
    int result = handle->result;
    uv_mutex_unlock(&handle->join_lock);
    return result;
}

extern "C" void
ss_local_destroy(ss_local_handle *handle)
{
    if (handle == NULL) {
        return;
    }
    ss_local_stop(handle);
    (void)ss_local_wait(handle);
    uv_mutex_destroy(&handle->join_lock);
    free_profile(&handle->profile);
    free(handle); // heap-ok: library API, startup
}

int
_start_ss_local_server(profile_t profile, ss_local_callback callback, void *udata, bool embedded)
{
    char *remote_host = profile.remote_host;
    char *local_addr  = profile.local_addr;
    char *method      = profile.method;
    char *password    = profile.password;
    char *log         = profile.log;
    int remote_port   = profile.remote_port;
    int local_port    = profile.local_port;
    int timeout       = profile.timeout;
    int mtu           = 0;
    int mptcp         = 0;

    mode      = profile.mode;
    fast_open = profile.fast_open;
    verbose   = profile.verbose;
    mtu       = profile.mtu;
    mptcp     = profile.mptcp;

    char local_port_str[16];
    char remote_port_str[16];
    snprintf(local_port_str, sizeof(local_port_str), "%d", local_port);
    snprintf(remote_port_str, sizeof(remote_port_str), "%d", remote_port);

#ifdef __MINGW32__
    winsock_init();
#endif

    USE_LOGFILE(log);

    // Nothing carries over from an earlier run in this process.
    ret_val = 0;
    acl     = 0;
    udp_fd  = -1;
    free_acl();
    if (profile.acl != NULL) {
        LOGI("initializing acl...");
        if (init_acl(profile.acl) != 0) {
            LOGE("failed to load the ACL file %s", profile.acl);
            return -1;
        }
        acl = 1;
    }

    if (local_addr == NULL) {
        local_addr = (char *)"127.0.0.1";
    }

#ifndef __MINGW32__
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    if (!embedded) {
        signal(SIGABRT, SIG_IGN);
    }
#endif

    // The ss_local_start() API runs in a host process whose signals are its
    // own: it stops through ss_local_stop() instead.
    ss::event::Program program;
    Relays relays;
    auto abort_start = [&](int listenfd) {
        if (listenfd >= 0 && relays.tcp.listeners() == 0) {
            ss_socket_close(listenfd);
        }
        relays.stop();
        program.close();
        free_acl();
        acl = 0;
#ifdef __MINGW32__
        winsock_cleanup();
#endif
        return -1;
    };
    if (!program.init() || (!embedded && !program.handle_signals(true)) || !program.allow_remote_stop()) {
        LOGE("failed to set up the event loop");
        return abort_start(-1);
    }

    // Setup keys
    if (!relays.init(program.loop(), method, password, NULL)) {
        LOGE("failed to init ciphers");
        return abort_start(-1);
    }

    struct sockaddr_storage storage;
    memset(&storage, 0, sizeof(struct sockaddr_storage));
    if (get_sockaddr(remote_host, remote_port_str, &storage, 1, ipv6first) == -1) {
        return abort_start(-1);
    }

    // Setup proxy context
    ss::relay::TcpConfig tcp_config;
    fill_tcp_config(tcp_config, &storage, 1, timeout, mptcp, NULL);
    int listen_fd = -1; // stays -1 in UDP_ONLY mode but is still passed to the callback below

    if (ss_is_ipv6addr(local_addr))
        LOGI("listening at [%s]:%s", local_addr, local_port_str);
    else
        LOGI("listening at %s:%s", local_addr, local_port_str);

    if (mode != UDP_ONLY) {
        // Setup socket
        int listenfd;
        listenfd = create_and_bind(local_addr, local_port_str);
        if (listenfd == -1) {
            ERROR("bind()");
            return abort_start(-1);
        }
        if (listen(listenfd, SOMAXCONN) == -1) {
            ERROR("listen()");
            return abort_start(listenfd);
        }
        if (!relays.start_tcp(tcp_config, listenfd)) {
            LOGE("failed to set up the TCP relay");
            return abort_start(listenfd);
        }
        listen_fd = listenfd;
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("udprelay enabled");
        udp_fd = relays.start_udp(local_addr, local_port_str, &storage, mtu, timeout, NULL);
        if (udp_fd == -1) {
            return abort_start(-1);
        }
    }

    if (callback) {
        callback(listen_fd, udp_fd, udata);
    }

    // ss_local_stop() wakes this loop from another thread.
    uv_once(&control_once, control_init);
    uv_mutex_lock(&control_lock);
    bool stop_now   = running_handle != NULL && running_handle->stop_requested;
    running_program = &program;
    uv_mutex_unlock(&control_lock);

    // Enter the loop
    if (!stop_now) {
        int code = program.run();
        if (code != 0)
            ret_val = code;
    }

    uv_mutex_lock(&control_lock);
    running_program = NULL;
    uv_mutex_unlock(&control_lock);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    relays.stop();
    program.close();
    free_acl();
    acl = 0;

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    return ret_val;
}

int
start_ss_local_server(profile_t profile)
{
    return _start_ss_local_server(profile, NULL, NULL, false);
}

int
start_ss_local_server_with_callback(profile_t profile, ss_local_callback callback, void *udata)
{
    return _start_ss_local_server(profile, callback, udata, false);
}

#endif
