/*
 * tunnel.cpp - Setup a local port forwarding through remote shadowsocks server
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
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#endif
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "core.h"

#include "netutils.h"
#include "utils.h"
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

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

static int
validate_tunnel_addr(const ss_addr_t *addr)
{
    struct ss_ip ip;
    uint16_t port;

    if (addr->host == NULL || addr->port == NULL) {
        return -1;
    }
    if (ss_parse_uint16_port(addr->port, &port) == -1) {
        return -1;
    }
    if (ss_ip_init(&ip, addr->host) == -1) {
        size_t host_len = strlen(addr->host);
        if (!validate_hostname(addr->host, host_len)) {
            return -1;
        }
    }

    return 0;
}

#ifdef __ANDROID__
int vpn = 0;
#endif

int verbose    = 0;
int reuse_port = 0;
int tcp_incoming_sndbuf = 0;
int tcp_incoming_rcvbuf = 0;
int tcp_outgoing_sndbuf = 0;
int tcp_outgoing_rcvbuf = 0;


static int ipv6first = 0;
static int mode      = TCP_ONLY;
#ifdef HAVE_SETRLIMIT
static int nofile = 0;
#endif
static int no_delay = 0;
static int max_connections  = 0;
static int max_udp_sessions = 0;
int fast_open       = 0;
static int ret_val  = 0;

#ifndef __MINGW32__
#else
static struct plugin_watcher_t {
    SOCKET fd;
    uint16_t port;
    int valid;
} plugin_watcher;
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
    char *iface      = NULL;

    char *plugin      = NULL;
    char *plugin_opts = NULL;
    char *plugin_host = NULL;
    char *plugin_port = NULL;
    char tmp_port[8];

    ss_addr_t tunnel_addr = { .host = NULL, .port = NULL };
    char *tunnel_addr_str = NULL;

    int remote_num    = 0;
    char *remote_port = NULL;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];

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

/* [cli_long_destination]
\par `--destination <addr:port>`
Set the forwarding destination as HOST:PORT; use [IPv6]:PORT for an IPv6 literal. Short alias: `-L`.
[cli_long_destination] */

/* [cli_long_vpn]
\par `--vpn`
Same behavior as `-V`; see that option for details. Short alias: `-V`.
[cli_long_vpn] */

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
\snippet{doc} utils.cpp cli_short_L
\snippet{doc} utils.cpp cli_short_a
\snippet{doc} utils.cpp cli_short_n
\snippet{doc} utils.cpp cli_short_h
\snippet{doc} utils.cpp cli_short_u
\snippet{doc} utils.cpp cli_short_U
\snippet{doc} utils.cpp cli_short_v
\snippet{doc} utils.cpp cli_short_V
\snippet{doc} utils.cpp cli_short_6
\snippet{doc} utils.cpp cli_short_A
\snippet{doc} tunnel.cpp cli_long_config
\snippet{doc} tunnel.cpp cli_long_cipher
\snippet{doc} tunnel.cpp cli_long_timeout
\snippet{doc} tunnel.cpp cli_long_user
\snippet{doc} tunnel.cpp cli_long_pid_file
\snippet{doc} tunnel.cpp cli_long_nofile
\snippet{doc} tunnel.cpp cli_long_udp
\snippet{doc} tunnel.cpp cli_long_udp_only
\snippet{doc} tunnel.cpp cli_long_ipv6_first
\snippet{doc} tunnel.cpp cli_long_verbose
\snippet{doc} tunnel.cpp cli_long_server
\snippet{doc} tunnel.cpp cli_long_server_port
\snippet{doc} tunnel.cpp cli_long_listen_address
\snippet{doc} tunnel.cpp cli_long_listen_port
\snippet{doc} tunnel.cpp cli_long_interface
\snippet{doc} tunnel.cpp cli_long_destination
\snippet{doc} utils.cpp cli_long_version
\snippet{doc} utils.cpp cli_long_tcp_only
\snippet{doc} utils.cpp cli_long_ipv4_first
\snippet{doc} tunnel.cpp cli_long_vpn
\snippet{doc} utils.cpp cli_long_fast_open
\snippet{doc} utils.cpp cli_long_mtu
\snippet{doc} utils.cpp cli_long_no_delay
\snippet{doc} utils.cpp cli_long_max_connections
\snippet{doc} utils.cpp cli_long_max_udp_sessions
\snippet{doc} utils.cpp cli_long_mptcp
\snippet{doc} utils.cpp cli_long_plugin
\snippet{doc} utils.cpp cli_long_plugin_opts
\snippet{doc} utils.cpp cli_long_reuse_port
\snippet{doc} utils.cpp cli_long_tcp_incoming_sndbuf
\snippet{doc} utils.cpp cli_long_tcp_incoming_rcvbuf
\snippet{doc} utils.cpp cli_long_tcp_outgoing_sndbuf
\snippet{doc} utils.cpp cli_long_tcp_outgoing_rcvbuf
\snippet{doc} utils.cpp cli_long_password
\snippet{doc} utils.cpp cli_long_key
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
        { "destination", required_argument, NULL, 'L' },
        { "version", no_argument, NULL, GETOPT_VAL_VERSION },
        { "tcp-only", no_argument, NULL, GETOPT_VAL_TCP_ONLY },
        { "ipv4-first", no_argument, NULL, GETOPT_VAL_IPV4_FIRST },
#ifdef __ANDROID__
        { "vpn", no_argument, NULL, 'V' },
#endif
        { "fast-open",   no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "mtu",         required_argument, NULL, GETOPT_VAL_MTU         },
        { "no-delay",    no_argument,       NULL, GETOPT_VAL_NODELAY     },
        { "max-connections", required_argument, NULL, GETOPT_VAL_MAX_CONNECTIONS },
        { "max-udp-sessions", required_argument, NULL, GETOPT_VAL_MAX_UDP_SESSIONS },
        { "mptcp",       no_argument,       NULL, GETOPT_VAL_MPTCP       },
        { "plugin",      required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts", required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "reuse-port",  no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "tcp-incoming-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_SNDBUF },
        { "tcp-incoming-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_INCOMING_RCVBUF },
        { "tcp-outgoing-sndbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_SNDBUF },
        { "tcp-outgoing-rcvbuf", required_argument, NULL, GETOPT_VAL_TCP_OUTGOING_RCVBUF },
        { "password",    required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "key",         required_argument, NULL, GETOPT_VAL_KEY         },
        { "help",        no_argument,       NULL, GETOPT_VAL_HELP        },
        { NULL,          0,                 NULL, 0                      }
    };

    int mode_set = 0;
    int ipv6first_set = 0;
    opterr = 0;

    USE_TTY();

#ifdef __ANDROID__
    while ((c = getopt_long(argc, argv, ":f:s:p:l:k:t:m:i:c:b:L:a:n:huUvV6A",
                            long_options, NULL)) != -1) {
#else
    while ((c = getopt_long(argc, argv, ":f:s:p:l:k:t:m:i:c:b:L:a:n:huUv6A",
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
        case 'u':
            mode_set = 1;
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode_set = 1;
            mode = UDP_ONLY;
            break;
        case 'L':
            tunnel_addr_str = optarg;
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
#ifdef __ANDROID__
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
        if (tunnel_addr_str == NULL) {
            tunnel_addr_str = conf->tunnel_address;
        }
        if (!ipv6first_set) {
            ipv6first = conf->ipv6_first;
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
    }

    if (complete_server_ports(remote_addr, remote_num, remote_port, plugin != NULL) != 0)
        cli_error("each server needs a port (1 to 65535); plugins require a shared port", 's', NULL);
    remote_port = remote_addr[0].port;

    if (remote_num == 0 || remote_port == NULL || tunnel_addr_str == NULL
        || local_port == NULL || (password == NULL && key == NULL)) {
        usage();
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
        if (!program.after_fork())
            FATAL("failed to reinitialize the event loop");
    }

    if (ipv6first) {
        LOGI("resolving hostname to IPv6 address first");
    }

    // parse tunnel addr
    parse_addr(tunnel_addr_str, &tunnel_addr);

    if (tunnel_addr.port == NULL) {
        FATAL("tunnel port is not defined");
    }
    if (validate_tunnel_addr(&tunnel_addr) == -1) {
        FATAL("invalid tunnel address");
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

    if (!program.handle_signals(false, plugin != NULL ? &plugin_alive : NULL))
        FATAL("failed to watch signals");

    // Setup keys
    LOGI("initializing ciphers... %s", method);
    ss::relay::Method relay_method;
    if (!relay_method.init(method, password, key, ss::crypto::Role::client))
        FATAL("failed to initialize ciphers");

    // Setup proxy context
    int remote_count = 0;
    struct sockaddr_storage remote_storage[MAX_REMOTE_NUM];
    memset(remote_storage, 0, sizeof(remote_storage));
    for (i = 0; i < remote_num; i++) {
        char *host = remote_addr[i].host;
        char *port = remote_addr[i].port == NULL ? remote_port : remote_addr[i].port;
        if (plugin != NULL) {
            host = plugin_host;
            port = plugin_port;
        }
        if (get_sockaddr(host, port, &remote_storage[i], 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        remote_count++;

        if (plugin != NULL)
            break;
    }

    ss::relay::TcpConfig tcp_config;
    tcp_config.kind              = ss::relay::Kind::tunnel;
    tcp_config.remotes           = { remote_storage, (size_t)remote_count };
    tcp_config.timeout_secs      = timeout_secs;
    tcp_config.max_connections   = max_connections > 0 ? max_connections : DEFAULT_MAX_CONNECTIONS;
    tcp_config.fast_open         = fast_open != 0;
    tcp_config.no_delay          = no_delay != 0;
    tcp_config.upstream.sndbuf   = tcp_outgoing_sndbuf;
    tcp_config.upstream.rcvbuf   = tcp_outgoing_rcvbuf;
    tcp_config.upstream.mptcp    = mptcp;
    tcp_config.upstream.iface    = iface;
    tcp_config.upstream.keepalive = true;
#ifdef __ANDROID__
    tcp_config.vpn              = vpn != 0;
    tcp_config.upstream.protect = protect_socket;
#endif
    {
        uint16_t tunnel_port = 0;
        ss_parse_uint16_port(tunnel_addr.port, &tunnel_port);
        tcp_config.tunnel_target_len = ss::relay::encode_socks_host(tunnel_addr.host, tunnel_port,
                                                                     tcp_config.tunnel_target.data());
        if (tcp_config.tunnel_target_len == 0) {
            FATAL("tunnel host name is too long");
        }
    }

    LOGI("listening at %s:%s", local_addr, local_port);

    ss::event::Loop &tcp_loop = program.loop();
    ss::relay::TcpRelay tcp_relay;
    ss::relay::UdpRelay udp_relay;

    if (mode != UDP_ONLY) {
        if (!tcp_relay.init(tcp_loop, relay_method, tcp_config, NULL)) {
            FATAL("failed to set up the TCP relay");
        }
        // Setup socket
        int listenfd;
        listenfd = create_and_bind(local_addr, local_port);
        if (listenfd == -1) {
            FATAL("bind() error");
        }
        if (listen(listenfd, SOMAXCONN) == -1) {
            FATAL("listen() error");
        }
        if (!tcp_relay.listen(listenfd)) {
            FATAL("failed to watch the listening socket");
        }
    }

    // Setup UDP
    if (mode != TCP_ONLY) {
        LOGI("UDP relay enabled");
        char *host = remote_addr[0].host;
        char *port = remote_addr[0].port == NULL ? remote_port : remote_addr[0].port;
        ss::relay::UdpConfig udp_config;
        udp_config.kind              = ss::relay::Kind::tunnel;
        udp_config.tunnel_target     = tcp_config.tunnel_target;
        udp_config.tunnel_target_len = tcp_config.tunnel_target_len;
        udp_config.timeout_secs      = timeout_secs;
        udp_config.max_sessions      = max_udp_sessions > 0 ? max_udp_sessions : 256;
        udp_config.mtu               = mtu;
        udp_config.iface             = iface;
#ifdef __ANDROID__
        udp_config.vpn     = vpn != 0;
        udp_config.protect = protect_socket;
#endif
        if (get_sockaddr(host, port, &udp_config.remote, 1, ipv6first) == -1) {
            FATAL("failed to resolve the provided hostname");
        }
        auto udp_fd = ss::relay::open_udp_listener(local_addr, local_port, false, reuse_port != 0);
        if (!udp_fd || !udp_relay.init(tcp_loop, relay_method, udp_config, NULL) || !udp_relay.listen(*udp_fd)) {
            FATAL("failed to initialize UDP relay");
        }
    }

    if (mode == UDP_ONLY) {
        LOGI("TCP relay disabled");
    }

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
    ss::heap_seal();
    {
        int code = program.run();
        if (code != 0)
            ret_val = code;
    }

    if (plugin != NULL) {
        stop_plugin();
    }

    tcp_relay.shutdown();
    udp_relay.shutdown();
    while (!tcp_relay.closed() || !udp_relay.closed()) {
        tcp_loop.run_nowait();
    }
    program.close();

#ifdef __MINGW32__

    winsock_cleanup();
#endif

    if (verbose)
        ss::log_heap_report();

    return ret_val;
}
