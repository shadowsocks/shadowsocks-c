/*
 * server.c - Provide shadowsocks service
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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>
#include <ctype.h>
#include <limits.h>
#include <dirent.h>
#include <inttypes.h>

#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <pwd.h>
#include <sys/wait.h>
#include "core.h"

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "json.h"
#include "utils.h"
#include "netutils.h"
#include "manager.h"

#ifndef BUF_SIZE
#define BUF_SIZE 65535
#endif

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

int verbose          = 0;
char *executable     = "ss-server";
char *working_dir    = NULL;
size_t working_dir_size = 0;

static struct server *server_table;

static int
copy_port(char *dst, size_t dst_len, const char *src, size_t src_len)
{
    if (dst_len == 0 || src == NULL || src_len == 0 || src_len >= dst_len) {
        return -1;
    }

    for (size_t i = 0; i < src_len; i++) {
        if (!isdigit((unsigned char)src[i])) {
            return -1;
        }
    }

    memcpy(dst, src, src_len);
    dst[src_len] = '\0';

    uint16_t port = 0;
    if (ss_parse_uint16_port(dst, &port) == -1) {
        dst[0] = '\0';
        return -1;
    }

    return 0;
}

static int
setnonblocking(int fd)
{
    int flags;
    if (-1 == (flags = fcntl(fd, F_GETFL, 0))) {
        flags = 0;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static void
destroy_server(struct server *server)
{
// function used to free memories alloced in **get_server**
    if (server->method)
        ss_free(server->method);
    if (server->plugin)
        ss_free(server->plugin);
    if (server->plugin_opts)
        ss_free(server->plugin_opts);
    if (server->mode)
        ss_free(server->mode);
}

static void
write_json_string(FILE *f, const char *str)
{
    const unsigned char *p = (const unsigned char *)str;

    fputc('"', f);
    while (*p) {
        switch (*p) {
        case '"':
            fputs("\\\"", f);
            break;
        case '\\':
            fputs("\\\\", f);
            break;
        case '\b':
            fputs("\\b", f);
            break;
        case '\f':
            fputs("\\f", f);
            break;
        case '\n':
            fputs("\\n", f);
            break;
        case '\r':
            fputs("\\r", f);
            break;
        case '\t':
            fputs("\\t", f);
            break;
        default:
            if (*p < 0x20) {
                fprintf(f, "\\u%04x", *p);
            } else {
                fputc(*p, f);
            }
            break;
        }
        p++;
    }
    fputc('"', f);
}

static int
append_char(char *buf, size_t buf_size, size_t *pos, char ch)
{
    if (*pos >= buf_size - 1) {
        return -1;
    }
    buf[(*pos)++] = ch;
    buf[*pos]     = '\0';
    return 0;
}

static int
append_string(char *buf, size_t buf_size, size_t *pos, const char *str)
{
    while (*str) {
        if (append_char(buf, buf_size, pos, *str++) == -1) {
            return -1;
        }
    }
    return 0;
}

static int
append_json_string(char *buf, size_t buf_size, size_t *pos, const char *str)
{
    const unsigned char *p = (const unsigned char *)str;

    if (append_char(buf, buf_size, pos, '"') == -1) {
        return -1;
    }
    while (*p) {
        char escaped[7];

        switch (*p) {
        case '"':
            if (append_string(buf, buf_size, pos, "\\\"") == -1) {
                return -1;
            }
            break;
        case '\\':
            if (append_string(buf, buf_size, pos, "\\\\") == -1) {
                return -1;
            }
            break;
        case '\b':
            if (append_string(buf, buf_size, pos, "\\b") == -1) {
                return -1;
            }
            break;
        case '\f':
            if (append_string(buf, buf_size, pos, "\\f") == -1) {
                return -1;
            }
            break;
        case '\n':
            if (append_string(buf, buf_size, pos, "\\n") == -1) {
                return -1;
            }
            break;
        case '\r':
            if (append_string(buf, buf_size, pos, "\\r") == -1) {
                return -1;
            }
            break;
        case '\t':
            if (append_string(buf, buf_size, pos, "\\t") == -1) {
                return -1;
            }
            break;
        default:
            if (*p < 0x20) {
                snprintf(escaped, sizeof(escaped), "\\u%04x", *p);
                if (append_string(buf, buf_size, pos, escaped) == -1) {
                    return -1;
                }
            } else if (append_char(buf, buf_size, pos, *p) == -1) {
                return -1;
            }
            break;
        }
        p++;
    }
    return append_char(buf, buf_size, pos, '"');
}

static int
append_list_entry(char *buf, size_t buf_size, size_t *pos,
                  struct server *server, const char *method)
{
    if (append_string(buf, buf_size, pos, "\n\t{\"server_port\":") == -1 ||
        append_json_string(buf, buf_size, pos, server->port) == -1 ||
        append_string(buf, buf_size, pos, ",\"password\":") == -1 ||
        append_json_string(buf, buf_size, pos, server->password) == -1 ||
        append_string(buf, buf_size, pos, ",\"method\":") == -1 ||
        append_json_string(buf, buf_size, pos, method) == -1 ||
        append_string(buf, buf_size, pos, "},") == -1) {
        return -1;
    }
    return 0;
}

static int
prepare_sigchld_for_wait(struct sigaction *old_action)
{
    struct sigaction action;

    if (sigaction(SIGCHLD, NULL, old_action) == -1) {
        ERROR("sigaction");
        return -1;
    }
    if (old_action->sa_handler != SIG_IGN) {
        return 0;
    }

    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) == -1) {
        ERROR("sigaction");
        return -1;
    }
    return 1;
}

static void
restore_sigchld_after_wait(int restore, const struct sigaction *old_action)
{
    if (restore == 1 && sigaction(SIGCHLD, old_action, NULL) == -1) {
        ERROR("sigaction");
    }
}

static int
build_config(char *prefix, struct manager_ctx *manager, struct server *server)
{
    char *path    = NULL;
    int path_size = strlen(prefix) + strlen(server->port) + 20;

    path = ss_malloc(path_size);
    snprintf(path, path_size, "%s/.shadowsocks_%s.conf", prefix, server->port);
    FILE *f = fopen(path, "w+");
    if (f == NULL) {
        if (verbose) {
            LOGE("unable to open config file");
        }
        ss_free(path);
        return -1;
    }
    fprintf(f, "{\n");
    fprintf(f, "\"server_port\":%s,\n", server->port);
    fprintf(f, "\"password\":");
    write_json_string(f, server->password);
    if (server->method) {
        fprintf(f, ",\n\"method\":");
        write_json_string(f, server->method);
    } else if (manager->method) {
        fprintf(f, ",\n\"method\":");
        write_json_string(f, manager->method);
    }
    if (server->fast_open[0])
        fprintf(f, ",\n\"fast_open\": %s", server->fast_open);
    else if (manager->fast_open)
        fprintf(f, ",\n\"fast_open\": true");
    if (server->no_delay[0])
        fprintf(f, ",\n\"no_delay\": %s", server->no_delay);
    else if (manager->no_delay)
        fprintf(f, ",\n\"no_delay\": true");
    if (manager->reuse_port)
        fprintf(f, ",\n\"reuse_port\": true");
    if (server->mode) {
        fprintf(f, ",\n\"mode\":");
        write_json_string(f, server->mode);
    }
    if (server->plugin) {
        fprintf(f, ",\n\"plugin\":");
        write_json_string(f, server->plugin);
    }
    if (server->plugin_opts) {
        fprintf(f, ",\n\"plugin_opts\":");
        write_json_string(f, server->plugin_opts);
    }
    fprintf(f, "\n}\n");
    fclose(f);
    ss_free(path);
    return 0;
}

static int
add_server_arg(char **argv, int *argc, int max_argc, char *arg)
{
    if (*argc >= max_argc - 1) {
        return -1;
    }

    argv[(*argc)++] = arg;
    argv[*argc]     = NULL;
    return 0;
}

static int
start_server_process(struct manager_ctx *manager, struct server *server)
{
    int port;
    int argc = 0;
    int status;
    char *argv[64 + MAX_REMOTE_NUM * 2];
    char *pid_path  = NULL;
    char *conf_path = NULL;
    char nofile[32];
    char mtu[32];
    struct sigaction old_sigchld;
    int restore_sigchld = 0;

    if (ss_parse_int(server->port, 1, UINT16_MAX, &port) == -1) {
        return -1;
    }

    if (build_config(working_dir, manager, server) == -1) {
        return -1;
    }

    int pid_path_size = strlen(working_dir) + strlen(server->port) + 20;
    int conf_path_size = strlen(working_dir) + strlen(server->port) + 20;
    pid_path           = ss_malloc(pid_path_size);
    conf_path          = ss_malloc(conf_path_size);
    snprintf(pid_path, pid_path_size, "%s/.shadowsocks_%d.pid", working_dir, port);
    snprintf(conf_path, conf_path_size, "%s/.shadowsocks_%d.conf", working_dir, port);

    argv[0] = NULL;

    if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), executable) == -1 ||
        add_server_arg(argv, &argc, ARRAY_SIZE(argv), "--manager-address") == -1 ||
        add_server_arg(argv, &argc, ARRAY_SIZE(argv), manager->manager_address) == -1 ||
        add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-f") == -1 ||
        add_server_arg(argv, &argc, ARRAY_SIZE(argv), pid_path) == -1 ||
        add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-c") == -1 ||
        add_server_arg(argv, &argc, ARRAY_SIZE(argv), conf_path) == -1) {
        goto ERROR;
    }

    if (manager->acl != NULL &&
        (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "--acl") == -1 ||
         add_server_arg(argv, &argc, ARRAY_SIZE(argv), manager->acl) == -1)) {
        goto ERROR;
    }
    if (manager->timeout != NULL &&
        (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-t") == -1 ||
         add_server_arg(argv, &argc, ARRAY_SIZE(argv), manager->timeout) == -1)) {
        goto ERROR;
    }

#ifdef HAVE_SETRLIMIT
    if (manager->nofile) {
        snprintf(nofile, sizeof(nofile), "%d", manager->nofile);
        if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-n") == -1 ||
            add_server_arg(argv, &argc, ARRAY_SIZE(argv), nofile) == -1) {
            goto ERROR;
        }
    }
#endif
    if (manager->user != NULL &&
        (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-a") == -1 ||
         add_server_arg(argv, &argc, ARRAY_SIZE(argv), manager->user) == -1)) {
        goto ERROR;
    }
    if (manager->verbose) {
        if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-v") == -1) {
            goto ERROR;
        }
    }
    if (server->mode == NULL && manager->mode == UDP_ONLY) {
        if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-U") == -1) {
            goto ERROR;
        }
    }
    if (server->mode == NULL && manager->mode == TCP_AND_UDP) {
        if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-u") == -1) {
            goto ERROR;
        }
    }
    if (manager->iface &&
        (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-i") == -1 ||
         add_server_arg(argv, &argc, ARRAY_SIZE(argv), manager->iface) == -1)) {
        goto ERROR;
    }
    if (server->fast_open[0] == 0 && manager->fast_open) {
        if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "--fast-open") == -1) {
            goto ERROR;
        }
    }
    if (server->no_delay[0] == 0 && manager->no_delay) {
        if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "--no-delay") == -1) {
            goto ERROR;
        }
    }
    if (manager->ipv6first) {
        if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-6") == -1) {
            goto ERROR;
        }
    }
    if (manager->mtu) {
        snprintf(mtu, sizeof(mtu), "%d", manager->mtu);
        if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "--mtu") == -1 ||
            add_server_arg(argv, &argc, ARRAY_SIZE(argv), mtu) == -1) {
            goto ERROR;
        }
    }
    if (server->plugin == NULL && manager->plugin &&
        (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "--plugin") == -1 ||
         add_server_arg(argv, &argc, ARRAY_SIZE(argv), manager->plugin) == -1)) {
        goto ERROR;
    }
    if (server->plugin_opts == NULL && manager->plugin_opts &&
        (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "--plugin-opts") == -1 ||
         add_server_arg(argv, &argc, ARRAY_SIZE(argv), manager->plugin_opts) == -1)) {
        goto ERROR;
    }
    if (manager->nameservers &&
        (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-d") == -1 ||
         add_server_arg(argv, &argc, ARRAY_SIZE(argv), manager->nameservers) == -1)) {
        goto ERROR;
    }
    for (int i = 0; i < manager->host_num; i++) {
        if (add_server_arg(argv, &argc, ARRAY_SIZE(argv), "-s") == -1 ||
            add_server_arg(argv, &argc, ARRAY_SIZE(argv), manager->hosts[i]) == -1) {
            goto ERROR;
        }
    }

    if (verbose) {
        LOGI("exec: %s", executable);
    }

    restore_sigchld = prepare_sigchld_for_wait(&old_sigchld);
    if (restore_sigchld == -1) {
        goto ERROR;
    }

    pid_t pid = fork();
    if (pid == -1) {
        ERROR("fork");
        goto ERROR;
    }

    if (pid == 0) {
        execvp(argv[0], argv);
        ERROR("execvp");
        _exit(127);
    }

    while (waitpid(pid, &status, 0) == -1) {
        if (errno != EINTR) {
            ERROR("waitpid");
            goto ERROR;
        }
    }

    restore_sigchld_after_wait(restore_sigchld, &old_sigchld);

    ss_free(pid_path);
    ss_free(conf_path);

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    LOGE("server process exited unexpectedly");
    return -1;

ERROR:
    restore_sigchld_after_wait(restore_sigchld, &old_sigchld);
    ss_free(pid_path);
    ss_free(conf_path);
    return -1;
}

static char *
get_data(char *buf, int len)
{
    char *data;
    int pos = 0;

    while (pos < len && buf[pos] != '{')
        pos++;
    if (pos == len) {
        return NULL;
    }
    data = buf + pos - 1;

    return data;
}

static char *
get_action(char *buf, int len)
{
    char *action;
    int pos = 0;

    while (pos < len && isspace((unsigned char)buf[pos]))
        pos++;
    if (pos == len) {
        return NULL;
    }
    action = buf + pos;

    while (pos < len && (!isspace((unsigned char)buf[pos]) && buf[pos] != ':'))
        pos++;
    buf[pos] = '\0';

    return action;
}

static struct server *
get_server(char *buf, int len)
{
    char *data = get_data(buf, len);
    char error_buf[512];

    if (data == NULL) {
        LOGE("No data found");
        return NULL;
    }

    json_settings settings = { 0 };
    json_value *obj        = json_parse_ex(&settings, data, strlen(data), error_buf);

    if (obj == NULL) {
        LOGE("%s", error_buf);
        return NULL;
    }

    struct server *server = ss_malloc(sizeof(struct server));
    memset(server, 0, sizeof(struct server));
    int valid = 1;
    if (obj->type == json_object) {
        int i = 0;
        for (i = 0; i < obj->u.object.length; i++) {
            char *name        = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (strcmp(name, "server_port") == 0) {
                if (value->type == json_string) {
                    if (copy_port(server->port, sizeof(server->port),
                                  value->u.string.ptr,
                                  value->u.string.length) == -1) {
                        LOGE("invalid server_port");
                        valid = 0;
                        break;
                    }
                } else if (value->type == json_integer) {
                    if (value->u.integer <= 0 || value->u.integer > 65535) {
                        LOGE("invalid server_port");
                        valid = 0;
                        break;
                    }
                    snprintf(server->port, sizeof(server->port), "%" PRId64, value->u.integer);
                }
            } else if (strcmp(name, "password") == 0) {
                if (value->type == json_string) {
                    if (value->u.string.length >= sizeof(server->password)) {
                        LOGE("password is too long");
                        valid = 0;
                        break;
                    }
                    memcpy(server->password, value->u.string.ptr, value->u.string.length);
                    server->password[value->u.string.length] = '\0';
                }
            } else if (strcmp(name, "method") == 0) {
                if (value->type == json_string) {
                    server->method = strdup(value->u.string.ptr);
                }
            } else if (strcmp(name, "fast_open") == 0) {
                if (value->type == json_boolean) {
                    strncpy(server->fast_open, (value->u.boolean ? "true" : "false"), 8);
                }
            } else if (strcmp(name, "no_delay") == 0) {
                if (value->type == json_boolean) {
                    strncpy(server->no_delay, (value->u.boolean ? "true" : "false"), 8);
                }
            } else if (strcmp(name, "plugin") == 0) {
                if (value->type == json_string) {
                    server->plugin = strdup(value->u.string.ptr);
                }
            } else if (strcmp(name, "plugin_opts") == 0) {
                if (value->type == json_string) {
                    server->plugin_opts = strdup(value->u.string.ptr);
                }
            } else if (strcmp(name, "mode") == 0) {
                if (value->type == json_string) {
                    server->mode = strdup(value->u.string.ptr);
                }
            } else {
                LOGE("invalid data: %s", data);
                valid = 0;
                break;
            }
        }
    }

    json_value_free(obj);
    if (!valid) {
        destroy_server(server);
        ss_free(server);
        return NULL;
    }
    return server;
}

static int
parse_traffic(char *buf, int len, char *port, uint64_t *traffic)
{
    char *data = get_data(buf, len);
    char error_buf[512];
    json_settings settings = { 0 };
    int found = 0;

    port[0] = '\0';

    if (data == NULL) {
        LOGE("No data found");
        return -1;
    }

    json_value *obj = json_parse_ex(&settings, data, strlen(data), error_buf);
    if (obj == NULL) {
        LOGE("%s", error_buf);
        return -1;
    }

    if (obj->type == json_object) {
        int i = 0;
        for (i = 0; i < obj->u.object.length; i++) {
            char *name        = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (value->type == json_integer) {
                if (value->u.integer < 0 ||
                    copy_port(port, 8, name, obj->u.object.values[i].name_length) == -1) {
                    json_value_free(obj);
                    return -1;
                }
                *traffic = (uint64_t)value->u.integer;
                found    = 1;
            }
        }
    }

    json_value_free(obj);
    return found ? 0 : -1;
}

static int
create_and_bind(const char *host, const char *port, int protocol)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp, *ipv4v6bindall;
    int s, listen_sock = -1;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;                  /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = protocol == IPPROTO_TCP ?
                        SOCK_STREAM : SOCK_DGRAM;   /* We want a TCP or UDP socket */
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = protocol;

    s = getaddrinfo(host, port, &hints, &result);

    if (s != 0) {
        LOGE("getaddrinfo: %s", gai_strerror(s));
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
        listen_sock = ss_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1) {
            continue;
        }

        if (rp->ai_family == AF_INET6) {
            int ipv6only = host ? 1 : 0;
            ss_setsockopt(listen_sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
        }

        int opt = 1;
        ss_setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        ss_setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            ss_socket_close(listen_sock);
            break;
        } else {
            ERROR("bind");
            ss_socket_close(listen_sock);
        }
    }

    if (result != NULL) {
        freeaddrinfo(result);
    }

    if (rp == NULL) {
        LOGE("Could not bind");
        return -1;
    }

    return 0;
}

static int
check_port(struct manager_ctx *manager, struct server *server)
{
    bool both_tcp_udp = manager->mode == TCP_AND_UDP;
    int bind_err      = 0;

    /* try to bind each interface */
    for (int i = 0; i < manager->host_num; i++) {
        LOGI("try to bind interface: %s, port: %s", manager->hosts[i], server->port);

        int tcp_udp_ret;
        if (manager->mode == UDP_ONLY) {
            tcp_udp_ret = create_and_bind(manager->hosts[i], server->port, IPPROTO_UDP);
        } else {
            tcp_udp_ret = create_and_bind(manager->hosts[i], server->port, IPPROTO_TCP);
        }

        int udp_ret = 0;
        if (both_tcp_udp) {
            udp_ret = create_and_bind(manager->hosts[i], server->port, IPPROTO_UDP);
        }

        if (tcp_udp_ret == -1 || udp_ret == -1) {
            bind_err = -1;
            break;
        }
    }

    return bind_err == -1 ? -1 : 0;
}

static int
add_server(struct manager_ctx *manager, struct server *server)
{
    int ret = check_port(manager, server);

    if (ret == -1) {
        LOGE("port is not available, please check.");
        return -1;
    }

    if (start_server_process(manager, server) == -1) {
        ERROR("add_server_process");
        return -1;
    }

    struct server *replaced;
    // NOLINTNEXTLINE(clang-analyzer-core.DivideZero,clang-analyzer-security.ArrayBound): uthash initializes nonzero buckets and hashes the NUL-terminated port within its key length
    HASH_REPLACE_STR(server_table, port, server, replaced);
    if (replaced != NULL) {
        destroy_server(replaced);
        ss_free(replaced);
    }

    return 0;
}

static void
kill_pid_from_file(FILE *f)
{
    char buf[16] = {0};
    int pid;

    if (fgets(buf, sizeof(buf), f) == NULL) {
        return;
    }
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] == '\0') break;
        if (buf[i] == '\r' || buf[i] == '\n') {
            buf[i] = '\0';
            break;
        }
    }
    // Reject malformed pid file content instead of signaling a garbage pid
    if (ss_parse_int(buf, 1, INT_MAX, &pid) == 0) {
        kill(pid, SIGTERM);
    }
}

static void
kill_server(char *prefix, char *pid_file)
{
    char *path = NULL;
    int path_size = strlen(prefix) + strlen(pid_file) + 2;
    path = ss_malloc(path_size);
    snprintf(path, path_size, "%s/%s", prefix, pid_file);
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        if (verbose) {
            LOGE("unable to open pid file");
        }
        ss_free(path);
        return;
    }
    kill_pid_from_file(f);
    fclose(f);
    remove(path);
    ss_free(path);
}

static void
stop_server(char *prefix, char *port)
{
    char *path = NULL;
    int path_size = strlen(prefix) + strlen(port) + 20;
    path = ss_malloc(path_size);
    snprintf(path, path_size, "%s/.shadowsocks_%s.pid", prefix, port);
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        if (verbose) {
            LOGE("unable to open pid file");
        }
        ss_free(path);
        return;
    }
    kill_pid_from_file(f);
    fclose(f);
    ss_free(path);
}

static void
remove_server(char *prefix, char *port)
{
    struct server *old_server = NULL;

    // NOLINTNEXTLINE(clang-analyzer-security.ArrayBound): uthash hashes only strlen(port) bytes; manager ports are validated and NUL-terminated
    HASH_FIND_STR(server_table, port, old_server);

    if (old_server != NULL) {
        HASH_DEL(server_table, old_server);
        destroy_server(old_server);
        ss_free(old_server);
    }

    stop_server(prefix, port);
}

static void
update_stat(char *port, uint64_t traffic)
{
    if (verbose) {
        LOGI("update traffic %" PRIu64 " for port %s", traffic, port);
    }
    struct server *ret;
    // NOLINTNEXTLINE(clang-analyzer-security.ArrayBound): uthash hashes only strlen(port) bytes; manager ports are validated and NUL-terminated
    HASH_FIND_STR(server_table, port, ret);
    if (ret != NULL) {
        struct server *server = (struct server *)ret;
        server->traffic = traffic;
    }
}

static void
manager_recv_cb(SS_P_ ss_io *w, int revents)
{
    struct manager_ctx *manager = (struct manager_ctx *)w;
    socklen_t len;
    ssize_t r;
    struct sockaddr_un claddr;
    char buf[BUF_SIZE];

    memset(buf, 0, BUF_SIZE);

    len = sizeof(struct sockaddr_un);
    r   = recvfrom(manager->fd, buf, BUF_SIZE, 0, (struct sockaddr *)&claddr, &len);
    if (r == -1) {
        ERROR("manager_recvfrom");
        return;
    }

    if (r > BUF_SIZE / 2) {
        LOGE("too large request: %d", (int)r);
        return;
    }

    // properly terminate string which recvfrom does not do
    buf[r] = '\0';

    char *action = get_action(buf, r);
    if (action == NULL) {
        return;
    }

    if (strcmp(action, "add") == 0) {
        struct server *server = get_server(buf, r);

        if (server == NULL || server->port[0] == 0 || server->password[0] == 0) {
            LOGE("invalid command: %s:%s", buf, get_data(buf, r));
            if (server != NULL) {
                destroy_server(server);
                ss_free(server);
            }
            goto ERROR_MSG;
        }

        remove_server(working_dir, server->port);
        int ret = add_server(manager, server);

        char *msg;
        int msg_len;

        if (ret == -1) {
            msg     = "port is not available";
            msg_len = 21;
            destroy_server(server);
            ss_free(server);
        } else {
            msg     = "ok";
            msg_len = 2;
        }

        if (sendto(manager->fd, msg, msg_len, 0, (struct sockaddr *)&claddr, len) != msg_len) {
            ERROR("add_sendto");
        }
    } else if (strcmp(action, "list") == 0) {
        struct server *server, *next;
        char buf[BUF_SIZE];
        memset(buf, 0, BUF_SIZE);
        strcpy(buf, "[");

        HASH_ITER(hh, server_table, server, next) {
            char *method          = server->method ? server->method : manager->method;
            char entry_buf[BUF_SIZE];
            size_t entry_pos      = 0;
            size_t pos            = strlen(buf);

            if (append_list_entry(entry_buf, sizeof(entry_buf), &entry_pos, server, method) == -1) {
                LOGE("list entry is too large");
                continue;
            }
            if (pos >= BUF_SIZE - entry_pos) {
                if (sendto(manager->fd, buf, pos, 0, (struct sockaddr *)&claddr, len)
                    != pos) {
                    ERROR("list_sendto");
                }
                memset(buf, 0, BUF_SIZE);
                pos = 0;
            }
            memcpy(buf + pos, entry_buf, entry_pos + 1);
        }

        size_t pos = strlen(buf);
        strcpy(buf + max(pos - 1, 1), "\n]"); // Remove trailing ","
        pos = strlen(buf);
        if (sendto(manager->fd, buf, pos, 0, (struct sockaddr *)&claddr, len)
            != pos) {
            ERROR("list_sendto");
        }
    } else if (strcmp(action, "remove") == 0) {
        struct server *server = get_server(buf, r);

        if (server == NULL || server->port[0] == 0) {
            LOGE("invalid command: %s:%s", buf, get_data(buf, r));
            if (server != NULL) {
                destroy_server(server);
                ss_free(server);
            }
            goto ERROR_MSG;
        }

        remove_server(working_dir, server->port);
        destroy_server(server);
        ss_free(server);

        char msg[3] = "ok";
        if (sendto(manager->fd, msg, 2, 0, (struct sockaddr *)&claddr, len) != 2) {
            ERROR("remove_sendto");
        }
    } else if (strcmp(action, "stat") == 0) {
        char port[8];
        uint64_t traffic = 0;

        if (parse_traffic(buf, r, port, &traffic) == -1) {
            LOGE("invalid command: %s:%s", buf, get_data(buf, r));
            return;
        }

        update_stat(port, traffic);

    } else if (strcmp(action, "ping") == 0) {
        struct server *server, *next;

        char buf[BUF_SIZE];
        size_t pos = 0;

        memset(buf, 0, BUF_SIZE);
        if (append_string(buf, sizeof(buf), &pos, "stat: {") == -1) {
            goto ERROR_MSG;
        }

        HASH_ITER(hh, server_table, server, next) {
            char entry_buf[64];
            int entry_len = snprintf(entry_buf, sizeof(entry_buf),
                                     "\"%s\":%" PRIu64 ",",
                                     server->port, server->traffic);
            if (entry_len < 0 || (size_t)entry_len >= sizeof(entry_buf)) {
                LOGE("ping entry is too large");
                continue;
            }

            if (pos >= BUF_SIZE - (size_t)entry_len) {
                if (pos > 7) {
                    buf[pos - 1] = '}';
                } else if (append_char(buf, sizeof(buf), &pos, '}') == -1) {
                    goto ERROR_MSG;
                }
                if (sendto(manager->fd, buf, pos, 0, (struct sockaddr *)&claddr, len)
                    != pos) {
                    ERROR("ping_sendto");
                }
                memset(buf, 0, BUF_SIZE);
                pos = 0;
                if (append_string(buf, sizeof(buf), &pos, "stat: {") == -1) {
                    goto ERROR_MSG;
                }
            }

            if (append_string(buf, sizeof(buf), &pos, entry_buf) == -1) {
                LOGE("ping response is too large");
                continue;
            }
        }

        if (pos > 7) {
            buf[pos - 1] = '}';
        } else {
            if (append_char(buf, sizeof(buf), &pos, '}') == -1) {
                goto ERROR_MSG;
            }
        }

        if (sendto(manager->fd, buf, pos, 0, (struct sockaddr *)&claddr, len)
            != pos) {
            ERROR("ping_sendto");
        }
    }

    return;

ERROR_MSG:
    strcpy(buf, "err");
    if (sendto(manager->fd, buf, 3, 0, (struct sockaddr *)&claddr, len) != 3) {
        ERROR("error_sendto");
    }
}

static void
signal_cb(SS_P_ ss_signal *w, int revents)
{
    if (revents & SS_SIGNAL) {
        switch (w->signum) {
        case SIGINT:
        case SIGTERM:
            ss_unloop(SS_A_ SS_UNLOOP_ALL);
        }
    }
}

int
create_server_socket(const char *host, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp, *ipv4v6bindall;
    int s, server_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;               /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_DGRAM;              /* We want a UDP socket */
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; /* For wildcard IP address */
    hints.ai_protocol = IPPROTO_UDP;

    s = getaddrinfo(host, port, &hints, &result);
    if (s != 0) {
        LOGE("getaddrinfo: %s", gai_strerror(s));
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
        server_sock = ss_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (server_sock == -1) {
            continue;
        }

        if (rp->ai_family == AF_INET6) {
            int ipv6only = host ? 1 : 0;
            ss_setsockopt(server_sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only));
        }

        int opt = 1;
        ss_setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        s = bind(server_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        } else {
            ERROR("bind");
        }

        ss_socket_close(server_sock);
    }

    if (result != NULL) {
        freeaddrinfo(result);
    }

    if (rp == NULL) {
        LOGE("cannot bind");
        return -1;
    }

    return server_sock;
}

int
main(int argc, char **argv)
{
    int i, c;
    int pid_flags         = 0;
    char *acl             = NULL;
    char *user            = NULL;
    char *password        = NULL;
    char *timeout         = NULL;
    char *method          = NULL;
    char *pid_path        = NULL;
    char *conf_path       = NULL;
    char *iface           = NULL;
    char *manager_address = NULL;
    char *plugin          = NULL;
    char *plugin_opts     = NULL;
    char *workdir         = NULL;

    int fast_open  = 0;
    int no_delay   = 0;
    int reuse_port = 0;
    int mode       = TCP_ONLY;
    int mtu        = 0;
    int ipv6first  = 0;
    int timeout_secs = 0;

#ifdef HAVE_SETRLIMIT
    static int nofile = 0;
#endif

    int server_num = 0;
    char *server_host[MAX_REMOTE_NUM];

    char *nameservers = NULL;

    jconf_t *conf = NULL;

    static struct option long_options[] = {
        { "fast-open",       no_argument,       NULL, GETOPT_VAL_FAST_OPEN   },
        { "no-delay",        no_argument,       NULL, GETOPT_VAL_NODELAY     },
        { "reuse-port",      no_argument,       NULL, GETOPT_VAL_REUSE_PORT  },
        { "acl",             required_argument, NULL, GETOPT_VAL_ACL         },
        { "manager-address", required_argument, NULL,
          GETOPT_VAL_MANAGER_ADDRESS },
        { "executable",      required_argument, NULL,
          GETOPT_VAL_EXECUTABLE },
        { "mtu",             required_argument, NULL, GETOPT_VAL_MTU         },
        { "plugin",          required_argument, NULL, GETOPT_VAL_PLUGIN      },
        { "plugin-opts",     required_argument, NULL, GETOPT_VAL_PLUGIN_OPTS },
        { "password",        required_argument, NULL, GETOPT_VAL_PASSWORD    },
        { "workdir",         required_argument, NULL, GETOPT_VAL_WORKDIR     },
        { "help",            no_argument,       NULL, GETOPT_VAL_HELP        },
        { NULL,              0,                 NULL, 0                      }
    };

    opterr = 0;

    USE_TTY();

    while ((c = getopt_long(argc, argv, "f:s:l:k:t:m:c:i:d:a:n:D:6huUvA",
                            long_options, NULL)) != -1)
        switch (c) {
        case GETOPT_VAL_REUSE_PORT:
            reuse_port = 1;
            break;
        case GETOPT_VAL_FAST_OPEN:
            fast_open = 1;
            break;
        case GETOPT_VAL_NODELAY:
            no_delay = 1;
            break;
        case GETOPT_VAL_ACL:
            acl = optarg;
            break;
        case GETOPT_VAL_MANAGER_ADDRESS:
            manager_address = optarg;
            break;
        case GETOPT_VAL_EXECUTABLE:
            executable = optarg;
            break;
        case GETOPT_VAL_MTU:
            if (ss_parse_int(optarg, 0, INT_MAX, &mtu) == -1) {
                FATAL("invalid MTU");
            }
            break;
        case GETOPT_VAL_PLUGIN:
            plugin = optarg;
            break;
        case GETOPT_VAL_PLUGIN_OPTS:
            plugin_opts = optarg;
            break;
        case 's':
            if (server_num < MAX_REMOTE_NUM) {
                server_host[server_num++] = optarg;
            }
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
        case 'i':
            iface = optarg;
            break;
        case 'd':
            nameservers = optarg;
            break;
        case 'a':
            user = optarg;
            break;
        case 'u':
            mode = TCP_AND_UDP;
            break;
        case 'U':
            mode = UDP_ONLY;
            break;
        case '6':
            ipv6first = 1;
            break;
        case GETOPT_VAL_WORKDIR:
        case 'D':
            workdir = optarg;
            break;
        case 'v':
            verbose = 1;
            break;
        case GETOPT_VAL_HELP:
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
#ifdef HAVE_SETRLIMIT
        case 'n':
            if (ss_parse_int(optarg, 0, INT_MAX, &nofile) == -1) {
                FATAL("invalid nofile");
            }
            break;
#endif
        case 'A':
            FATAL("One time auth has been deprecated. Try AEAD ciphers instead.");
            break;
        case '?':
            // The option character is not recognized.
            LOGE("Unrecognized option: %s", optarg);
            opterr = 1;
            break;
        }

    if (opterr) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (conf_path != NULL) {
        conf = read_jconf(conf_path);
        if (server_num == 0) {
            server_num = conf->remote_num;
            for (i = 0; i < server_num; i++)
                server_host[i] = conf->remote_addr[i].host;
        }
        if (password == NULL) {
            password = conf->password;
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
        if (fast_open == 0) {
            fast_open = conf->fast_open;
        }
        if (no_delay == 0) {
            no_delay = conf->no_delay;
        }
        if (reuse_port == 0) {
            reuse_port = conf->reuse_port;
        }
        if (nameservers == NULL) {
            nameservers = conf->nameserver;
        }
        if (mode == TCP_ONLY) {
            mode = conf->mode;
        }
        if (mtu == 0) {
            mtu = conf->mtu;
        }
        if (plugin == NULL) {
            plugin = conf->plugin;
        }
        if (plugin_opts == NULL) {
            plugin_opts = conf->plugin_opts;
        }
        if (ipv6first == 0) {
            ipv6first = conf->ipv6_first;
        }
        if (workdir == NULL) {
            workdir = conf->workdir;
        }
        if (acl == NULL) {
            acl = conf->acl;
        }
        if (manager_address == NULL) {
            manager_address = conf->manager_address;
        }
#ifdef HAVE_SETRLIMIT
        if (nofile == 0) {
            nofile = conf->nofile;
        }
#endif
    }

    if (server_num == 0) {
        server_host[server_num++] = "0.0.0.0";
    }

    if (method == NULL) {
        method = "table";
    }

    if (timeout == NULL) {
        timeout = "60";
    }
    if (ss_parse_int(timeout, 1, INT_MAX, &timeout_secs) == -1) {
        FATAL("invalid timeout");
    }
    (void)timeout_secs;

    USE_SYSLOG(argv[0], pid_flags);
    if (pid_flags) {
        daemonize(pid_path);
    }

    if (server_num == 0) {
        usage();
        exit(EXIT_FAILURE);
    }

    if (fast_open == 1) {
#ifdef TCP_FASTOPEN
        LOGI("using tcp fast open");
#else
        LOGE("tcp fast open is not supported by this environment");
#endif
    }

    if (no_delay == 1) {
        LOGI("using tcp no-delay");
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

    struct passwd *pw = getpwuid(getuid());

    if (workdir == NULL || strlen(workdir) == 0) {
        workdir = pw != NULL ? pw->pw_dir : NULL;
        // If home dir is still not defined or set to nologin/nonexistent, fall back to /tmp
        if (workdir == NULL || strlen(workdir) == 0 || strstr(workdir, "nologin") || 
            strstr(workdir, "nonexistent") || strcmp(workdir, "/") == 0) {
            workdir = "/tmp";
        }

        working_dir_size = strlen(workdir) + 15;
        working_dir      = ss_malloc(working_dir_size);
        snprintf(working_dir, working_dir_size, "%s/.shadowsocks", workdir);
    } else {
        working_dir_size = strlen(workdir) + 2;
        working_dir      = ss_malloc(working_dir_size);
        snprintf(working_dir, working_dir_size, "%s", workdir);
    }
    if (working_dir == NULL) {
        FATAL("unable to allocate working directory");
    }
    LOGI("working directory points to %s", working_dir);

    int err = mkdir(working_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    if (err != 0 && errno != EEXIST) {
        ERROR("mkdir");
        ss_free(working_dir);
        FATAL("unable to create working directory");
    }

    if (manager_address == NULL) {
        size_t manager_address_size = strlen(workdir) + 20;
        manager_address = ss_malloc(manager_address_size);
        snprintf(manager_address, manager_address_size, "%s/.ss-manager.socks", workdir);
        LOGI("using the default manager address: %s", manager_address);
    }

    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGABRT, SIG_IGN);

    struct ss_signal sigint_watcher;
    struct ss_signal sigterm_watcher;
    ss_signal_init(&sigint_watcher, signal_cb, SIGINT);
    ss_signal_init(&sigterm_watcher, signal_cb, SIGTERM);
    ss_signal_start(SS_DEFAULT, &sigint_watcher);
    ss_signal_start(SS_DEFAULT, &sigterm_watcher);

    struct manager_ctx manager;
    memset(&manager, 0, sizeof(struct manager_ctx));

    manager.reuse_port      = reuse_port;
    manager.fast_open       = fast_open;
    manager.no_delay        = no_delay;
    manager.verbose         = verbose;
    manager.mode            = mode;
    manager.password        = password;
    manager.timeout         = timeout;
    manager.method          = method;
    manager.iface           = iface;
    manager.acl             = acl;
    manager.user            = user;
    manager.manager_address = manager_address;
    manager.hosts           = server_host;
    manager.host_num        = server_num;
    manager.nameservers     = nameservers;
    manager.mtu             = mtu;
    manager.plugin          = plugin;
    manager.plugin_opts     = plugin_opts;
    manager.ipv6first       = ipv6first;
    manager.workdir         = workdir;
#ifdef HAVE_SETRLIMIT
    manager.nofile = nofile;
#endif

    // initialize ev loop
    struct ss_loop *loop = SS_DEFAULT;

    // Clean up all existed processes
    DIR *dp;
    struct dirent *ep;
    dp = opendir(working_dir);
    if (dp != NULL) {
        while ((ep = readdir(dp)) != NULL) {
            size_t len = strlen(ep->d_name);
            if (len >= 3 && strcmp(ep->d_name + len - 3, "pid") == 0) {
                kill_server(working_dir, ep->d_name);
                if (verbose)
                    LOGI("kill %s", ep->d_name);
            }
        }
        closedir(dp);
    } else {
        ss_free(working_dir);
        FATAL("Couldn't open the directory");
    }

    server_table = NULL;

    if (conf != NULL) {
        for (i = 0; i < conf->port_password_num; i++) {
            struct server *server = ss_malloc(sizeof(struct server));
            memset(server, 0, sizeof(struct server));
            if (copy_port(server->port, sizeof(server->port),
                          conf->port_password[i].port,
                          strlen(conf->port_password[i].port)) == -1) {
                LOGE("invalid port_password port");
                ss_free(server);
                continue;
            }
            if (strlen(conf->port_password[i].password) >= sizeof(server->password)) {
                LOGE("port_password password is too long");
                ss_free(server);
                continue;
            }
            strcpy(server->password, conf->port_password[i].password);
            add_server(&manager, server);
        }
    }

    int sfd;
    ss_addr_t ip_addr = { .host = NULL, .port = NULL };
    parse_addr(manager_address, &ip_addr);

    if (ip_addr.host == NULL || ip_addr.port == NULL) {
        struct sockaddr_un svaddr;
        if (strlen(manager_address) >= sizeof(svaddr.sun_path)) {
            ss_free(working_dir);
            FATAL("manager unix socket path is too long");
        }

        sfd = ss_socket(AF_UNIX, SOCK_DGRAM, 0);       /*  Create server socket */
        if (sfd == -1) {
            ss_free(working_dir);
            FATAL("socket");
        }

        setnonblocking(sfd);

        if (remove(manager_address) == -1 && errno != ENOENT) {
            ERROR("bind");
            ss_free(working_dir);
            exit(EXIT_FAILURE);
        }

        memset(&svaddr, 0, sizeof(struct sockaddr_un));
        svaddr.sun_family = AF_UNIX;
        strncpy(svaddr.sun_path, manager_address, sizeof(svaddr.sun_path) - 1);

        if (bind(sfd, (struct sockaddr *)&svaddr, sizeof(struct sockaddr_un)) == -1) {
            ERROR("bind");
            ss_free(working_dir);
            exit(EXIT_FAILURE);
        }
    } else {
        sfd = create_server_socket(ip_addr.host, ip_addr.port);
        if (sfd == -1) {
            ss_free(working_dir);
            FATAL("socket");
        }
    }

    manager.fd = sfd;
    ss_io_init(&manager.io, manager_recv_cb, manager.fd, SS_READ);
    ss_io_start(loop, &manager.io);

    // start ev loop
    ss_run(loop, 0);

    if (verbose) {
        LOGI("closed gracefully");
    }

    // Clean up
    struct server *server, *next;
    HASH_ITER(hh, server_table, server, next) {
        stop_server(working_dir, server->port);
        HASH_DEL(server_table, server);
        destroy_server(server);
        ss_free(server);
    }

    ss_signal_stop(SS_DEFAULT, &sigint_watcher);
    ss_signal_stop(SS_DEFAULT, &sigterm_watcher);
    ss_free(working_dir);
    free_addr(&ip_addr);

    return 0;
}
