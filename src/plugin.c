/*
 * plugin.c - Manage plugins
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

#include <string.h>
#include <errno.h>
#ifndef __MINGW32__
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#endif

#include "ss_process.h"
#include "platform.h"

#include "utils.h"
#include "plugin.h"
#include "ss_windows.h"

#define CMD_RESRV_LEN 128

#ifndef __MINGW32__
#define TEMPDIR "/tmp/"
#else
#define TEMPDIR
#endif

static struct ss_process *sub;
static uint16_t sub_control_port;

static int
start_ss_plugin(const char *plugin,
                const char *plugin_opts,
                const char *remote_host,
                const char *remote_port,
                const char *local_host,
                const char *local_port,
                enum plugin_mode mode)
{
    ss_process_env(sub, "SS_REMOTE_HOST", remote_host);
    ss_process_env(sub, "SS_REMOTE_PORT", remote_port);

    ss_process_env(sub, "SS_LOCAL_HOST", local_host);
    ss_process_env(sub, "SS_LOCAL_PORT", local_port);

    if (plugin_opts != NULL)
        ss_process_env(sub, "SS_PLUGIN_OPTIONS", plugin_opts);

    ss_process_arg(sub, plugin);  // argv[0]

#ifdef __ANDROID__
    extern int vpn;
    if (vpn)
        ss_process_arg(sub, "-V");
#endif



    return ss_process_start(sub, sub_control_port);
}

#define OBFSPROXY_OPTS_MAX  4096
/*
 * For obfsproxy, we use standalone mode for now.
 * Managed mode needs to use SOCKS5 proxy as forwarder, which is not supported
 * yet.
 *
 * The idea of using standalone mode is quite simple, just assemble the
 * internal port into obfsproxy parameters.
 *
 * Using manually ran scramblesuit as an example:
 * obfsproxy \
 * --data-dir /tmp/ss_libev_plugin_with_suffix \
 * scramblesuit \
 * --password SOMEMEANINGLESSPASSWORDASEXAMPLE \
 * --dest some.server.org:12345 \
 * client \
 * 127.0.0.1:54321
 *
 * In above case, @plugin = "obfsproxy",
 * @plugin_opts = "scramblesuit --password SOMEMEANINGLESSPASSWORDASEXAMPLE"
 * For obfs3, it's even easier, just pass @plugin = "obfsproxy"
 * @plugin_opts = "obfs3"
 *
 * And the rest parameters are all assembled here.
 * Some old obfsproxy will not be supported as it doesn't even support
 * "--data-dir" option
 */
static int
start_obfsproxy(const char *plugin,
                const char *plugin_opts,
                const char *remote_host,
                const char *remote_port,
                const char *local_host,
                const char *local_port,
                enum plugin_mode mode)
{
    char *pch;
    char *opts_dump = NULL;
    char *buf = NULL;
    int ret, buf_size = 0;

    if (plugin_opts != NULL) {
        opts_dump = strndup(plugin_opts, OBFSPROXY_OPTS_MAX);
        if (!opts_dump) {
            ERROR("start_obfsproxy strndup failed");
            return -ENOMEM;
        }
    }

    /* The first parameter will be skipped, so pass @plugin again */
    ss_process_arg(sub, plugin);

    ss_process_arg(sub, "--data-dir");
    buf_size = 20 + strlen(plugin) + strlen(remote_host)
               + strlen(remote_port) + strlen(local_host) + strlen(local_port);
    buf = ss_malloc(buf_size);
    snprintf(buf, buf_size, TEMPDIR "%s_%s:%s_%s:%s", plugin,
             remote_host, remote_port, local_host, local_port);
    ss_process_arg(sub, buf);

    /*
     * Iterate @plugin_opts by space
     */
    if (opts_dump != NULL) {
        pch = strtok(opts_dump, " ");
        while (pch) {
            ss_process_arg(sub, pch);
            pch = strtok(NULL, " ");
        }
    }

    /* The rest options */
    if (mode == MODE_CLIENT) {
        /* Client mode */
        ss_process_arg(sub, "--dest");
        snprintf(buf, buf_size, "%s:%s", remote_host, remote_port);
        ss_process_arg(sub, buf);
        ss_process_arg(sub, "client");
        snprintf(buf, buf_size, "%s:%s", local_host, local_port);
        ss_process_arg(sub, buf);
    } else {
        /* Server mode */
        ss_process_arg(sub, "--dest");
        snprintf(buf, buf_size, "%s:%s", local_host, local_port);
        ss_process_arg(sub, buf);
        ss_process_arg(sub, "server");
        snprintf(buf, buf_size, "%s:%s", remote_host, remote_port);
        ss_process_arg(sub, buf);
    }

    ret = ss_process_start(sub, sub_control_port);
    ss_free(opts_dump);
    free(buf);
    return ret;
}

int
start_plugin(const char *plugin,
             const char *plugin_opts,
             const char *remote_host,
             const char *remote_port,
             const char *local_host,
             const char *local_port,
#ifdef __MINGW32__
             uint16_t control_port,
#endif
             enum plugin_mode mode)
{
    int ret;

    if (plugin == NULL)
        return -1;

    if (strlen(plugin) == 0)
        return 0;

    stop_plugin();
    sub = ss_process_new(plugin);
#ifdef __MINGW32__
    sub_control_port = control_port;
#endif

    if (!strncmp(plugin, "obfsproxy", strlen("obfsproxy")))
        ret = start_obfsproxy(plugin, plugin_opts, remote_host, remote_port,
                              local_host, local_port, mode);
    else
        ret = start_ss_plugin(plugin, plugin_opts, remote_host, remote_port,
                              local_host, local_port, mode);
    if (ret != 0) stop_plugin();
    return ret;
}

uint16_t
get_local_port()
{
    int sock = ss_socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port        = 0;
    if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        ss_socket_close(sock);
        return 0;
    }

    socklen_t len = sizeof(serv_addr);
    if (getsockname(sock, (struct sockaddr *)&serv_addr, &len) == -1) {
        ss_socket_close(sock);
        return 0;
    }
    if (ss_socket_close(sock) < 0) {
        return 0;
    }

    return ntohs(serv_addr.sin_port);
}

void
stop_plugin(void)
{
    ss_process_free(sub);
    sub = NULL;
}

int
is_plugin_running(void)
{
    return ss_process_running(sub);
}
