/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <stdint.h>
#include "plugin.h"
#include "utils.h"
int
start_plugin(const char *plugin, const char *options, const char *remote_host,
             const char *remote_port, const char *local_host, const char *local_port,
#ifdef __MINGW32__
             uint16_t control_port,
#endif
             enum plugin_role role)
{
    (void)plugin; (void)options; (void)remote_host; (void)remote_port;
    (void)local_host; (void)local_port; (void)role;
#ifdef __MINGW32__
    (void)control_port;
#endif
    LOGE("Plugin support is disabled in this build");
    return -1;
}
void set_plugin_user(const char *user) { (void)user; }
uint16_t get_local_port(int with_udp)
{
    (void)with_udp;
    FATAL("Plugin support is disabled in this build");
    return 0;
}
void stop_plugin(void) {}
int is_plugin_running(void) { return 0; }
