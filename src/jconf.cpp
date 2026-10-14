/*
 * jconf.c - Parse the JSON format config file
 *
 * Copyright (C) 2013 - 2019, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <limits.h>

#include "netutils.h"
#include "utils.h"
#include "jconf.h"
#include "json.h"
#include "string.h"

#include "core.h"
#include "core/arena.hpp"

#include <memory>
#include <new>
#include <string_view>

#define check_json_value_type(value, expected_type, message) \
    do { \
        if ((value)->type != (expected_type)) \
            FATAL((message)); \
    } while (0)

/*
 * The parsed configuration lives as long as the process, so its strings come
 * from one arena reserved when the file is read. The file text and the JSON
 * tree use a second, scratch arena that is released before read_jconf
 * returns. Nothing here goes back to malloc per string.
 */
namespace {

alignas(ss::MonotonicArena) unsigned char conf_arena_storage[sizeof(ss::MonotonicArena)];
ss::MonotonicArena *conf_arena;

// The arena is never destroyed: callers keep jconf_t pointers until exit.
ss::MonotonicArena &
config_arena(std::size_t bytes)
{
    if (conf_arena == nullptr) {
        conf_arena = ::new (conf_arena_storage) ss::MonotonicArena(); // heap-ok: placement into static storage
    } else {
        // A second read_jconf replaces the previous result (conf is static).
        *conf_arena = ss::MonotonicArena();
    }
    if (!conf_arena->reserve(bytes)) {
        FATAL("No enough memory.");
    }
    return *conf_arena;
}

char *
conf_strndup(std::string_view text)
{
    auto copy = conf_arena->intern(text);
    if (!copy) {
        FATAL("No enough memory.");
    }
    return const_cast<char *>(copy->data());
}

// json-parser's allocator hooks. The scratch Region is calloc'ed and never
// reused within one parse, so `zero` already holds.
void *
scratch_alloc(size_t size, int, void *user)
{
    auto bytes = static_cast<ss::MonotonicArena *>(user)->allocate(size);
    return bytes ? bytes->data() : nullptr;
}

void
scratch_free(void *, void *)
{
}

struct AddrParts {
    std::string_view host;
    std::string_view port; // empty when there is none
};

// Split "host", "host:port", "[v6]" or "[v6]:port". IPv6 literals without
// brackets and anything else with several colons stay whole.
AddrParts
split_addr(const char *str)
{
    // Plain pointer arithmetic: string_view::substr can throw out_of_range,
    // which would pull in the C++ runtime.
    std::string_view text(str);
    auto slice = [&](std::size_t from, std::size_t to) { return std::string_view(str + from, to - from); };
    struct ss_ip ip;
    if (ss_ip_init(&ip, str) != -1) {
        return { text, {} };
    }
    if (text.front() == '[') {
        auto end = text.find(']');
        if (end == std::string_view::npos) {
            return { text, {} };
        }
        AddrParts parts{ slice(1, end), {} };
        if (end + 1 < text.size() && text[end + 1] == ':') {
            parts.port = slice(end + 2, text.size());
        }
        return parts;
    }
    auto colon = text.find(':');
    if (colon == std::string_view::npos || text.find(':', colon + 1) != std::string_view::npos) {
        return { text, {} };
    }
    return { slice(0, colon), slice(colon + 1, text.size()) };
}

void
parse_conf_addr(const char *str, ss_addr_t *addr)
{
    if (str == NULL) {
        return;
    }
    AddrParts parts = *str == '\0' ? AddrParts{} : split_addr(str);
    addr->host = conf_strndup(parts.host);
    addr->port = parts.port.empty() ? NULL : conf_strndup(parts.port);
}

} // namespace

static char *
to_string(const json_value *value)
{
    if (value->type == json_string) {
        return conf_strndup(std::string_view(value->u.string.ptr, value->u.string.length));
    } else if (value->type == json_integer) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%" PRId64, value->u.integer);
        return conf_strndup(buf);
    } else if (value->type == json_null) {
        return NULL;
    } else {
        LOGE("%d", value->type);
        FATAL("Invalid config format.");
    }
    return 0;
}

static int
to_nonnegative_int(const json_value *value, const char *option)
{
    check_json_value_type(value, json_integer,
                          "invalid config file: option must be an integer");
    if (value->u.integer < 0 || value->u.integer > INT_MAX) {
        LOGE("invalid config file: option '%s' is out of range", option);
        FATAL("invalid config file: integer option is out of range");
    }
    return (int)value->u.integer;
}

void
free_addr(ss_addr_t *addr)
{
    ss_free(addr->host);
    ss_free(addr->port);
}

void
parse_addr(const char *str_in, ss_addr_t *addr)
{
    if (str_in == NULL)
        return;
    if (*str_in == '\0') {
        addr->host = strdup(str_in);
        addr->port = NULL;
        return;
    }
    AddrParts parts = split_addr(str_in);
    addr->host = ss_strndup(parts.host.data(), parts.host.size());
    addr->port = parts.port.empty() ? NULL : ss_strndup(parts.port.data(), parts.port.size());
}

/* CLI endpoints are strict; keep the legacy JSON address parser unchanged. */
int
parse_server_endpoint(const char *str, ss_addr_t *addr)
{
    ss_addr_t parsed = { 0 };
    uint16_t port;
    if (str == NULL || *str == '\0')
        return -1;
    for (const char *p = str; *p; p++) {
        if ((unsigned char)*p <= ' ' || *p == '/' || *p == '@')
            return -1;
    }
    parse_addr(str, &parsed);
    if (parsed.host == NULL || *parsed.host == '\0')
        goto invalid;
    if (str[0] == '[') {
        const char *end = strchr(str, ']');
        if (end == NULL || (end[1] != '\0' && end[1] != ':')
            || (end[1] == ':' && end[2] == '\0'))
            goto invalid;
    } else if (strchr(str, '[') || strchr(str, ']')) {
        goto invalid;
    }
    if (str[0] == '[' || strchr(parsed.host, ':')) {
        /* Validate IPv6 separately from an optional interface scope ID. */
        struct ss_ip ip;
        char *literal = strdup(parsed.host);
        char *scope = strchr(literal, '%');
        int valid_scope = 1;
        if (scope != NULL) {
            *scope++ = '\0';
            valid_scope = *scope != '\0';
            for (const char *p = scope; *p; p++) {
                if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
                      || (*p >= '0' && *p <= '9') || *p == '_' || *p == '-' || *p == '.'))
                    valid_scope = 0;
            }
        }
        int valid = strchr(literal, ':') != NULL && ss_ip_init(&ip, literal) != -1;
        free(literal);
        if (!valid || !valid_scope)
            goto invalid;
    } else if (strchr(parsed.host, '%')) {
        goto invalid;
    }
    if (parsed.port != NULL) {
        if (ss_parse_uint16_port(parsed.port, &port) != 0)
            goto invalid;
        for (const char *p = parsed.port; *p; p++) {
            if (*p < '0' || *p > '9')
                goto invalid;
        }
    } else if (str[strlen(str) - 1] == ':' && !strchr(parsed.host, ':')) {
        goto invalid;
    }
    *addr = parsed;
    return 0;
invalid:
    free_addr(&parsed);
    return -1;
}

/* Resolve fallback ports before callers reuse the first port for SIP003. */
int
complete_server_ports(ss_addr_t *addr, int count, const char *fallback, int plugin)
{
    uint16_t first = 0;
    if (count == 0)
        return -1;
    for (int i = 0; i < count; i++) {
        uint16_t port;
        const char *value = addr[i].port != NULL ? addr[i].port : fallback;
        if (value == NULL || ss_parse_uint16_port(value, &port) != 0)
            return -1;
        if (plugin && i > 0 && port != first)
            return -1;
        if (i == 0)
            first = port;
    }
    for (int i = 0; i < count; i++) {
        if (addr[i].port == NULL)
            addr[i].port = strdup(fallback);
    }
    return 0;
}

static int
parse_dscp(char *str)
{
    size_t str_len = strlen(str);

    // Pre-defined values (EF, CSx, AFxy)
    if (str_len == 2 && strcasecmp(str, "EF") == 0) {
        return DSCP_EF;
    }

    if (str_len == DSCP_CS_LEN && strncasecmp(str, "CS", 2) == 0) {
        if (str[2] >= '0' && str[2] <= '7') {
            // CSx = 8x
            return (str[2] - '0') << 3;
        }
    }

    if (str_len == DSCP_AF_LEN && strncasecmp(str, "AF", 2) == 0) {
        if (str[2] >= '1' && str[2] <= '4' && str[3] >= '1' && str[3] <= '3') {
            // AFxy = 8x + 2y
            return ((str[2] - '0') << 3) | ((str[3] - '0') << 1);
        }
    }

    // Manual hexadecimal mode (0xYZ)
    char *endptr;
    int dscp = (int)strtol(str, &endptr, 0);
    if (*endptr == '\0' && dscp >= DSCP_MIN && dscp <= DSCP_MAX) {
        return dscp;
    }

    LOGE("Invalid DSCP value (%s)", str);
    return DSCP_DEFAULT;
}

jconf_t *
read_jconf(const char *file)
{
    static jconf_t conf;

    memset(&conf, 0, sizeof(jconf_t));

    json_value *obj;

    FILE *f = fopen(file, "rb");
    if (f == NULL) {
        FATAL("Invalid config path.");
    }

    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (pos < 0) {
        FATAL("Invalid config path.");
    }

    if (pos >= MAX_CONF_SIZE) {
        FATAL("Too large config file.");
    }

    // Every string kept in conf copies part of the file plus a NUL: a JSON
    // string or key, an integer printed back in decimal, or the two halves of
    // an address (whose unsplit copy is kept too). 16x the file size is a
    // comfortable bound.
    std::size_t len = static_cast<std::size_t>(pos);
    config_arena(16 * len + 4096);

    // json-parser needs a json_value (and an array or object slot) for every
    // value, each costing at least one byte of input.
    ss::MonotonicArena scratch;
    if (!scratch.reserve(len + 1 + 128 * (len + 1))) {
        FATAL("No enough memory.");
    }
    char *buf = reinterpret_cast<char *>(scratch.allocate(len + 1, 1)->data());

    if (len > 0 && fread(buf, len, 1, f) != 1) {
        FATAL("Failed to read the config file.");
    }
    fclose(f);

    buf[len] = '\0'; // end of string

    json_settings settings = { 0UL, 0, scratch_alloc, scratch_free, &scratch, 0 };
    char error_buf[512];
    obj = json_parse_ex(&settings, buf, len, error_buf);

    if (obj == NULL) {
        FATAL(error_buf);
    }

    if (obj->type == json_object) {
        unsigned int i, j;
        for (i = 0; i < obj->u.object.length; i++) {
            char *name        = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (strcmp(name, "server") == 0) {
                if (value->type == json_array) {
                    for (j = 0; j < value->u.array.length; j++) {
                        if (j >= MAX_REMOTE_NUM) {
                            break;
                        }
                        json_value *v  = value->u.array.values[j];
                        parse_conf_addr(to_string(v), conf.remote_addr + j);
                        conf.remote_num = j + 1;
                    }
                } else if (value->type == json_string) {
                    parse_conf_addr(to_string(value), conf.remote_addr);
                    conf.remote_num = 1;
                }
            } else if (strcmp(name, "port_password") == 0) {
                if (value->type == json_object) {
                    for (j = 0; j < value->u.object.length; j++) {
                        if (j >= MAX_PORT_NUM) {
                            break;
                        }
                        json_value *v = value->u.object.values[j].value;
                        if (v->type == json_string) {
                            conf.port_password[j].port = conf_strndup(
                                std::string_view(value->u.object.values[j].name, value->u.object.values[j].name_length));
                            conf.port_password[j].password = to_string(v);
                            conf.port_password_num         = j + 1;
                        }
                    }
                }
            } else if (strcmp(name, "server_port") == 0) {
                conf.remote_port = to_string(value);
            } else if (strcmp(name, "local_address") == 0) {
                conf.local_addr = to_string(value);
            } else if (strcmp(name, "local_ipv4_address") == 0) {
                conf.local_addr_v4 = to_string(value);
            } else if (strcmp(name, "local_ipv6_address") == 0) {
                conf.local_addr_v6 = to_string(value);
            } else if (strcmp(name, "local_port") == 0) {
                conf.local_port = to_string(value);
            } else if (strcmp(name, "password") == 0) {
                conf.password = to_string(value);
            } else if (strcmp(name, "key") == 0) {
                conf.key = to_string(value);
            } else if (strcmp(name, "method") == 0) {
                conf.method = to_string(value);
            } else if (strcmp(name, "timeout") == 0) {
                conf.timeout = to_string(value);
            } else if (strcmp(name, "user") == 0) {
                conf.user = to_string(value);
            } else if (strcmp(name, "plugin") == 0) {
                conf.plugin = to_string(value);
                if (conf.plugin && strlen(conf.plugin) == 0) {
                    conf.plugin = NULL;
                }
            } else if (strcmp(name, "plugin_opts") == 0) {
                conf.plugin_opts = to_string(value);
            } else if (strcmp(name, "fast_open") == 0) {
                check_json_value_type(value, json_boolean,
                                      "invalid config file: option 'fast_open' must be a boolean");
                conf.fast_open = value->u.boolean;
            } else if (strcmp(name, "reuse_port") == 0) {
                check_json_value_type(value, json_boolean,
                                      "invalid config file: option 'reuse_port' must be a boolean");
                conf.reuse_port = value->u.boolean;
            } else if (strcmp(name, "tcp_incoming_sndbuf") == 0) {
                conf.tcp_incoming_sndbuf = to_nonnegative_int(value, name);
            } else if (strcmp(name, "tcp_incoming_rcvbuf") == 0) {
                conf.tcp_incoming_rcvbuf = to_nonnegative_int(value, name);
            } else if (strcmp(name, "tcp_outgoing_sndbuf") == 0) {
                conf.tcp_outgoing_sndbuf = to_nonnegative_int(value, name);
            } else if (strcmp(name, "tcp_outgoing_rcvbuf") == 0) {
                conf.tcp_outgoing_rcvbuf = to_nonnegative_int(value, name);
            } else if (strcmp(name, "auth") == 0) {
                FATAL("One time auth has been deprecated. Try AEAD ciphers instead.");
            } else if (strcmp(name, "max_connections") == 0) {
                conf.max_connections = to_nonnegative_int(value, name);
            } else if (strcmp(name, "max_udp_sessions") == 0) {
                conf.max_udp_sessions = to_nonnegative_int(value, name);
            } else if (strcmp(name, "max_dns_queries") == 0) {
                conf.max_dns_queries = to_nonnegative_int(value, name);
            } else if (strcmp(name, "nofile") == 0) {
                conf.nofile = to_nonnegative_int(value, name);
            } else if (strcmp(name, "nameserver") == 0) {
                conf.nameserver = to_string(value);
            } else if (strcmp(name, "dscp") == 0) {
                if (value->type == json_object) {
                    for (j = 0; j < value->u.object.length; j++) {
                        if (j >= MAX_DSCP_NUM) {
                            break;
                        }
                        json_value *v = value->u.object.values[j].value;
                        if (v->type == json_string) {
                            char *dscp_str = to_string(v);
                            int dscp   = parse_dscp(dscp_str);
                            char *port = conf_strndup(std::string_view(value->u.object.values[j].name,
                                                                       value->u.object.values[j].name_length));
                            conf.dscp[j].port = port;
                            conf.dscp[j].dscp = dscp;
                            conf.dscp_num     = j + 1;
                        }
                    }
                }
            } else if (strcmp(name, "tunnel_address") == 0) {
                conf.tunnel_address = to_string(value);
            } else if (strcmp(name, "mode") == 0) {
                char *mode_str = to_string(value);

                if (mode_str == NULL)
                    conf.mode = TCP_ONLY;
                else if (strcmp(mode_str, "tcp_only") == 0)
                    conf.mode = TCP_ONLY;
                else if (strcmp(mode_str, "tcp_and_udp") == 0)
                    conf.mode = TCP_AND_UDP;
                else if (strcmp(mode_str, "udp_only") == 0)
                    conf.mode = UDP_ONLY;
                else
                    LOGI("ignore unknown mode: %s, use tcp_only as fallback",
                         mode_str);

            } else if (strcmp(name, "mtu") == 0) {
                conf.mtu = to_nonnegative_int(value, name);
            } else if (strcmp(name, "mptcp") == 0) {
                check_json_value_type(value, json_boolean,
                                      "invalid config file: option 'mptcp' must be a boolean");
                conf.mptcp = get_mptcp(value->u.boolean);
            } else if (strcmp(name, "ipv6_first") == 0) {
                check_json_value_type(value, json_boolean,
                                      "invalid config file: option 'ipv6_first' must be a boolean");
                conf.ipv6_first = value->u.boolean;
#ifdef HAS_SYSLOG
            } else if (strcmp(name, "use_syslog") == 0) {
                check_json_value_type(value, json_boolean,
                                      "invalid config file: option 'use_syslog' must be a boolean");
                use_syslog = value->u.boolean;
#endif
            } else if (strcmp(name, "no_delay") == 0) {
                check_json_value_type(
                    value, json_boolean,
                    "invalid config file: option 'no_delay' must be a boolean");
                conf.no_delay = value->u.boolean;
            } else if (strcmp(name, "printable_salt") == 0) {
                check_json_value_type(
                    value, json_boolean,
                    "invalid config file: option 'printable_salt' must be a boolean");
                conf.printable_salt = value->u.boolean;
            } else if (strcmp(name, "tcp_tproxy") == 0) {
                check_json_value_type(
                    value, json_boolean,
                    "invalid config file: option 'tcp_tproxy' must be a boolean");
                conf.tcp_tproxy = value->u.boolean;
            } else if (strcmp(name, "workdir") == 0) {
                conf.workdir = to_string(value);
            } else if (strcmp(name, "acl") == 0) {
                conf.acl = to_string(value);
            } else if (strcmp(name, "manager_address") == 0) {
                conf.manager_address = to_string(value);
            }
        }
    } else {
        FATAL("Invalid config file");
    }

    // The tree and the file text go with the scratch arena.
    return &conf;
}
