/*
 * acl.c - Manage the ACL (Access Control List)
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

#include <ctype.h>
#include <string.h>

#include "ipset.h"
#include "core.h"

#include "rule.h"
#include "netutils.h"
#include "utils.h"
#include "acl.h"

static struct ss_ipset white_list_ipv4;
static struct ss_ipset white_list_ipv6;

static struct ss_ipset black_list_ipv4;
static struct ss_ipset black_list_ipv6;

static struct ss_list black_list_rules;
static struct ss_list white_list_rules;

static int acl_mode = BLACK_LIST;

static struct ss_ipset outbound_block_list_ipv4;
static struct ss_ipset outbound_block_list_ipv6;
static struct ss_list outbound_block_list_rules;

static int
parse_addr_cidr(const char *str, char *host, size_t host_len, int *cidr)
{
    int ret = -1;
    const char *pch;
    size_t addr_len;

    if (host_len == 0) {
        return -1;
    }

    pch = strchr(str, '/');
    while (pch != NULL) {
        ret = pch - str;
        pch = strchr(pch + 1, '/');
    }
    addr_len = ret == -1 ? strlen(str) : (size_t)ret;
    if (addr_len >= host_len) {
        return -1;
    }

    if (ret == -1) {
        memcpy(host, str, addr_len);
        host[addr_len] = '\0';
        *cidr = -1;
    } else {
        memcpy(host, str, addr_len);
        host[addr_len] = '\0';
        if (ss_parse_int(str + ret + 1, 0, 128, cidr) == -1) {
            *cidr = -2;
        }
    }

    return 0;
}

char *
trimwhitespace(char *str)
{
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0)   // All spaces?
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    // Write new null terminator
    *(end + 1) = 0;

    return str;
}

int
init_acl(const char *path)
{
    if (path == NULL) {
        return -1;
    }

    // initialize ipset

    ss_ipset_clear(&white_list_ipv4);
    ss_ipset_clear(&white_list_ipv6);
    ss_ipset_clear(&black_list_ipv4);
    ss_ipset_clear(&black_list_ipv6);
    ss_ipset_clear(&outbound_block_list_ipv4);
    ss_ipset_clear(&outbound_block_list_ipv6);

    ss_list_init(&black_list_rules);
    ss_list_init(&white_list_rules);
    ss_list_init(&outbound_block_list_rules);

    struct ss_ipset *list_ipv4  = &black_list_ipv4;
    struct ss_ipset *list_ipv6  = &black_list_ipv6;
    struct ss_list *rules = &black_list_rules;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        LOGE("Invalid acl path.");
        return -1;
    }

    char buf[MAX_HOSTNAME_LEN];

    while (!ferror(f) && !feof(f) && fgets(buf, sizeof(buf), f) != NULL) {
            // Discards the whole line if longer than 255 characters
            int long_line = 0;  // 1: Long  2: Error
            while ((strlen(buf) == 255) && (buf[254] != '\n')) {
                long_line = 1;
                LOGE("Discarding long ACL content: %s", buf);
                if (fgets(buf, 256, f) == NULL) {
                    long_line = 2;
                    break;
                }
            }
            if (long_line) {
                if (long_line == 1) {
                    LOGE("Discarding long ACL content: %s", buf);
                }
                continue;
            }

            // Trim the newline
            int len = strlen(buf);
            if (len > 0 && buf[len - 1] == '\n') {
                buf[len - 1] = '\0';
            }

            char *comment = strchr(buf, '#');
            if (comment) {
                *comment = '\0';
            }

            char *line = trimwhitespace(buf);
            if (strlen(line) == 0) {
                continue;
            }

            if (strcmp(line, "[outbound_block_list]") == 0) {
                list_ipv4 = &outbound_block_list_ipv4;
                list_ipv6 = &outbound_block_list_ipv6;
                rules     = &outbound_block_list_rules;
                continue;
            } else if (strcmp(line, "[black_list]") == 0
                       || strcmp(line, "[bypass_list]") == 0) {
                list_ipv4 = &black_list_ipv4;
                list_ipv6 = &black_list_ipv6;
                rules     = &black_list_rules;
                continue;
            } else if (strcmp(line, "[white_list]") == 0
                       || strcmp(line, "[proxy_list]") == 0) {
                list_ipv4 = &white_list_ipv4;
                list_ipv6 = &white_list_ipv6;
                rules     = &white_list_rules;
                continue;
            } else if (strcmp(line, "[reject_all]") == 0
                       || strcmp(line, "[bypass_all]") == 0) {
                acl_mode = WHITE_LIST;
                continue;
            } else if (strcmp(line, "[accept_all]") == 0
                       || strcmp(line, "[proxy_all]") == 0) {
                acl_mode = BLACK_LIST;
                continue;
            }

            char host[MAX_HOSTNAME_LEN];
            int cidr;
            if (parse_addr_cidr(line, host, sizeof(host), &cidr) == -1) {
                LOGE("invalid ACL entry: %s", line);
                continue;
            }

            struct ss_ip addr;
            int err = ss_ip_init(&addr, host);
            if (!err) {
                if (addr.version == 4) {
                    if (cidr > 32 || cidr == -2) {
                        LOGE("invalid ACL IPv4 CIDR: %s", line);
                        continue;
                    }
                    if (cidr >= 0) {
                        ss_ipset_assign(list_ipv4, addr.bytes, 32, (unsigned)cidr, true);
                    } else {
                        ss_ipset_assign(list_ipv4, addr.bytes, 32, 32, true);
                    }
                } else if (addr.version == 6) {
                    if (cidr > 128 || cidr == -2) {
                        LOGE("invalid ACL IPv6 CIDR: %s", line);
                        continue;
                    }
                    if (cidr >= 0) {
                        ss_ipset_assign(list_ipv6, addr.bytes, 128, (unsigned)cidr, true);
                    } else {
                        ss_ipset_assign(list_ipv6, addr.bytes, 128, 128, true);
                    }
                }
            } else {
                rule_t *rule = new_rule();
                if (rule == NULL) {
                    continue;
                }
                int status = accept_rule_arg(rule, line);
                if (status == 1) status = init_rule(rule);
                if (status < 0) {
                    free_rule(rule);
                    fclose(f);
                    free_acl();
                    return -1;
                }
                if (status != 1) {
                    free_rule(rule);
                    continue;
                }
                add_rule(rules, rule);
            }
        }

    int failed = ferror(f);
    fclose(f);
    if (failed) {
        free_acl();
        return -1;
    }
    return 0;
}

void
free_rules(struct ss_list *rules)
{
    struct ss_list_item *iter;
    while ((iter = ss_list_head(rules)) != NULL) {
        rule_t *rule = ss_container_of(iter, rule_t, entries);
        remove_rule(rule);
    }
}

void
free_acl(void)
{
    ss_ipset_clear(&black_list_ipv4);
    ss_ipset_clear(&black_list_ipv6);
    ss_ipset_clear(&white_list_ipv4);
    ss_ipset_clear(&white_list_ipv6);
    ss_ipset_clear(&outbound_block_list_ipv4);
    ss_ipset_clear(&outbound_block_list_ipv6);

    free_rules(&black_list_rules);
    free_rules(&white_list_rules);
    free_rules(&outbound_block_list_rules);
}

int
get_acl_mode(void)
{
    return acl_mode;
}

/*
 * Return 0,  if not match.
 * Return 1,  if match black list.
 * Return -1, if match white list.
 */
int
acl_match_host(const char *host)
{
    struct ss_ip addr;
    int ret = 0;
    int err = ss_ip_init(&addr, host);

    if (err) {
        int host_len = strlen(host);
        if (lookup_rule(&black_list_rules, host, host_len) != NULL)
            ret = 1;
        else if (lookup_rule(&white_list_rules, host, host_len) != NULL)
            ret = -1;
        return ret;
    }

    if (addr.version == 4) {
        if (ss_ipset_contains(&black_list_ipv4, addr.bytes, 32))
            ret = 1;
        else if (ss_ipset_contains(&white_list_ipv4, addr.bytes, 32))
            ret = -1;
    } else if (addr.version == 6) {
        if (ss_ipset_contains(&black_list_ipv6, addr.bytes, 128))
            ret = 1;
        else if (ss_ipset_contains(&white_list_ipv6, addr.bytes, 128))
            ret = -1;
    }

    return ret;
}

int
acl_add_ip(const char *ip)
{
    struct ss_ip addr;
    int err = ss_ip_init(&addr, ip);
    if (err) {
        return -1;
    }

    if (addr.version == 4) {
        ss_ipset_assign(&black_list_ipv4, addr.bytes, 32, 32, true);
    } else if (addr.version == 6) {
        ss_ipset_assign(&black_list_ipv6, addr.bytes, 128, 128, true);
    }

    return 0;
}

int
acl_remove_ip(const char *ip)
{
    struct ss_ip addr;
    int err = ss_ip_init(&addr, ip);
    if (err) {
        return -1;
    }

    if (addr.version == 4) {
        ss_ipset_assign(&black_list_ipv4, addr.bytes, 32, 32, false);
    } else if (addr.version == 6) {
        ss_ipset_assign(&black_list_ipv6, addr.bytes, 128, 128, false);
    }

    return 0;
}

/*
 * Return 0,  if not match.
 * Return 1,  if match black list.
 */
int
outbound_block_match_host(const char *host)
{
    struct ss_ip addr;
    int ret = 0;
    int err = ss_ip_init(&addr, host);

    if (err) {
        int host_len = strlen(host);
        if (lookup_rule(&outbound_block_list_rules, host, host_len) != NULL)
            ret = 1;
        return ret;
    }

    if (addr.version == 4) {
        if (ss_ipset_contains(&outbound_block_list_ipv4, addr.bytes, 32))
            ret = 1;
    } else if (addr.version == 6) {
        if (ss_ipset_contains(&outbound_block_list_ipv6, addr.bytes, 128))
            ret = 1;
    }

    return ret;
}
