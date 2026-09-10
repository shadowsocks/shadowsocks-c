/*
 * ssurl.c - Parse ss:// server URIs (SIP002 and the legacy form)
 *
 * Copyright (C) 2013 - 2026, Max Lv <max.c.lv@gmail.com>
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
 *
 * Spec: https://shadowsocks.org/guide/sip002.html
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "base64.h"
#include "ssurl.h"
#include "utils.h"

#define SS_URL_SCHEME "ss://"

/* memrchr is a GNU extension and is absent on macOS and the BSDs. */
static const char *
find_last(const char *s, size_t len, char c)
{
    for (size_t i = len; i > 0; i--) {
        if (s[i - 1] == c)
            return s + i - 1;
    }
    return NULL;
}

static char *
str_ndup(const char *s, size_t n)
{
    char *out = ss_malloc(n + 1);

    memcpy(out, s, n);
    out[n] = '\0';
    return out;
}

static int
hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Percent-decode in place semantics: returns a newly allocated string. */
static char *
percent_decode(const char *s, size_t len)
{
    char *out = ss_malloc(len + 1);
    size_t o  = 0;

    for (size_t i = 0; i < len; i++) {
        if (s[i] == '%' && i + 2 < len) {
            int hi = hex_value(s[i + 1]);
            int lo = hex_value(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out[o++] = (char)((hi << 4) | lo);
                i       += 2;
                continue;
            }
        }
        out[o++] = s[i];
    }

    out[o] = '\0';
    return out;
}

/*
 * Base64-decode into a fresh string. Returns NULL if the input is not
 * valid base64. base64_decode accepts both the standard and URL-safe
 * alphabets and stops at padding, so unpadded input works too.
 */
static char *
base64_dup(const char *s, size_t len)
{
    if (len == 0)
        return NULL;

    char *in  = str_ndup(s, len);
    /* decoded output is always shorter than the encoded input */
    uint8_t *out = ss_malloc(len + 1);

    int out_len = base64_decode(out, in, (int)len);
    ss_free(in);

    if (out_len <= 0) {
        ss_free(out);
        return NULL;
    }

    out[out_len] = '\0';
    return (char *)out;
}

/*
 * Split "host:port" and store the parts. Handles the bracketed IPv6 form
 * [::1]:8388. Returns 0 on success.
 */
static int
split_host_port(const char *s, size_t len, ss_url_t *url)
{
    if (len == 0)
        return -1;

    if (s[0] == '[') {
        const char *close = memchr(s, ']', len);
        if (close == NULL)
            return -1;

        size_t host_len = (size_t)(close - s) - 1;
        if (host_len == 0)
            return -1;

        size_t rest = len - (size_t)(close - s) - 1;
        if (rest < 2 || close[1] != ':')
            return -1;

        url->host = str_ndup(s + 1, host_len);
        url->port = str_ndup(close + 2, rest - 1);
        return 0;
    }

    const char *colon = find_last(s, len, ':');
    if (colon == NULL || colon == s)
        return -1;

    size_t host_len = (size_t)(colon - s);
    size_t port_len = len - host_len - 1;
    if (port_len == 0)
        return -1;

    url->host = str_ndup(s, host_len);
    url->port = str_ndup(colon + 1, port_len);
    return 0;
}

/* Split "method:password" into the url fields. Returns 0 on success. */
static int
split_userinfo(const char *s, ss_url_t *url)
{
    const char *colon = strchr(s, ':');

    if (colon == NULL || colon == s || colon[1] == '\0')
        return -1;

    url->method   = str_ndup(s, (size_t)(colon - s));
    url->password = str_ndup(colon + 1, strlen(colon + 1));
    return 0;
}

/*
 * Read the query string. Only "plugin" is meaningful to us; per SIP003 its
 * value is the plugin name, optionally followed by ';' and the options.
 */
static void
parse_query(const char *s, size_t len, ss_url_t *url)
{
    const char *end = s + len;

    while (s < end) {
        const char *amp = memchr(s, '&', (size_t)(end - s));
        const char *pair_end = amp ? amp : end;
        const char *eq = memchr(s, '=', (size_t)(pair_end - s));

        if (eq != NULL) {
            size_t name_len = (size_t)(eq - s);
            if (name_len == 6 && strncmp(s, "plugin", 6) == 0) {
                char *value = percent_decode(eq + 1, (size_t)(pair_end - eq - 1));
                char *semi  = strchr(value, ';');
                if (semi != NULL) {
                    *semi            = '\0';
                    url->plugin_opts = str_ndup(semi + 1, strlen(semi + 1));
                }
                url->plugin = value;
            }
        }

        if (amp == NULL)
            break;
        s = amp + 1;
    }
}

void
ss_url_free(ss_url_t *url)
{
    if (url == NULL)
        return;

    ss_free(url->method);
    ss_free(url->password);
    ss_free(url->host);
    ss_free(url->port);
    ss_free(url->plugin);
    ss_free(url->plugin_opts);
    ss_free(url->tag);
    memset(url, 0, sizeof(*url));
}

int
ss_url_parse(const char *uri, ss_url_t *url)
{
    if (url == NULL)
        return -1;

    memset(url, 0, sizeof(*url));
    if (uri == NULL)
        return -1;

    if (strncasecmp(uri, SS_URL_SCHEME, strlen(SS_URL_SCHEME)) != 0)
        return -1;

    const char *body = uri + strlen(SS_URL_SCHEME);
    size_t body_len  = strlen(body);
    if (body_len == 0)
        return -1;

    /* The fragment is a human-readable tag and is not part of the config. */
    const char *hash = memchr(body, '#', body_len);
    if (hash != NULL) {
        url->tag = percent_decode(hash + 1, body_len - (size_t)(hash - body) - 1);
        body_len = (size_t)(hash - body);
    }

    const char *query = memchr(body, '?', body_len);
    size_t head_len   = query ? (size_t)(query - body) : body_len;

    /*
     * SIP002 keeps the host in the clear, so an '@' separates the encoded
     * userinfo from it. Without one this is the legacy form, where the
     * whole body is a single base64 blob.
     */
    const char *at = find_last(body, head_len, '@');

    if (at != NULL) {
        size_t userinfo_len = (size_t)(at - body);
        if (userinfo_len == 0)
            goto fail;

        /*
         * The userinfo is normally base64, but some producers write
         * "method:password" directly; base64 decoding fails on the ':'
         * so a failed decode simply means the plain form.
         */
        char *userinfo = base64_dup(body, userinfo_len);
        if (userinfo == NULL || strchr(userinfo, ':') == NULL) {
            ss_free(userinfo);
            userinfo = percent_decode(body, userinfo_len);
        }

        int rc = split_userinfo(userinfo, url);
        ss_free(userinfo);
        if (rc != 0)
            goto fail;

        /* A trailing '/' before the query or end is allowed by SIP002. */
        size_t hostport_len = head_len - userinfo_len - 1;
        const char *hostport = at + 1;
        if (hostport_len > 0 && hostport[hostport_len - 1] == '/')
            hostport_len--;

        if (split_host_port(hostport, hostport_len, url) != 0)
            goto fail;
    } else {
        char *plain = base64_dup(body, head_len);
        if (plain == NULL)
            goto fail;

        char *sep = strrchr(plain, '@');
        if (sep == NULL) {
            ss_free(plain);
            goto fail;
        }
        *sep = '\0';

        int rc = split_userinfo(plain, url);
        if (rc == 0)
            rc = split_host_port(sep + 1, strlen(sep + 1), url);
        ss_free(plain);
        if (rc != 0)
            goto fail;
    }

    if (query != NULL) {
        size_t query_ofst = (size_t)(query - body) + 1;
        parse_query(body + query_ofst, body_len - query_ofst, url);
    }

    return 0;

fail:
    ss_url_free(url);
    return -1;
}
