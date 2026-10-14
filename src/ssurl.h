/*
 * ssurl.h - Parse ss:// server URIs (SIP002 and the legacy form)
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
 */

#ifndef _SSURL_H
#define _SSURL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A parsed ss:// URI. Every field is heap-allocated and owned by the
 * struct; release them all with ss_url_free(). Fields that the URI did not
 * carry are NULL.
 */
typedef struct ss_url {
    char *method;
    char *password;
    char *host;
    char *port;
    char *plugin;
    char *plugin_opts;
    char *tag;
} ss_url_t;

/*
 * Parse an ss:// URI in either the SIP002 form
 *
 *     ss://base64url(method:password)@host:port/?plugin=name;opts#tag
 *
 * or the legacy form
 *
 *     ss://base64(method:password@host:port)#tag
 *
 * Returns 0 on success, -1 if the URI is malformed. On failure nothing is
 * allocated and *url is left zeroed.
 */
int ss_url_parse(const char *uri, ss_url_t *url);

/* Free every field and zero the struct. Safe on a zeroed struct. */
void ss_url_free(ss_url_t *url);

#ifdef __cplusplus
}
#endif

#endif // _SSURL_H
