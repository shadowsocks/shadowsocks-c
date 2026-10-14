/*
 * aead.h - Define the AEAD interface
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

#ifndef _AEAD_H
#define _AEAD_H

#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// currently, XCHACHA20POLY1305IETF is not released yet
// XCHACHA20POLY1305 is removed in upstream
#ifdef FS_HAVE_XCHACHA20IETF
#define AEAD_CIPHER_NUM              8
#else
#define AEAD_CIPHER_NUM              7
#endif

int aead_encrypt_all(buffer_t *, cipher_t *, size_t);
int aead_decrypt_all(buffer_t *, cipher_t *, size_t);

int aead_encrypt(buffer_t *, cipher_ctx_t *, size_t);
int aead_decrypt(buffer_t *, cipher_ctx_t *, size_t);

void aead_ctx_init(cipher_t *, cipher_ctx_t *, int);
void aead_ctx_release(cipher_ctx_t *);

cipher_t *aead_init(const char *pass, const char *key, const char *method);

/* AEAD-2022 (SIP022) */
int aead_is_2022(const cipher_t *cipher);
void aead_set_role(int role); /* override compile-time default; used by tests */

/*
 * Server-side UDP session table size. Inserting beyond it evicts the least
 * recently used session; a relay context that still references the evicted
 * session keeps it alive until it releases it.
 */
#define AEAD_2022_UDP_SESSION_TABLE_CAP 4096

int aead_2022_encrypt_udp(buffer_t *, cipher_t *, size_t, void **);
int aead_2022_decrypt_udp(buffer_t *, cipher_t *, size_t, void **);
void aead_2022_udp_session_release(void *);

#ifdef __cplusplus
}
#endif

#endif // _AEAD_H
