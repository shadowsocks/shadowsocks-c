/*
 * aead_internal.h - Internal interface shared by aead.cpp and aead2022.cpp
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

#ifndef _AEAD_INTERNAL_H
#define _AEAD_INTERNAL_H

#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* AEAD method identifiers (indexes into the supported_aead_ciphers tables) */
#define AES128GCM               0
#define AES192GCM               1
#define AES256GCM               2
#define AES128GCM2022           3
#define AES256GCM2022           4
/*
 * methods above require a gcm context
 * methods below don't require it,
 * then we need to fake one
 */
#define CHACHA20POLY1305IETF        5
#define CHACHA20POLY1305IETF2022    6

#ifdef FS_HAVE_XCHACHA20IETF
#define XCHACHA20POLY1305IETF   7
#endif

static inline int
is_aead_2022(int method)
{
    return method == AES128GCM2022 || method == AES256GCM2022
           || method == CHACHA20POLY1305IETF2022;
}

/* Low-level one-shot AEAD operations implemented in aead.cpp */
int aead_cipher_encrypt(cipher_ctx_t *cipher_ctx,
                        uint8_t *c, size_t *clen,
                        uint8_t *m, size_t mlen,
                        uint8_t *ad, size_t adlen,
                        uint8_t *n, uint8_t *k);
int aead_cipher_decrypt(cipher_ctx_t *cipher_ctx,
                        uint8_t *p, size_t *plen,
                        uint8_t *m, size_t mlen,
                        uint8_t *ad, size_t adlen,
                        uint8_t *n, uint8_t *k);
void aead_cipher_ctx_set_key(cipher_ctx_t *cipher_ctx, int enc);

/* AEAD-2022 pieces implemented in aead2022.cpp */
int aead_get_role(void);
void ss2022_derive_subkey(const uint8_t *key, size_t key_len,
                          const uint8_t *salt, size_t salt_len,
                          uint8_t *subkey, size_t subkey_len);
int ss2022_tcp_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx,
                       size_t capacity);
int ss2022_tcp_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx,
                       size_t capacity);

#ifdef __cplusplus
}
#endif

#endif // _AEAD_INTERNAL_H
