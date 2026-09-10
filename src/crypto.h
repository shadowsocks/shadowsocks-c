/*
 * crypto.h - Define the enryptor's interface
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
 * You should have recenonceed a copy of the GNU General Public License
 * along with shadowsocks-libev; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#ifndef __MINGW32__
#include <sys/socket.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif HAVE_INTTYPES_H
#include <inttypes.h>
#endif

/* Definitions for libsodium */
#include <sodium.h>
typedef crypto_aead_aes256gcm_state aes256gcm_ctx;
/* Definitions for mbedTLS */
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
typedef mbedtls_cipher_info_t cipher_kt_t;
typedef mbedtls_cipher_context_t cipher_evp_t;
typedef mbedtls_md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_NONCE_LENGTH 32
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE
/* we must have MBEDTLS_CIPHER_MODE_CFB defined */
#if SS_ENABLE_LEGACY && !defined(MBEDTLS_CIPHER_MODE_CFB)
#error Cipher Feedback mode a.k.a CFB not supported by your mbed TLS.
#endif
#ifndef MBEDTLS_GCM_C
#error No GCM support detected
#endif
#ifdef crypto_aead_xchacha20poly1305_ietf_ABYTES
#define FS_HAVE_XCHACHA20IETF
#endif

#define ADDRTYPE_MASK 0xF

#define CRYPTO_ERROR     -2
#define CRYPTO_NEED_MORE -1
#define CRYPTO_OK         0

#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define SUBKEY_INFO "ss-subkey"
#define IV_INFO "ss-iv"

/* SIP022 AEAD-2022 (Shadowsocks 2022 Edition) */
#define SS2022_SUBKEY_CTX "shadowsocks 2022 session subkey"
#define SS2022_TIME_WINDOW 30
#define SS2022_SALT_RETENTION 60
#define SS2022_MAX_PADDING 900
#define SS2022_SESSION_ID_LEN 8

#define CRYPTO_ROLE_CLIENT 0
#define CRYPTO_ROLE_SERVER 1

#ifndef BF_NUM_ENTRIES_FOR_SERVER
#define BF_NUM_ENTRIES_FOR_SERVER 1e6
#endif

#ifndef BF_NUM_ENTRIES_FOR_CLIENT
#define BF_NUM_ENTRIES_FOR_CLIENT 1e4
#endif

#ifndef BF_ERROR_RATE_FOR_SERVER
#define BF_ERROR_RATE_FOR_SERVER 1e-10
#endif

#ifndef BF_ERROR_RATE_FOR_CLIENT
#define BF_ERROR_RATE_FOR_CLIENT 1e-15
#endif

typedef struct buffer {
    size_t idx;
    size_t len;
    size_t capacity;
    char   *data;
} buffer_t;

typedef struct {
    int method;
    int skey;
    size_t nonce_len;
    size_t key_len;
    size_t tag_len;
    uint8_t key[MAX_KEY_LENGTH];
} cipher_t;

typedef struct cipher_ctx {
    uint32_t init;
    uint64_t counter;
    cipher_evp_t *evp;
    aes256gcm_ctx *aes256gcm_ctx;
    cipher_t *cipher;
    buffer_t *chunk;
    uint8_t salt[MAX_KEY_LENGTH];
    uint8_t skey[MAX_KEY_LENGTH];
    uint8_t nonce[MAX_NONCE_LENGTH];

    /* AEAD-2022 state */
    struct cipher_ctx *peer; /* paired enc/dec ctx of the same connection */
    uint8_t role;            /* CRYPTO_ROLE_CLIENT or CRYPTO_ROLE_SERVER */
    uint8_t hdr_stage;       /* TCP decrypt header state machine stage */
    uint16_t hdr_varlen;     /* pending request variable-length header size */
    uint16_t next_plen;      /* pending response first payload chunk size */
} cipher_ctx_t;

typedef struct crypto {
    cipher_t *cipher;

    int(*const encrypt_all) (buffer_t *, cipher_t *, size_t);
    int(*const decrypt_all) (buffer_t *, cipher_t *, size_t);
    int(*const encrypt) (buffer_t *, cipher_ctx_t *, size_t);
    int(*const decrypt) (buffer_t *, cipher_ctx_t *, size_t);

    void(*const ctx_init) (cipher_t *, cipher_ctx_t *, int);
    void(*const ctx_release) (cipher_ctx_t *);

    /*
     * AEAD-2022 session-based UDP. NULL for legacy ciphers; when set,
     * udprelay must use these instead of encrypt_all/decrypt_all, passing
     * a per-conversation session slot. The slot is released with
     * udp_session_release.
     */
    int(*const encrypt_udp) (buffer_t *, cipher_t *, size_t, void **);
    int(*const decrypt_udp) (buffer_t *, cipher_t *, size_t, void **);
    void(*const udp_session_release) (void *);
} crypto_t;

/* Pair the encrypt/decrypt contexts of one connection (needed by AEAD-2022
 * to echo and verify the request salt in the response header). */
static inline void
cipher_ctx_pair(cipher_ctx_t *a, cipher_ctx_t *b)
{
    a->peer = b;
    b->peer = a;
}

int balloc(buffer_t *, size_t);
int brealloc(buffer_t *, size_t, size_t);
int bprepend(buffer_t *, buffer_t *, size_t);
void bfree(buffer_t *);

static inline void
bswap_data(buffer_t *a, buffer_t *b)
{
    char *tmp_data      = a->data;
    size_t tmp_capacity = a->capacity;
    a->data             = b->data;
    a->capacity         = b->capacity;
    b->data             = tmp_data;
    b->capacity         = tmp_capacity;
}

int rand_bytes(void *, int);

crypto_t *crypto_init(const char *, const char *, const char *);
unsigned char *crypto_md5(const unsigned char *, size_t, unsigned char *);

int crypto_derive_key(const char *, uint8_t *, size_t);
int crypto_parse_key(const char *, uint8_t *, size_t);
int crypto_parse_psk(const char *, uint8_t *, size_t);
int crypto_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                int salt_len, const unsigned char *ikm, int ikm_len,
                const unsigned char *info, int info_len, unsigned char *okm,
                int okm_len);
int crypto_hkdf_extract(const mbedtls_md_info_t *md, const unsigned char *salt,
                        int salt_len, const unsigned char *ikm, int ikm_len,
                        unsigned char *prk);
int crypto_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
                       int prk_len, const unsigned char *info, int info_len,
                       unsigned char *okm, int okm_len);
#ifdef SS_DEBUG
void dump(char *tag, char *text, int len);
#endif

extern struct cache *nonce_cache;
extern const char *supported_stream_ciphers[];
extern const char *supported_aead_ciphers[];

#endif // _CRYPTO_H
