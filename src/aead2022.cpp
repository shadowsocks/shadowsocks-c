/*
 * aead2022.c - Shadowsocks 2022 Edition (SIP022) AEAD ciphers
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
 * Spec: https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include <sodium.h>

#include "aead.h"
#include "aead_internal.h"
#include "cache.h"
#include "utils.h"
#include "blake3/blake3.h"

/* SIP022 constants */
#define SS2022_HDR_TYPE_CLIENT   0
#define SS2022_HDR_TYPE_SERVER   1

/* TCP decrypt state machine (cipher_ctx_t.hdr_stage) */
#define SS2022_STAGE_FIXED_HDR   0
#define SS2022_STAGE_VAR_HDR     1  /* request: variable header; response: first payload */
#define SS2022_STAGE_STREAM      2

/* request fixed-length header: type(1) + timestamp(8) + length(2) */
#define SS2022_REQ_FIXED_LEN     11
/* response fixed-length header: type(1) + timestamp(8) + request salt + length(2) */
#define SS2022_RESP_FIXED_LEN(salt_len) (11 + (salt_len))
#define SS2022_FIXED_BUF_LEN     (11 + MAX_KEY_LENGTH)

#define SS2022_CHUNK_LEN_SIZE    2
#define SS2022_CHUNK_MASK        0xFFFF
#define SS2022_TAG_LEN           16
#define SS2022_SALT_POOL_CAP     65536

/*
 * Role handling. AEAD-2022 is asymmetric: the client encrypts request
 * streams and decrypts response streams, the server does the opposite.
 * The default follows the module this file is compiled into; unit tests
 * override it with aead_set_role().
 */
#ifdef MODULE_REMOTE
static int aead_role = CRYPTO_ROLE_SERVER;
#else
static int aead_role = CRYPTO_ROLE_CLIENT;
#endif

void
aead_set_role(int role)
{
    aead_role = role;
}

int
aead_get_role(void)
{
    return aead_role;
}

/*
 * session_subkey := blake3::derive_key(context, key || salt)
 * salt is the per-stream random salt for TCP, or the session ID for UDP.
 */
void
ss2022_derive_subkey(const uint8_t *key, size_t key_len,
                     const uint8_t *salt, size_t salt_len,
                     uint8_t *subkey, size_t subkey_len)
{
    uint8_t material[2 * MAX_KEY_LENGTH];
    blake3_hasher hasher;

    memcpy(material, key, key_len);
    memcpy(material + key_len, salt, salt_len);

    blake3_hasher_init_derive_key(&hasher, SS2022_SUBKEY_CTX);
    blake3_hasher_update(&hasher, material, key_len + salt_len);
    blake3_hasher_finalize(&hasher, subkey, subkey_len);

    sodium_memzero(material, sizeof(material));
}

/*
 * Server-side salt pool. SIP022 requires exact salt matching with 60s of
 * retention and forbids bloom filters (false positives are not allowed),
 * so ppbloom cannot be reused here.
 */
static struct cache *ss2022_salt_pool = NULL;

static int
ss2022_salt_check_and_add(const uint8_t *salt, size_t salt_len)
{
    if (ss2022_salt_pool == NULL) {
        if (cache_create_keyed(&ss2022_salt_pool, SS2022_SALT_POOL_CAP, MAX_KEY_LENGTH, NULL) != 0)
            return CRYPTO_ERROR;
    }

    cache_clear(ss2022_salt_pool, SS2022_SALT_RETENTION);

    if (cache_key_exist(ss2022_salt_pool, (char *)salt, salt_len)) {
        LOGE("crypto: AEAD-2022: repeat salt detected");
        return CRYPTO_ERROR;
    }

    cache_insert(ss2022_salt_pool, (char *)salt, salt_len, NULL);
    return CRYPTO_OK;
}

static int
ss2022_check_timestamp(uint64_t ts)
{
    uint64_t now  = (uint64_t)time(NULL);
    uint64_t diff = now > ts ? now - ts : ts - now;
    return diff <= SS2022_TIME_WINDOW ? CRYPTO_OK : CRYPTO_ERROR;
}

static void
store16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void
store64_be(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xff);
        v  >>= 8;
    }
}

static uint64_t
load64_be(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

/*
 * Length of the SOCKS5 address (ATYP + address + port) at the head of buf,
 * or 0 if it is malformed or truncated.
 */
static size_t
ss2022_socks_addr_len(const uint8_t *buf, size_t len)
{
    if (len < 1)
        return 0;

    size_t addr_len;
    switch (buf[0] & ADDRTYPE_MASK) {
    case 1:                                   /* IPv4 */
        addr_len = 1 + 4;
        break;
    case 4:                                   /* IPv6 */
        addr_len = 1 + 16;
        break;
    case 3:                                   /* domain */
        if (len < 2)
            return 0;
        addr_len = 2 + buf[1];
        break;
    default:
        return 0;
    }

    return (len >= addr_len + 2) ? addr_len + 2 : 0;
}

/* Encrypt one chunk at c, then advance the counting nonce. */
static int
ss2022_seal(cipher_ctx_t *ctx, uint8_t *c, const uint8_t *p, size_t plen)
{
    size_t clen = plen + SS2022_TAG_LEN;
    int err     = aead_cipher_encrypt(ctx, c, &clen, (uint8_t *)p, plen,
                                      NULL, 0, ctx->nonce, ctx->skey);
    if (err)
        return -1;
    sodium_increment(ctx->nonce, ctx->cipher->nonce_len);
    return (int)clen;
}

/* Decrypt one chunk (mlen includes the tag), then advance the nonce. */
static int
ss2022_open(cipher_ctx_t *ctx, uint8_t *p, const uint8_t *c, size_t mlen)
{
    size_t plen = mlen - SS2022_TAG_LEN;
    int err     = aead_cipher_decrypt(ctx, p, &plen, (uint8_t *)c, mlen,
                                      NULL, 0, ctx->nonce, ctx->skey);
    if (err)
        return -1;
    sodium_increment(ctx->nonce, ctx->cipher->nonce_len);
    return (int)plen;
}

/* ------------------------------------------------------------------ TCP */

/*
 * Build the request variable-length header body:
 *   ATYP || address || port || padding length || padding || initial payload
 * The caller's first plaintext holds the SOCKS address, optionally followed
 * by initial payload bytes. SIP022 requires padding when there is no initial
 * payload, so random padding is added in that case.
 */
static int
ss2022_build_req_varhdr(const uint8_t *first, size_t first_len,
                        uint8_t **out, size_t *out_len)
{
    size_t addr_len = ss2022_socks_addr_len(first, first_len);
    if (addr_len == 0) {
        LOGE("AEAD-2022: malformed SOCKS address in request header");
        return CRYPTO_ERROR;
    }

    size_t payload_len = first_len - addr_len;
    uint16_t pad_len   = 0;

    if (payload_len == 0) {
        uint16_t r;
        rand_bytes(&r, sizeof(r));
        pad_len = (uint16_t)(r % SS2022_MAX_PADDING) + 1;
    }

    size_t total = addr_len + 2 + pad_len + payload_len;
    uint8_t *buf = (uint8_t *)ss_malloc(total);

    memcpy(buf, first, addr_len);
    store16_be(buf + addr_len, pad_len);
    if (pad_len > 0)
        rand_bytes(buf + addr_len + 2, pad_len);
    if (payload_len > 0)
        memcpy(buf + addr_len + 2 + pad_len, first + addr_len, payload_len);

    *out     = buf;
    *out_len = total;
    return CRYPTO_OK;
}

/*
 * Emit salt and header chunks for the first write of a stream. The salt and
 * headers are written into one buffer so the caller sends them in a single
 * write, as SIP022 requires.
 */
static int
ss2022_emit_header(cipher_ctx_t *ctx, buffer_t *out, size_t *out_len,
                   const uint8_t *first, size_t first_len, size_t capacity)
{
    size_t salt_len = ctx->cipher->key_len;
    uint64_t now    = (uint64_t)time(NULL);
    uint8_t fixed[SS2022_FIXED_BUF_LEN];
    size_t fixed_len;
    uint8_t *body     = NULL;
    size_t body_len   = 0;
    int body_owned    = 0;
    int rc            = CRYPTO_ERROR;
    size_t o;
    int n;

    if (ctx->role == CRYPTO_ROLE_CLIENT) {
        if (ss2022_build_req_varhdr(first, first_len, &body, &body_len)
            != CRYPTO_OK)
            return CRYPTO_ERROR;
        body_owned = 1;

        if (body_len > SS2022_CHUNK_MASK) {
            LOGE("AEAD-2022: request header too large");
            goto done;
        }

        fixed_len = SS2022_REQ_FIXED_LEN;
        fixed[0]  = SS2022_HDR_TYPE_CLIENT;
        store64_be(fixed + 1, now);
        store16_be(fixed + 9, (uint16_t)body_len);
    } else {
        /*
         * The response fixed header doubles as the first length chunk and
         * echoes the request salt, which lives in the paired decrypt ctx.
         */
        cipher_ctx_t *peer = ctx->peer;
        if (peer == NULL || !peer->init) {
            LOGE("AEAD-2022: response header needs the request salt");
            return CRYPTO_ERROR;
        }
        if (first_len > SS2022_CHUNK_MASK) {
            LOGE("AEAD-2022: response payload too large");
            return CRYPTO_ERROR;
        }

        body     = (uint8_t *)first;
        body_len = first_len;

        fixed_len = SS2022_RESP_FIXED_LEN(salt_len);
        fixed[0]  = SS2022_HDR_TYPE_SERVER;
        store64_be(fixed + 1, now);
        memcpy(fixed + 9, peer->salt, salt_len);
        store16_be(fixed + 9 + salt_len, (uint16_t)body_len);
    }

    brealloc(out, salt_len + fixed_len + SS2022_TAG_LEN
             + body_len + SS2022_TAG_LEN, capacity);

    memcpy(out->data, ctx->salt, salt_len);
    o = salt_len;

    n = ss2022_seal(ctx, (uint8_t *)out->data + o, fixed, fixed_len);
    if (n < 0)
        goto done;
    o += n;

    n = ss2022_seal(ctx, (uint8_t *)out->data + o, body, body_len);
    if (n < 0)
        goto done;
    o += n;

    *out_len = o;
    rc       = CRYPTO_OK;

done:
    if (body_owned)
        ss_free(body);
    return rc;
}

int
ss2022_tcp_encrypt(buffer_t *plaintext, cipher_ctx_t *ctx, size_t capacity)
{
    static buffer_t tmp = { 0, 0, 0, NULL };

    if (plaintext->len == 0)
        return CRYPTO_OK;

    if (!ctx->init) {
        aead_cipher_ctx_set_key(ctx, 1);
        ctx->init = 1;

        size_t out_len = 0;
        int err = ss2022_emit_header(ctx, &tmp, &out_len,
                                     (uint8_t *)plaintext->data,
                                     plaintext->len, capacity);
        if (err)
            return err;

        tmp.len = out_len;
        bswap_data(plaintext, &tmp);
        plaintext->len = out_len;
        return CRYPTO_OK;
    }

    /* Steady state: length chunk followed by payload chunk. */
    size_t remaining = plaintext->len;
    uint8_t *src     = (uint8_t *)plaintext->data;
    size_t total_out = 0;

    size_t nchunks = (plaintext->len + SS2022_CHUNK_MASK - 1) / SS2022_CHUNK_MASK;
    brealloc(&tmp, plaintext->len
             + nchunks * (SS2022_CHUNK_LEN_SIZE + 2 * SS2022_TAG_LEN),
             capacity);

    while (remaining > 0) {
        uint16_t plen = remaining > SS2022_CHUNK_MASK
                        ? SS2022_CHUNK_MASK : (uint16_t)remaining;

        uint8_t len_buf[SS2022_CHUNK_LEN_SIZE];
        store16_be(len_buf, plen);

        int n = ss2022_seal(ctx, (uint8_t *)tmp.data + total_out,
                            len_buf, SS2022_CHUNK_LEN_SIZE);
        if (n < 0)
            return CRYPTO_ERROR;
        total_out += n;

        n = ss2022_seal(ctx, (uint8_t *)tmp.data + total_out, src, plen);
        if (n < 0)
            return CRYPTO_ERROR;
        total_out += n;

        src       += plen;
        remaining -= plen;
    }

    tmp.len = total_out;
    bswap_data(plaintext, &tmp);
    plaintext->len = total_out;
    return CRYPTO_OK;
}

/*
 * Parse a decrypted request variable-length header and emit the SOCKS
 * address followed by any initial payload, which is the layout the
 * ss-server request path already understands.
 */
static int
ss2022_parse_req_varhdr(const uint8_t *h, size_t len, buffer_t *out,
                        size_t capacity)
{
    size_t socks_len = ss2022_socks_addr_len(h, len);
    if (socks_len == 0 || len < socks_len + 2)
        return CRYPTO_ERROR;

    uint16_t pad_len = load16_be(h + socks_len);
    size_t pad_ofst  = socks_len + 2;

    if (pad_len > SS2022_MAX_PADDING || pad_ofst + pad_len > len)
        return CRYPTO_ERROR;

    size_t payload_ofst = pad_ofst + pad_len;
    size_t payload_len  = len - payload_ofst;

    /* SIP022: a request with neither payload nor padding must be rejected. */
    if (payload_len == 0 && pad_len == 0)
        return CRYPTO_ERROR;

    brealloc(out, socks_len + payload_len, capacity);
    memcpy(out->data, h, socks_len);
    if (payload_len > 0)
        memcpy(out->data + socks_len, h + payload_ofst, payload_len);
    out->len = socks_len + payload_len;
    return CRYPTO_OK;
}

/* Append n bytes of freshly decrypted plaintext to the output buffer. */
static int
ss2022_drain_chunks(cipher_ctx_t *ctx, buffer_t *chunk, buffer_t *out,
                    size_t capacity)
{
    for (;;) {
        if (ctx->next_plen == 0) {
            /* Need a length chunk first. */
            if (chunk->len < SS2022_CHUNK_LEN_SIZE + SS2022_TAG_LEN)
                return CRYPTO_OK;

            uint8_t len_buf[SS2022_CHUNK_LEN_SIZE];
            int n = ss2022_open(ctx, len_buf,
                                (uint8_t *)chunk->data + chunk->idx,
                                SS2022_CHUNK_LEN_SIZE + SS2022_TAG_LEN);
            if (n < 0) {
                LOGE("AEAD-2022: length chunk authentication failed");
                return CRYPTO_ERROR;
            }

            uint16_t plen = load16_be(len_buf);
            if (plen == 0) {
                LOGE("AEAD-2022: zero-length payload chunk");
                return CRYPTO_ERROR;
            }

            chunk->idx    += SS2022_CHUNK_LEN_SIZE + SS2022_TAG_LEN;
            chunk->len    -= SS2022_CHUNK_LEN_SIZE + SS2022_TAG_LEN;
            ctx->next_plen = plen;
        }

        /*
         * The length chunk's nonce has already been consumed, so the pending
         * length is kept in ctx->next_plen until the payload arrives.
         */
        size_t need = (size_t)ctx->next_plen + SS2022_TAG_LEN;
        if (chunk->len < need)
            return CRYPTO_OK;

        brealloc(out, out->len + ctx->next_plen, capacity);
        int n = ss2022_open(ctx, (uint8_t *)out->data + out->len,
                            (uint8_t *)chunk->data + chunk->idx, need);
        if (n < 0) {
            LOGE("AEAD-2022: payload chunk authentication failed");
            return CRYPTO_ERROR;
        }

        chunk->idx    += need;
        chunk->len    -= need;
        out->len      += n;
        ctx->next_plen = 0;
    }
}

int
ss2022_tcp_decrypt(buffer_t *ciphertext, cipher_ctx_t *ctx, size_t capacity)
{
    static buffer_t out = { 0, 0, 0, NULL };

    size_t salt_len = ctx->cipher->key_len;
    int is_client   = (ctx->role == CRYPTO_ROLE_CLIENT);

    if (ctx->chunk == NULL) {
        ctx->chunk = (buffer_t *)ss_malloc(sizeof(buffer_t));
        memset(ctx->chunk, 0, sizeof(buffer_t));
        balloc(ctx->chunk, capacity);
    }

    buffer_t *chunk = ctx->chunk;

    /* Accumulate the newly received ciphertext. */
    if (chunk->idx > 0) {
        if (chunk->len > 0)
            memmove(chunk->data, chunk->data + chunk->idx, chunk->len);
        chunk->idx = 0;
    }
    brealloc(chunk, chunk->len + ciphertext->len, capacity);
    memcpy(chunk->data + chunk->len, ciphertext->data, ciphertext->len);
    chunk->len += ciphertext->len;

    out.len = 0;

    /* Stage 0: salt and fixed-length header, consumed as one unit. */
    if (!ctx->init) {
        size_t fixed_len = is_client ? SS2022_RESP_FIXED_LEN(salt_len)
                                     : SS2022_REQ_FIXED_LEN;
        size_t need = salt_len + fixed_len + SS2022_TAG_LEN;

        if (chunk->len < need) {
            ciphertext->len = 0;
            return CRYPTO_NEED_MORE;
        }

        memcpy(ctx->salt, chunk->data + chunk->idx, salt_len);

        if (!is_client
            && ss2022_salt_check_and_add(ctx->salt, salt_len) != CRYPTO_OK)
            return CRYPTO_ERROR;

        aead_cipher_ctx_set_key(ctx, 0);

        uint8_t fixed[SS2022_FIXED_BUF_LEN];
        int n = ss2022_open(ctx, fixed,
                            (uint8_t *)chunk->data + chunk->idx + salt_len,
                            fixed_len + SS2022_TAG_LEN);
        if (n < 0) {
            LOGE("AEAD-2022: fixed header authentication failed");
            return CRYPTO_ERROR;
        }

        uint8_t want_type = is_client ? SS2022_HDR_TYPE_SERVER
                                      : SS2022_HDR_TYPE_CLIENT;
        if (fixed[0] != want_type) {
            LOGE("AEAD-2022: unexpected header type %u", fixed[0]);
            return CRYPTO_ERROR;
        }
        if (ss2022_check_timestamp(load64_be(fixed + 1)) != CRYPTO_OK) {
            LOGE("AEAD-2022: header timestamp out of window");
            return CRYPTO_ERROR;
        }

        if (is_client) {
            cipher_ctx_t *peer = ctx->peer;
            if (peer == NULL || memcmp(fixed + 9, peer->salt, salt_len) != 0) {
                LOGE("AEAD-2022: response does not echo the request salt");
                return CRYPTO_ERROR;
            }
            ctx->next_plen = load16_be(fixed + 9 + salt_len);
        } else {
            ctx->hdr_varlen = load16_be(fixed + 9);
        }

        chunk->idx    += need;
        chunk->len    -= need;
        ctx->init      = 1;
        ctx->hdr_stage = SS2022_STAGE_VAR_HDR;
    }

    /*
     * Stage 1: the request's variable-length header, or the response's first
     * payload chunk whose length came from the fixed header.
     */
    if (ctx->hdr_stage == SS2022_STAGE_VAR_HDR) {
        uint16_t want = is_client ? ctx->next_plen : ctx->hdr_varlen;
        size_t need   = (size_t)want + SS2022_TAG_LEN;

        if (want == 0) {
            LOGE("AEAD-2022: empty header chunk");
            return CRYPTO_ERROR;
        }
        if (chunk->len < need) {
            ciphertext->len = 0;
            return CRYPTO_NEED_MORE;
        }

        uint8_t *body = (uint8_t *)ss_malloc(want);
        int n = ss2022_open(ctx, body,
                            (uint8_t *)chunk->data + chunk->idx, need);
        if (n < 0) {
            ss_free(body);
            LOGE("AEAD-2022: header chunk authentication failed");
            return CRYPTO_ERROR;
        }
        chunk->idx += need;
        chunk->len -= need;

        int rc = CRYPTO_OK;
        if (is_client) {
            brealloc(&out, n, capacity);
            memcpy(out.data, body, n);
            out.len = n;
        } else {
            rc = ss2022_parse_req_varhdr(body, n, &out, capacity);
            if (rc != CRYPTO_OK)
                LOGE("AEAD-2022: malformed request header");
        }
        ss_free(body);
        if (rc != CRYPTO_OK)
            return rc;

        ctx->next_plen = 0;
        ctx->hdr_stage = SS2022_STAGE_STREAM;
    }

    /* Stage 2: length chunk and payload chunk, repeated. */
    if (ss2022_drain_chunks(ctx, chunk, &out, capacity) != CRYPTO_OK)
        return CRYPTO_ERROR;

    if (chunk->len == 0)
        chunk->idx = 0;

    if (out.len == 0) {
        ciphertext->len = 0;
        return CRYPTO_NEED_MORE;
    }

    brealloc(ciphertext, out.len, capacity);
    memcpy(ciphertext->data, out.data, out.len);
    ciphertext->len = out.len;
    return CRYPTO_OK;
}
