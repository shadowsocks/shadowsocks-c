/*
 * aead2022_udp.c - Shadowsocks 2022 Edition (SIP022) session-based UDP
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
 * A UDP packet is:
 *
 *   AES methods:  [AES-ECB(psk, session ID || packet ID)] [AEAD body]
 *   ChaCha:       [24B random nonce] [XChaCha20-Poly1305(psk) body]
 *
 * The body carries a main header (type, timestamp, optional client session
 * ID, padding, SOCKS address) followed by the payload.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include <sodium.h>
#include <mbedtls/aes.h>

#include "aead.h"
#include "aead_internal.h"
#include "cache.h"
#include "utils.h"
#include "ss_ref.h"

#define SS2022_UDP_TYPE_CLIENT   0
#define SS2022_UDP_TYPE_SERVER   1
#define SS2022_UDP_SEP_HDR_LEN   16
#define SS2022_UDP_TAG_LEN       16
#define SS2022_UDP_XNONCE_LEN    24
/* type(1) + timestamp(8) + padding length(2) */
#define SS2022_UDP_MIN_HDR       11
/* sliding window width for replay protection */
#define SS2022_WINDOW_BITS       256

/*
 * Per-conversation UDP session state. The client keeps one of these per
 * source address; the server keeps one per client session ID. It holds our
 * own outgoing session (ID, packet counter) and the replay window of the
 * peer session we are receiving from.
 */
typedef struct ss2022_udp_session {
    ss_ref_t ref; /* Table and relay slots independently own this session. */
    cipher_t *cipher;

    /* outgoing */
    uint8_t tx_session_id[SS2022_SESSION_ID_LEN];
    uint64_t tx_packet_id;
    uint8_t tx_subkey[MAX_KEY_LENGTH];
    int tx_ready;

    /* incoming: last accepted peer session and its sliding window */
    uint8_t rx_session_id[SS2022_SESSION_ID_LEN];
    uint8_t rx_subkey[MAX_KEY_LENGTH];
    int rx_ready;
    uint64_t rx_highest;
    uint8_t rx_window[SS2022_WINDOW_BITS / 8];

    /* peer's client session ID, echoed by the server in its replies */
    uint8_t peer_session_id[SS2022_SESSION_ID_LEN];
    int peer_session_known;

} ss2022_udp_session_t;

/*
 * Server-side session table, keyed by the 8-byte client session ID. SIP022
 * requires servers to route by session ID rather than source address, so
 * that sessions survive client network changes.
 */
#define SS2022_SESSION_TABLE_CAP AEAD_2022_UDP_SESSION_TABLE_CAP
#define SS2022_SESSION_TTL       600

static struct cache *ss2022_sessions = NULL;

static void
session_destroy(void *object)
{
    sodium_memzero(object, sizeof(ss2022_udp_session_t));
    ss_free(object);
}

/* Cache callback: drop the table's reference when an entry is evicted. */
static void
session_free_cb(void *key, void *element)
{
    (void)key;
    ss_ref_release(element);
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

static int
ss2022_check_timestamp(uint64_t ts)
{
    uint64_t now  = (uint64_t)time(NULL);
    uint64_t diff = now > ts ? now - ts : ts - now;
    return diff <= SS2022_TIME_WINDOW ? CRYPTO_OK : CRYPTO_ERROR;
}

/*
 * Sliding window replay filter (WireGuard style). Only called after the
 * packet has been authenticated and its header validated.
 */
static int
window_check(const ss2022_udp_session_t *s, uint64_t id)
{
    if (id > s->rx_highest)
        return CRYPTO_OK;
    if (s->rx_highest - id >= SS2022_WINDOW_BITS)
        return CRYPTO_ERROR;

    uint64_t bit = id % SS2022_WINDOW_BITS;
    return (s->rx_window[bit / 8] & (1u << (bit % 8)))
           ? CRYPTO_ERROR : CRYPTO_OK;
}

static void
window_update(ss2022_udp_session_t *s, uint64_t id)
{
    if (id > s->rx_highest) {
        uint64_t shift = id - s->rx_highest;
        if (shift >= SS2022_WINDOW_BITS) {
            memset(s->rx_window, 0, sizeof(s->rx_window));
        } else {
            for (uint64_t i = s->rx_highest + 1; i <= id; i++) {
                uint64_t b = i % SS2022_WINDOW_BITS;
                s->rx_window[b / 8] &= (uint8_t) ~(1u << (b % 8));
            }
        }
        s->rx_highest = id;
    }

    uint64_t bit = id % SS2022_WINDOW_BITS;
    s->rx_window[bit / 8] |= (uint8_t)(1u << (bit % 8));
}

static ss2022_udp_session_t *
session_new(cipher_t *cipher)
{
    ss2022_udp_session_t *s = (ss2022_udp_session_t *)ss_malloc(sizeof(ss2022_udp_session_t));
    memset(s, 0, sizeof(ss2022_udp_session_t));
    s->cipher   = cipher;
    ss_ref_init(s, session_destroy);
    return s;
}

static ss2022_udp_session_t *
session_get(void **slot, cipher_t *cipher)
{
    ss2022_udp_session_t *s = (ss2022_udp_session_t *)*slot;
    if (s != NULL)
        return s;

    s     = session_new(cipher);
    *slot = s;
    return s;
}

/* Look up (or create) the server-side session for a client session ID. */
static ss2022_udp_session_t *
session_by_id(const uint8_t *session_id, cipher_t *cipher)
{
    if (ss2022_sessions == NULL
        && cache_create_keyed(&ss2022_sessions, SS2022_SESSION_TABLE_CAP,
                              SS2022_SESSION_ID_LEN, session_free_cb) != 0)
        return NULL;

    ss2022_udp_session_t *s = NULL;
    cache_lookup(ss2022_sessions, (char *)session_id, SS2022_SESSION_ID_LEN,
                 (void *)&s);
    if (s != NULL)
        return s;

    cache_clear(ss2022_sessions, SS2022_SESSION_TTL);

    s = session_new(cipher);
    /* Transfer the initial reference to the table on successful insertion. */
    if (cache_insert(ss2022_sessions, (char *)session_id,
                     SS2022_SESSION_ID_LEN, s) != 0) {
        ss_ref_release(s);
        return NULL;
    }
    return s;
}

void
aead_2022_udp_session_release(void *slot)
{
    ss_ref_release(slot);
}

static int
is_chacha(const cipher_t *cipher)
{
    return cipher->method == CHACHA20POLY1305IETF2022;
}

/* AES-ECB over the 16-byte separate header, keyed directly with the PSK. */
static int
sep_hdr_crypt(const cipher_t *cipher, uint8_t *dst, const uint8_t *src, int enc)
{
    mbedtls_aes_context aes;
    int err;

    mbedtls_aes_init(&aes);
    if (enc)
        err = mbedtls_aes_setkey_enc(&aes, cipher->key,
                                     (unsigned int)cipher->key_len * 8);
    else
        err = mbedtls_aes_setkey_dec(&aes, cipher->key,
                                     (unsigned int)cipher->key_len * 8);
    if (err == 0)
        err = mbedtls_aes_crypt_ecb(&aes,
                                    enc ? MBEDTLS_AES_ENCRYPT
                                        : MBEDTLS_AES_DECRYPT,
                                    src, dst);
    mbedtls_aes_free(&aes);
    return err == 0 ? CRYPTO_OK : CRYPTO_ERROR;
}

/*
 * AEAD over the packet body. For AES methods the session subkey and a nonce
 * taken from the separate header are used; for ChaCha the PSK is used
 * directly with a random 24-byte nonce.
 */
static int
body_seal(const cipher_t *cipher, const uint8_t *key,
          uint8_t *c, size_t *clen, const uint8_t *m, size_t mlen,
          const uint8_t *nonce)
{
    unsigned long long out_len = 0;
    int err;

    if (is_chacha(cipher)) {
        err = crypto_aead_xchacha20poly1305_ietf_encrypt(
            c, &out_len, m, mlen, NULL, 0, NULL, nonce, key);
        *clen = (size_t)out_len;
        return err == 0 ? CRYPTO_OK : CRYPTO_ERROR;
    }

    cipher_t tmp_cipher   = *cipher;
    cipher_ctx_t tmp_ctx;
    memset(&tmp_ctx, 0, sizeof(tmp_ctx));
    tmp_ctx.cipher = &tmp_cipher;

    /* Reuse the shared one-shot helper with an mbedTLS GCM context. */
    tmp_ctx.evp = (cipher_evp_t *)ss_malloc(sizeof(cipher_evp_t));
    memset(tmp_ctx.evp, 0, sizeof(cipher_evp_t));
    mbedtls_cipher_init(tmp_ctx.evp);
    const cipher_kt_t *kt = mbedtls_cipher_info_from_string(
        cipher->key_len == 16 ? "AES-128-GCM" : "AES-256-GCM");
    if (kt == NULL || mbedtls_cipher_setup(tmp_ctx.evp, kt) != 0
        || mbedtls_cipher_setkey(tmp_ctx.evp, key,
                                 (int)cipher->key_len * 8, MBEDTLS_ENCRYPT) != 0) {
        mbedtls_cipher_free(tmp_ctx.evp);
        ss_free(tmp_ctx.evp);
        return CRYPTO_ERROR;
    }

    *clen = mlen + SS2022_UDP_TAG_LEN;
    err   = aead_cipher_encrypt(&tmp_ctx, c, clen, (uint8_t *)m, mlen,
                                NULL, 0, (uint8_t *)nonce, (uint8_t *)key);

    mbedtls_cipher_free(tmp_ctx.evp);
    ss_free(tmp_ctx.evp);
    return err == 0 ? CRYPTO_OK : CRYPTO_ERROR;
}

static int
body_open(const cipher_t *cipher, const uint8_t *key,
          uint8_t *p, size_t *plen, const uint8_t *c, size_t clen,
          const uint8_t *nonce)
{
    unsigned long long out_len = 0;
    int err;

    if (is_chacha(cipher)) {
        err = crypto_aead_xchacha20poly1305_ietf_decrypt(
            p, &out_len, NULL, c, clen, NULL, 0, nonce, key);
        *plen = (size_t)out_len;
        return err == 0 ? CRYPTO_OK : CRYPTO_ERROR;
    }

    cipher_t tmp_cipher = *cipher;
    cipher_ctx_t tmp_ctx;
    memset(&tmp_ctx, 0, sizeof(tmp_ctx));
    tmp_ctx.cipher = &tmp_cipher;

    tmp_ctx.evp = (cipher_evp_t *)ss_malloc(sizeof(cipher_evp_t));
    memset(tmp_ctx.evp, 0, sizeof(cipher_evp_t));
    mbedtls_cipher_init(tmp_ctx.evp);
    const cipher_kt_t *kt = mbedtls_cipher_info_from_string(
        cipher->key_len == 16 ? "AES-128-GCM" : "AES-256-GCM");
    if (kt == NULL || mbedtls_cipher_setup(tmp_ctx.evp, kt) != 0
        || mbedtls_cipher_setkey(tmp_ctx.evp, key,
                                 (int)cipher->key_len * 8, MBEDTLS_DECRYPT) != 0) {
        mbedtls_cipher_free(tmp_ctx.evp);
        ss_free(tmp_ctx.evp);
        return CRYPTO_ERROR;
    }

    *plen = clen - SS2022_UDP_TAG_LEN;
    err   = aead_cipher_decrypt(&tmp_ctx, p, plen, (uint8_t *)c, clen,
                                NULL, 0, (uint8_t *)nonce, (uint8_t *)key);

    mbedtls_cipher_free(tmp_ctx.evp);
    ss_free(tmp_ctx.evp);
    return err == 0 ? CRYPTO_OK : CRYPTO_ERROR;
}

/*
 * Encrypt one UDP packet. The plaintext is a SOCKS address followed by the
 * payload, matching what udprelay hands to the legacy encrypt_all.
 */
int
aead_2022_encrypt_udp(buffer_t *plaintext, cipher_t *cipher, size_t capacity,
                      void **slot)
{
    static buffer_t tmp = { 0, 0, 0, NULL };

    ss2022_udp_session_t *s = session_get(slot, cipher);
    int is_server           = (aead_get_role() == CRYPTO_ROLE_SERVER);
    size_t salt_len         = cipher->key_len;

    if (!s->tx_ready) {
        rand_bytes(s->tx_session_id, SS2022_SESSION_ID_LEN);
        s->tx_packet_id = 0;
        ss2022_derive_subkey(cipher->key, salt_len,
                             s->tx_session_id, SS2022_SESSION_ID_LEN,
                             s->tx_subkey, salt_len);
        s->tx_ready = 1;
    }

    /* Build the main header followed by the payload. */
    size_t extra = is_server ? SS2022_SESSION_ID_LEN : 0;
    size_t hdr_len = SS2022_UDP_MIN_HDR + extra;
    size_t body_len = hdr_len + plaintext->len;

    uint8_t *body = (uint8_t *)ss_malloc(body_len);
    size_t o      = 0;

    body[o++] = is_server ? SS2022_UDP_TYPE_SERVER : SS2022_UDP_TYPE_CLIENT;
    store64_be(body + o, (uint64_t)time(NULL));
    o += 8;

    if (is_server) {
        if (!s->peer_session_known) {
            ss_free(body);
            LOGE("AEAD-2022: no client session to reply to");
            return CRYPTO_ERROR;
        }
        memcpy(body + o, s->peer_session_id, SS2022_SESSION_ID_LEN);
        o += SS2022_SESSION_ID_LEN;
    }

    store16_be(body + o, 0);  /* padding length */
    o += 2;

    memcpy(body + o, plaintext->data, plaintext->len);

    int rc = CRYPTO_ERROR;

    if (is_chacha(cipher)) {
        /*
         * nonce || XChaCha20-Poly1305(psk, session ID || packet ID ||
         * main header || payload)
         */
        size_t merged_len = SS2022_UDP_SEP_HDR_LEN + body_len;
        uint8_t *merged   = (uint8_t *)ss_malloc(merged_len);
        memcpy(merged, s->tx_session_id, SS2022_SESSION_ID_LEN);
        store64_be(merged + SS2022_SESSION_ID_LEN, s->tx_packet_id);
        memcpy(merged + SS2022_UDP_SEP_HDR_LEN, body, body_len);

        brealloc(&tmp, SS2022_UDP_XNONCE_LEN + merged_len + SS2022_UDP_TAG_LEN,
                 capacity);
        rand_bytes(tmp.data, SS2022_UDP_XNONCE_LEN);

        size_t clen = 0;
        rc = body_seal(cipher, cipher->key,
                       (uint8_t *)tmp.data + SS2022_UDP_XNONCE_LEN, &clen,
                       merged, merged_len, (uint8_t *)tmp.data);
        sodium_memzero(merged, merged_len);
        ss_free(merged);

        if (rc == CRYPTO_OK)
            tmp.len = SS2022_UDP_XNONCE_LEN + clen;
    } else {
        uint8_t sep[SS2022_UDP_SEP_HDR_LEN];
        memcpy(sep, s->tx_session_id, SS2022_SESSION_ID_LEN);
        store64_be(sep + SS2022_SESSION_ID_LEN, s->tx_packet_id);

        brealloc(&tmp, SS2022_UDP_SEP_HDR_LEN + body_len + SS2022_UDP_TAG_LEN,
                 capacity);

        rc = sep_hdr_crypt(cipher, (uint8_t *)tmp.data, sep, 1);
        if (rc == CRYPTO_OK) {
            size_t clen = 0;
            /* nonce is separate_header[4..16] of the plaintext header */
            rc = body_seal(cipher, s->tx_subkey,
                           (uint8_t *)tmp.data + SS2022_UDP_SEP_HDR_LEN, &clen,
                           body, body_len, sep + 4);
            if (rc == CRYPTO_OK)
                tmp.len = SS2022_UDP_SEP_HDR_LEN + clen;
        }
    }

    sodium_memzero(body, body_len);
    ss_free(body);

    if (rc != CRYPTO_OK)
        return CRYPTO_ERROR;

    s->tx_packet_id++;

    bswap_data(plaintext, &tmp);
    plaintext->len = tmp.len;
    return CRYPTO_OK;
}

int
aead_2022_decrypt_udp(buffer_t *ciphertext, cipher_t *cipher, size_t capacity,
                      void **slot)
{
    static buffer_t tmp = { 0, 0, 0, NULL };

    int is_server   = (aead_get_role() == CRYPTO_ROLE_SERVER);
    size_t salt_len = cipher->key_len;

    uint8_t session_id[SS2022_SESSION_ID_LEN];
    uint64_t packet_id;
    size_t plen = 0;

    if (is_chacha(cipher)) {
        if (ciphertext->len <= SS2022_UDP_XNONCE_LEN + SS2022_UDP_SEP_HDR_LEN
            + SS2022_UDP_TAG_LEN)
            return CRYPTO_ERROR;

        size_t clen = ciphertext->len - SS2022_UDP_XNONCE_LEN;
        brealloc(&tmp, clen, capacity);

        if (body_open(cipher, cipher->key, (uint8_t *)tmp.data, &plen,
                      (uint8_t *)ciphertext->data + SS2022_UDP_XNONCE_LEN, clen,
                      (uint8_t *)ciphertext->data) != CRYPTO_OK)
            return CRYPTO_ERROR;

        if (plen < SS2022_UDP_SEP_HDR_LEN)
            return CRYPTO_ERROR;

        memcpy(session_id, tmp.data, SS2022_SESSION_ID_LEN);
        packet_id = load64_be((uint8_t *)tmp.data + SS2022_SESSION_ID_LEN);

        /* strip the merged session ID and packet ID */
        plen -= SS2022_UDP_SEP_HDR_LEN;
        memmove(tmp.data, tmp.data + SS2022_UDP_SEP_HDR_LEN, plen);
    } else {
        if (ciphertext->len <= SS2022_UDP_SEP_HDR_LEN + SS2022_UDP_TAG_LEN)
            return CRYPTO_ERROR;

        uint8_t sep[SS2022_UDP_SEP_HDR_LEN];
        if (sep_hdr_crypt(cipher, sep, (uint8_t *)ciphertext->data, 0)
            != CRYPTO_OK)
            return CRYPTO_ERROR;

        memcpy(session_id, sep, SS2022_SESSION_ID_LEN);
        packet_id = load64_be(sep + SS2022_SESSION_ID_LEN);

        uint8_t subkey[MAX_KEY_LENGTH];
        ss2022_derive_subkey(cipher->key, salt_len,
                             session_id, SS2022_SESSION_ID_LEN,
                             subkey, salt_len);

        size_t clen = ciphertext->len - SS2022_UDP_SEP_HDR_LEN;
        brealloc(&tmp, clen, capacity);

        int rc = body_open(cipher, subkey, (uint8_t *)tmp.data, &plen,
                           (uint8_t *)ciphertext->data + SS2022_UDP_SEP_HDR_LEN,
                           clen, sep + 4);
        sodium_memzero(subkey, sizeof(subkey));
        if (rc != CRYPTO_OK)
            return CRYPTO_ERROR;
    }

    /*
     * Resolve the session. The server routes by client session ID, which is
     * only known now; the client keeps one session per source address, held
     * in the caller's slot.
     */
    ss2022_udp_session_t *s;
    if (is_server) {
        s = session_by_id(session_id, cipher);
        if (s == NULL)
            return CRYPTO_ERROR;
    } else {
        s = session_get(slot, cipher);
    }

    /* Main header validation */
    size_t extra   = is_server ? 0 : SS2022_SESSION_ID_LEN;
    size_t hdr_len = SS2022_UDP_MIN_HDR + extra;
    if (plen < hdr_len)
        return CRYPTO_ERROR;

    uint8_t *body     = (uint8_t *)tmp.data;
    uint8_t want_type = is_server ? SS2022_UDP_TYPE_CLIENT
                                  : SS2022_UDP_TYPE_SERVER;
    if (body[0] != want_type)
        return CRYPTO_ERROR;

    if (ss2022_check_timestamp(load64_be(body + 1)) != CRYPTO_OK)
        return CRYPTO_ERROR;

    size_t o = 9;
    if (!is_server) {
        /* the server echoes our client session ID; verify it is ours */
        if (!s->tx_ready
            || memcmp(body + o, s->tx_session_id, SS2022_SESSION_ID_LEN) != 0)
            return CRYPTO_ERROR;
        o += SS2022_SESSION_ID_LEN;
    }

    uint16_t pad_len = load16_be(body + o);
    o += 2;
    if (o + pad_len > plen)
        return CRYPTO_ERROR;
    o += pad_len;

    /* Replay protection: new session resets the window. */
    if (!s->rx_ready
        || memcmp(s->rx_session_id, session_id, SS2022_SESSION_ID_LEN) != 0) {
        memcpy(s->rx_session_id, session_id, SS2022_SESSION_ID_LEN);
        memset(s->rx_window, 0, sizeof(s->rx_window));
        s->rx_highest = 0;
        s->rx_ready   = 1;
        /* packet ID 0 is legitimate for a fresh session */
        if (packet_id > 0)
            s->rx_highest = packet_id - 1;
    } else if (window_check(s, packet_id) != CRYPTO_OK) {
        LOGE("AEAD-2022: UDP replay detected");
        return CRYPTO_ERROR;
    }
    window_update(s, packet_id);

    if (is_server) {
        memcpy(s->peer_session_id, session_id, SS2022_SESSION_ID_LEN);
        s->peer_session_known = 1;
        /* Publish only validated packets and retain the reply session. */
        ss_ref_assign(slot, s);
    }

    size_t payload_len = plen - o;
    brealloc(ciphertext, payload_len ? payload_len : 1, capacity);
    memcpy(ciphertext->data, body + o, payload_len);
    ciphertext->len = payload_len;
    return CRYPTO_OK;
}
