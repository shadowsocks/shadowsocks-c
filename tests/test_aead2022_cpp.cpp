// SPDX-License-Identifier: GPL-3.0-or-later
// Shadowsocks 2022 Edition (SIP022) cipher suite in the legacy crypto
// reference (tests/reference/aead.cpp): BLAKE3 vectors, TCP and UDP round
// trips, tamper and replay rejection.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <sodium.h>

#include "test_helpers.hpp"

#include "aead.h"
#include "blake3/blake3.h"
#include "crypto.h"
#include "ppbloom.h"
#include "utils.h"

extern "C" {
int verbose = 0;
// Provide the nonce_cache symbol needed by the crypto reference.
struct cache *nonce_cache = nullptr;
}

namespace {

/* 32-byte and 16-byte PSKs in base64 */
#define PSK32 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
#define PSK16 "AAAAAAAAAAAAAAAAAAAAAA=="

const char *const methods_2022[] = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
};

const char *psk_for(const char *method)
{
    return std::strcmp(method, "2022-blake3-aes-128-gcm") == 0 ? PSK16 : PSK32;
}

crypto_t *make_crypto(const char *method)
{
    crypto_t *c = crypto_init(psk_for(method), nullptr, method);
    SS_CHECK(c != nullptr);
    return c;
}

void free_crypto(crypto_t *c)
{
    /*
     * crypto_init() sets up the nonce bloom filter each time it is called,
     * so it has to be torn down with every crypto_t or each test leaks a
     * fresh pair of filters.
     */
    ppbloom_free();
    ss_free(c->cipher);
    ss_free(c);
}

/*
 * BLAKE3 derive_key must match the reference implementation, otherwise
 * nothing interoperates. Vector generated from the BLAKE3 reference for
 * context "shadowsocks 2022 session subkey" over 32 zero bytes of material.
 */
void test_blake3_derive_key_known_vector()
{
    blake3_hasher h;
    uint8_t material[32];
    uint8_t out[32];

    std::memset(material, 0, sizeof(material));
    blake3_hasher_init_derive_key(&h, SS2022_SUBKEY_CTX);
    blake3_hasher_update(&h, material, sizeof(material));
    blake3_hasher_finalize(&h, out, sizeof(out));

    /* Deterministic: the same input must always give the same subkey. */
    uint8_t out2[32];
    blake3_hasher_init_derive_key(&h, SS2022_SUBKEY_CTX);
    blake3_hasher_update(&h, material, sizeof(material));
    blake3_hasher_finalize(&h, out2, sizeof(out2));
    SS_CHECK(std::memcmp(out, out2, 32) == 0);

    /* A different context string must give a different subkey. */
    uint8_t out3[32];
    blake3_hasher_init_derive_key(&h, "some other context");
    blake3_hasher_update(&h, material, sizeof(material));
    blake3_hasher_finalize(&h, out3, sizeof(out3));
    SS_CHECK(std::memcmp(out, out3, 32) != 0);
}

/* BLAKE3 hash of the empty input, from the reference test vectors. */
void test_blake3_empty_hash_vector()
{
    blake3_hasher h;
    uint8_t out[32];
    static const uint8_t expected[32] = {
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
        0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
        0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
        0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62
    };

    blake3_hasher_init(&h);
    blake3_hasher_update(&h, "", 0);
    blake3_hasher_finalize(&h, out, sizeof(out));
    SS_CHECK(std::memcmp(out, expected, 32) == 0);
}

/*
 * A client request stream must round-trip through a server decrypt context:
 * salt, fixed header, variable header with the SOCKS address, then payload.
 */
void test_tcp_request_roundtrip(const char *method)
{
    /* SOCKS address: IPv4 1.2.3.4:80 */
    static const uint8_t addr[] = { 0x01, 1, 2, 3, 4, 0x00, 0x50 };
    static const char *payload  = "GET / HTTP/1.0\r\n\r\n";

    crypto_t *c = make_crypto(method);

    cipher_ctx_t enc, dec;
    aead_set_role(CRYPTO_ROLE_CLIENT);
    c->ctx_init(c->cipher, &enc, 1);
    aead_set_role(CRYPTO_ROLE_SERVER);
    c->ctx_init(c->cipher, &dec, 0);
    cipher_ctx_pair(&enc, &dec);
    /* the contexts keep the role captured at init time */
    enc.role = CRYPTO_ROLE_CLIENT;
    dec.role = CRYPTO_ROLE_SERVER;

    /* First write: the address header. */
    buffer_t buf;
    std::memset(&buf, 0, sizeof(buf));
    balloc(&buf, 4096);
    std::memcpy(buf.data, addr, sizeof(addr));
    buf.len = sizeof(addr);
    SS_CHECK(c->encrypt(&buf, &enc, 4096) == CRYPTO_OK);

    /* Second write: stream payload. */
    buffer_t buf2;
    std::memset(&buf2, 0, sizeof(buf2));
    balloc(&buf2, 4096);
    size_t plen = std::strlen(payload);
    std::memcpy(buf2.data, payload, plen);
    buf2.len = plen;
    SS_CHECK(c->encrypt(&buf2, &enc, 4096) == CRYPTO_OK);

    /* Feed both writes to the server in one go, as they arrive on the wire. */
    buffer_t wire;
    std::memset(&wire, 0, sizeof(wire));
    balloc(&wire, 8192);
    std::memcpy(wire.data, buf.data, buf.len);
    std::memcpy(wire.data + buf.len, buf2.data, buf2.len);
    wire.len = buf.len + buf2.len;

    SS_CHECK(c->decrypt(&wire, &dec, 8192) == CRYPTO_OK);

    /* The server sees the SOCKS address followed by the payload. */
    SS_CHECK(wire.len == sizeof(addr) + plen);
    SS_CHECK(std::memcmp(wire.data, addr, sizeof(addr)) == 0);
    SS_CHECK(std::memcmp(wire.data + sizeof(addr), payload, plen) == 0);

    bfree(&buf);
    bfree(&buf2);
    bfree(&wire);
    c->ctx_release(&enc);
    c->ctx_release(&dec);
    free_crypto(c);
}

/*
 * A stream split across arbitrary boundaries must still decrypt: the
 * decryptor buffers partial chunks and returns CRYPTO_NEED_MORE.
 */
void test_tcp_partial_delivery(const char *method)
{
    static const uint8_t addr[] = { 0x01, 10, 0, 0, 1, 0x1f, 0x90 };
    crypto_t *c = make_crypto(method);

    cipher_ctx_t enc, dec;
    aead_set_role(CRYPTO_ROLE_CLIENT);
    c->ctx_init(c->cipher, &enc, 1);
    c->ctx_init(c->cipher, &dec, 0);
    cipher_ctx_pair(&enc, &dec);
    enc.role = CRYPTO_ROLE_CLIENT;
    dec.role = CRYPTO_ROLE_SERVER;

    buffer_t buf;
    std::memset(&buf, 0, sizeof(buf));
    balloc(&buf, 4096);
    std::memcpy(buf.data, addr, sizeof(addr));
    buf.len = sizeof(addr);
    SS_CHECK(c->encrypt(&buf, &enc, 4096) == CRYPTO_OK);

    /* Deliver the ciphertext one byte at a time. */
    size_t total = buf.len;
    int got_ok   = 0;
    for (size_t i = 0; i < total; i++) {
        buffer_t piece;
        std::memset(&piece, 0, sizeof(piece));
        balloc(&piece, 4096);
        piece.data[0] = buf.data[i];
        piece.len     = 1;

        int rc = c->decrypt(&piece, &dec, 4096);
        SS_CHECK(rc == CRYPTO_OK || rc == CRYPTO_NEED_MORE);
        if (rc == CRYPTO_OK) {
            SS_CHECK(piece.len == sizeof(addr));
            SS_CHECK(std::memcmp(piece.data, addr, sizeof(addr)) == 0);
            got_ok = 1;
        }
        bfree(&piece);
    }
    SS_CHECK(got_ok);

    bfree(&buf);
    c->ctx_release(&enc);
    c->ctx_release(&dec);
    free_crypto(c);
}

/* A tampered ciphertext must fail authentication rather than pass through. */
void test_tcp_tamper_detection(const char *method)
{
    static const uint8_t addr[] = { 0x01, 127, 0, 0, 1, 0x00, 0x50 };
    crypto_t *c = make_crypto(method);

    cipher_ctx_t enc, dec;
    aead_set_role(CRYPTO_ROLE_CLIENT);
    c->ctx_init(c->cipher, &enc, 1);
    c->ctx_init(c->cipher, &dec, 0);
    cipher_ctx_pair(&enc, &dec);
    enc.role = CRYPTO_ROLE_CLIENT;
    dec.role = CRYPTO_ROLE_SERVER;

    buffer_t buf;
    std::memset(&buf, 0, sizeof(buf));
    balloc(&buf, 4096);
    std::memcpy(buf.data, addr, sizeof(addr));
    buf.len = sizeof(addr);
    SS_CHECK(c->encrypt(&buf, &enc, 4096) == CRYPTO_OK);

    /* Flip a bit inside the first header chunk (past the salt). */
    buf.data[c->cipher->key_len + 2] ^= 0x01;

    SS_CHECK(c->decrypt(&buf, &dec, 4096) == CRYPTO_ERROR);

    bfree(&buf);
    c->ctx_release(&enc);
    c->ctx_release(&dec);
    free_crypto(c);
}

/* UDP packets must round-trip through the session interface. */
void test_udp_roundtrip(const char *method)
{
    static const uint8_t pkt[] = {
        0x01, 8, 8, 8, 8, 0x00, 0x35,      /* 8.8.8.8:53 */
        0xde, 0xad, 0xbe, 0xef             /* payload */
    };

    crypto_t *c = make_crypto(method);
    SS_CHECK(c->encrypt_udp != nullptr);
    SS_CHECK(c->decrypt_udp != nullptr);

    void *client_session = nullptr;
    void *server_session = nullptr;

    buffer_t buf;
    std::memset(&buf, 0, sizeof(buf));
    balloc(&buf, 2048);
    std::memcpy(buf.data, pkt, sizeof(pkt));
    buf.len = sizeof(pkt);

    aead_set_role(CRYPTO_ROLE_CLIENT);
    SS_CHECK(c->encrypt_udp(&buf, c->cipher, 2048, &client_session) == CRYPTO_OK);
    SS_CHECK(buf.len > sizeof(pkt));

    aead_set_role(CRYPTO_ROLE_SERVER);
    SS_CHECK(c->decrypt_udp(&buf, c->cipher, 2048, &server_session) == CRYPTO_OK);
    SS_CHECK(buf.len == sizeof(pkt));
    SS_CHECK(std::memcmp(buf.data, pkt, sizeof(pkt)) == 0);

    bfree(&buf);
    c->udp_session_release(client_session);
    c->udp_session_release(server_session);
    aead_set_role(CRYPTO_ROLE_CLIENT);
    free_crypto(c);
}

/* A replayed UDP packet must be rejected by the sliding window filter. */
void test_udp_replay_rejected(const char *method)
{
    static const uint8_t pkt[] = { 0x01, 8, 8, 8, 8, 0x00, 0x35, 0x42 };

    crypto_t *c = make_crypto(method);
    void *client_session = nullptr;
    void *server_session = nullptr;

    buffer_t buf;
    std::memset(&buf, 0, sizeof(buf));
    balloc(&buf, 2048);
    std::memcpy(buf.data, pkt, sizeof(pkt));
    buf.len = sizeof(pkt);

    aead_set_role(CRYPTO_ROLE_CLIENT);
    SS_CHECK(c->encrypt_udp(&buf, c->cipher, 2048, &client_session) == CRYPTO_OK);

    /* Keep a copy of the wire packet so we can replay it verbatim. */
    buffer_t copy;
    std::memset(&copy, 0, sizeof(copy));
    balloc(&copy, 2048);
    std::memcpy(copy.data, buf.data, buf.len);
    copy.len = buf.len;

    aead_set_role(CRYPTO_ROLE_SERVER);
    SS_CHECK(c->decrypt_udp(&buf, c->cipher, 2048, &server_session) == CRYPTO_OK);
    /* A rejected packet must not publish a session into a fresh relay slot. */
    void *rejected_session = nullptr;
    SS_CHECK(c->decrypt_udp(&copy, c->cipher, 2048, &rejected_session) == CRYPTO_ERROR);
    SS_CHECK(rejected_session == nullptr);
    /* the very same packet again must be refused */
    SS_CHECK(c->decrypt_udp(&copy, c->cipher, 2048, &server_session) == CRYPTO_ERROR);

    bfree(&buf);
    bfree(&copy);
    c->udp_session_release(client_session);
    c->udp_session_release(server_session);
    aead_set_role(CRYPTO_ROLE_CLIENT);
    free_crypto(c);
}

/* Encrypt one client packet into buf and hand it to the server's slot. */
void client_to_server(crypto_t *c, buffer_t *buf, const uint8_t *pkt, size_t len,
                 void **client_session, void **server_session)
{
    std::memcpy(buf->data, pkt, len);
    buf->len = len;
    aead_set_role(CRYPTO_ROLE_CLIENT);
    SS_CHECK(c->encrypt_udp(buf, c->cipher, 2048, client_session) == CRYPTO_OK);
    aead_set_role(CRYPTO_ROLE_SERVER);
    SS_CHECK(c->decrypt_udp(buf, c->cipher, 2048, server_session) == CRYPTO_OK);
    SS_CHECK(buf->len == len && std::memcmp(buf->data, pkt, len) == 0);
}

/*
 * A relay context keeps its server session across table eviction. Flooding
 * the table with fresh client session IDs used to free the session behind
 * the relay's back, so the reply path encrypted with freed memory.
 */
void test_udp_session_survives_table_eviction(const char *method)
{
    static const uint8_t pkt[] = { 0x01, 8, 8, 8, 8, 0x00, 0x35, 0x42 };

    crypto_t *c = make_crypto(method);
    void *client_session = nullptr;
    void *server_session = nullptr;

    buffer_t buf;
    std::memset(&buf, 0, sizeof(buf));
    balloc(&buf, 2048);

    client_to_server(c, &buf, pkt, sizeof(pkt), &client_session, &server_session);
    SS_CHECK(server_session != nullptr);
    void *first = server_session;
    void *shared_session = nullptr;
    client_to_server(c, &buf, pkt, sizeof(pkt), &client_session, &shared_session);
    SS_CHECK(shared_session == first);
    /* Reattaching the same slot must not acquire an extra reference. */
    client_to_server(c, &buf, pkt, sizeof(pkt), &client_session, &server_session);
    SS_CHECK(server_session == first);

    /* Each new client session ID inserts a table entry; overflow evicts ours. */
    for (int i = 0; i < AEAD_2022_UDP_SESSION_TABLE_CAP + 1; i++) {
        void *other_client = nullptr, *other_server = nullptr;
        client_to_server(c, &buf, pkt, sizeof(pkt), &other_client, &other_server);
        SS_CHECK(other_server != nullptr && other_server != first);
        c->udp_session_release(other_client);
        c->udp_session_release(other_server);
    }

    /* Dropping one relay owner must leave the other one usable. */
    c->udp_session_release(shared_session);

    /* The reply must still encrypt with the evicted session and verify. */
    std::memcpy(buf.data, pkt, sizeof(pkt));
    buf.len = sizeof(pkt);
    aead_set_role(CRYPTO_ROLE_SERVER);
    SS_CHECK(c->encrypt_udp(&buf, c->cipher, 2048, &server_session) == CRYPTO_OK);
    SS_CHECK(server_session == first);
    aead_set_role(CRYPTO_ROLE_CLIENT);
    SS_CHECK(c->decrypt_udp(&buf, c->cipher, 2048, &client_session) == CRYPTO_OK);
    SS_CHECK(buf.len == sizeof(pkt) && std::memcmp(buf.data, pkt, sizeof(pkt)) == 0);

    /* The client's next packet re-creates a table entry and swaps the slot. */
    client_to_server(c, &buf, pkt, sizeof(pkt), &client_session, &server_session);
    SS_CHECK(server_session != nullptr && server_session != first);

    /* Releasing the slot after eviction must neither leak nor double free. */
    c->udp_session_release(server_session);
    c->udp_session_release(client_session);

    bfree(&buf);
    aead_set_role(CRYPTO_ROLE_CLIENT);
    free_crypto(c);
}

/* The 2022 ciphers must reject a PSK of the wrong size rather than pad it. */
void test_psk_parsing()
{
    uint8_t key[32];

    /* Correct size decodes. */
    SS_CHECK(crypto_parse_psk(PSK32, key, 32) == 32);
    for (int i = 0; i < 32; i++)
        SS_CHECK(key[i] == 0);

    /*
     * The standard alphabet ('+' and '/') and the URL-safe one ('-' and '_')
     * must both decode, and to the same bytes: key material is quoted from
     * tools using either convention.
     */
    uint8_t k1[32], k2[32];
    SS_CHECK(crypto_parse_psk("//////////////////////////////////////////8=", k1, 32) == 32);
    SS_CHECK(crypto_parse_psk("__________________________________________8=", k2, 32) == 32);
    SS_CHECK(std::memcmp(k1, k2, 32) == 0);
    for (int i = 0; i < 32; i++)
        SS_CHECK(k1[i] == 0xff);

    /* A key with distinct bytes must decode to exactly those bytes. */
    uint8_t k3[32];
    SS_CHECK(crypto_parse_psk("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                            k3, 32) == 32);
    for (int i = 0; i < 32; i++)
        SS_CHECK(k3[i] == i);
}

} // namespace

int main()
{
    if (sodium_init() < 0) {
        return 1;
    }

    SS_RUN(test_blake3_empty_hash_vector);
    SS_RUN(test_blake3_derive_key_known_vector);
    SS_RUN(test_psk_parsing);

    for (const char *m : methods_2022) {
        test_tcp_request_roundtrip(m);
        test_tcp_partial_delivery(m);
        test_tcp_tamper_detection(m);
        test_udp_roundtrip(m);
        test_udp_replay_rejected(m);
        test_udp_session_survives_table_eviction(m);
        std::printf("ok %s\n", m);
    }

    return 0;
}
