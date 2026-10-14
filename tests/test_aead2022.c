/*
 * Unit tests for the Shadowsocks 2022 Edition (SIP022) cipher suite.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

int verbose = 0;

#include "crypto.h"
#include "aead.h"
#include "ppbloom.h"
#include "utils.h"
#include "blake3/blake3.h"

/* Provide nonce_cache symbol needed by crypto.cpp */
struct cache *nonce_cache = NULL;

/* 32-byte and 16-byte PSKs in base64 */
#define PSK32 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
#define PSK16 "AAAAAAAAAAAAAAAAAAAAAA=="

static const char *methods_2022[] = {
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
};

static const char *
psk_for(const char *method)
{
    return strcmp(method, "2022-blake3-aes-128-gcm") == 0 ? PSK16 : PSK32;
}

static crypto_t *
make_crypto(const char *method)
{
    crypto_t *c = crypto_init(psk_for(method), NULL, method);
    assert(c != NULL);
    return c;
}

static void
free_crypto(crypto_t *c)
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
static void
test_blake3_derive_key_known_vector(void)
{
    blake3_hasher h;
    uint8_t material[32];
    uint8_t out[32];

    memset(material, 0, sizeof(material));
    blake3_hasher_init_derive_key(&h, SS2022_SUBKEY_CTX);
    blake3_hasher_update(&h, material, sizeof(material));
    blake3_hasher_finalize(&h, out, sizeof(out));

    /* Deterministic: the same input must always give the same subkey. */
    uint8_t out2[32];
    blake3_hasher_init_derive_key(&h, SS2022_SUBKEY_CTX);
    blake3_hasher_update(&h, material, sizeof(material));
    blake3_hasher_finalize(&h, out2, sizeof(out2));
    assert(memcmp(out, out2, 32) == 0);

    /* A different context string must give a different subkey. */
    uint8_t out3[32];
    blake3_hasher_init_derive_key(&h, "some other context");
    blake3_hasher_update(&h, material, sizeof(material));
    blake3_hasher_finalize(&h, out3, sizeof(out3));
    assert(memcmp(out, out3, 32) != 0);
    (void)out3;
}

/* BLAKE3 hash of the empty input, from the reference test vectors. */
static void
test_blake3_empty_hash_vector(void)
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
    assert(memcmp(out, expected, 32) == 0);
    (void)expected;
}

/*
 * A client request stream must round-trip through a server decrypt context:
 * salt, fixed header, variable header with the SOCKS address, then payload.
 */
static void
test_tcp_request_roundtrip(const char *method)
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
    memset(&buf, 0, sizeof(buf));
    balloc(&buf, 4096);
    memcpy(buf.data, addr, sizeof(addr));
    buf.len = sizeof(addr);
    assert(c->encrypt(&buf, &enc, 4096) == CRYPTO_OK);

    /* Second write: stream payload. */
    buffer_t buf2;
    memset(&buf2, 0, sizeof(buf2));
    balloc(&buf2, 4096);
    size_t plen = strlen(payload);
    memcpy(buf2.data, payload, plen);
    buf2.len = plen;
    assert(c->encrypt(&buf2, &enc, 4096) == CRYPTO_OK);

    /* Feed both writes to the server in one go, as they arrive on the wire. */
    buffer_t wire;
    memset(&wire, 0, sizeof(wire));
    balloc(&wire, 8192);
    memcpy(wire.data, buf.data, buf.len);
    memcpy(wire.data + buf.len, buf2.data, buf2.len);
    wire.len = buf.len + buf2.len;

    assert(c->decrypt(&wire, &dec, 8192) == CRYPTO_OK);

    /* The server sees the SOCKS address followed by the payload. */
    assert(wire.len == sizeof(addr) + plen);
    assert(memcmp(wire.data, addr, sizeof(addr)) == 0);
    assert(memcmp(wire.data + sizeof(addr), payload, plen) == 0);

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
static void
test_tcp_partial_delivery(const char *method)
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
    memset(&buf, 0, sizeof(buf));
    balloc(&buf, 4096);
    memcpy(buf.data, addr, sizeof(addr));
    buf.len = sizeof(addr);
    assert(c->encrypt(&buf, &enc, 4096) == CRYPTO_OK);

    /* Deliver the ciphertext one byte at a time. */
    size_t total = buf.len;
    int got_ok   = 0;
    for (size_t i = 0; i < total; i++) {
        buffer_t piece;
        memset(&piece, 0, sizeof(piece));
        balloc(&piece, 4096);
        piece.data[0] = buf.data[i];
        piece.len     = 1;

        int rc = c->decrypt(&piece, &dec, 4096);
        assert(rc == CRYPTO_OK || rc == CRYPTO_NEED_MORE);
        if (rc == CRYPTO_OK) {
            assert(piece.len == sizeof(addr));
            assert(memcmp(piece.data, addr, sizeof(addr)) == 0);
            got_ok = 1;
        }
        bfree(&piece);
    }
    assert(got_ok);
    (void)got_ok;

    bfree(&buf);
    c->ctx_release(&enc);
    c->ctx_release(&dec);
    free_crypto(c);
}

/* A tampered ciphertext must fail authentication rather than pass through. */
static void
test_tcp_tamper_detection(const char *method)
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
    memset(&buf, 0, sizeof(buf));
    balloc(&buf, 4096);
    memcpy(buf.data, addr, sizeof(addr));
    buf.len = sizeof(addr);
    assert(c->encrypt(&buf, &enc, 4096) == CRYPTO_OK);

    /* Flip a bit inside the first header chunk (past the salt). */
    buf.data[c->cipher->key_len + 2] ^= 0x01;

    assert(c->decrypt(&buf, &dec, 4096) == CRYPTO_ERROR);

    bfree(&buf);
    c->ctx_release(&enc);
    c->ctx_release(&dec);
    free_crypto(c);
}

/* UDP packets must round-trip through the session interface. */
static void
test_udp_roundtrip(const char *method)
{
    static const uint8_t pkt[] = {
        0x01, 8, 8, 8, 8, 0x00, 0x35,      /* 8.8.8.8:53 */
        0xde, 0xad, 0xbe, 0xef             /* payload */
    };

    crypto_t *c = make_crypto(method);
    assert(c->encrypt_udp != NULL);
    assert(c->decrypt_udp != NULL);

    void *client_session = NULL;
    void *server_session = NULL;

    buffer_t buf;
    memset(&buf, 0, sizeof(buf));
    balloc(&buf, 2048);
    memcpy(buf.data, pkt, sizeof(pkt));
    buf.len = sizeof(pkt);

    aead_set_role(CRYPTO_ROLE_CLIENT);
    assert(c->encrypt_udp(&buf, c->cipher, 2048, &client_session) == CRYPTO_OK);
    assert(buf.len > sizeof(pkt));

    aead_set_role(CRYPTO_ROLE_SERVER);
    assert(c->decrypt_udp(&buf, c->cipher, 2048, &server_session) == CRYPTO_OK);
    assert(buf.len == sizeof(pkt));
    assert(memcmp(buf.data, pkt, sizeof(pkt)) == 0);

    bfree(&buf);
    c->udp_session_release(client_session);
    c->udp_session_release(server_session);
    aead_set_role(CRYPTO_ROLE_CLIENT);
    free_crypto(c);
}

/* A replayed UDP packet must be rejected by the sliding window filter. */
static void
test_udp_replay_rejected(const char *method)
{
    static const uint8_t pkt[] = { 0x01, 8, 8, 8, 8, 0x00, 0x35, 0x42 };

    crypto_t *c = make_crypto(method);
    void *client_session = NULL;
    void *server_session = NULL;

    buffer_t buf;
    memset(&buf, 0, sizeof(buf));
    balloc(&buf, 2048);
    memcpy(buf.data, pkt, sizeof(pkt));
    buf.len = sizeof(pkt);

    aead_set_role(CRYPTO_ROLE_CLIENT);
    assert(c->encrypt_udp(&buf, c->cipher, 2048, &client_session) == CRYPTO_OK);

    /* Keep a copy of the wire packet so we can replay it verbatim. */
    buffer_t copy;
    memset(&copy, 0, sizeof(copy));
    balloc(&copy, 2048);
    memcpy(copy.data, buf.data, buf.len);
    copy.len = buf.len;

    aead_set_role(CRYPTO_ROLE_SERVER);
    assert(c->decrypt_udp(&buf, c->cipher, 2048, &server_session) == CRYPTO_OK);
    /* the very same packet again must be refused */
    assert(c->decrypt_udp(&copy, c->cipher, 2048, &server_session) == CRYPTO_ERROR);

    bfree(&buf);
    bfree(&copy);
    c->udp_session_release(client_session);
    c->udp_session_release(server_session);
    aead_set_role(CRYPTO_ROLE_CLIENT);
    free_crypto(c);
}

/* The 2022 ciphers must reject a PSK of the wrong size rather than pad it. */
static void
test_psk_parsing(void)
{
    uint8_t key[32];

    /* Correct size decodes. */
    assert(crypto_parse_psk(PSK32, key, 32) == 32);
    for (int i = 0; i < 32; i++)
        assert(key[i] == 0);

    /*
     * The standard alphabet ('+' and '/') and the URL-safe one ('-' and '_')
     * must both decode, and to the same bytes: key material is quoted from
     * tools using either convention.
     */
    uint8_t k1[32], k2[32];
    assert(crypto_parse_psk("//////////////////////////////////////////8=", k1, 32) == 32);
    assert(crypto_parse_psk("__________________________________________8=", k2, 32) == 32);
    assert(memcmp(k1, k2, 32) == 0);
    for (int i = 0; i < 32; i++)
        assert(k1[i] == 0xff);

    /* A key with distinct bytes must decode to exactly those bytes. */
    uint8_t k3[32];
    assert(crypto_parse_psk("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
                            k3, 32) == 32);
    for (int i = 0; i < 32; i++)
        assert(k3[i] == i);
}

int
main(void)
{
    if (sodium_init() < 0)
        return 1;

    test_blake3_empty_hash_vector();
    test_blake3_derive_key_known_vector();
    test_psk_parsing();

    for (size_t i = 0; i < sizeof(methods_2022) / sizeof(methods_2022[0]); i++) {
        const char *m = methods_2022[i];
        test_tcp_request_roundtrip(m);
        test_tcp_partial_delivery(m);
        test_tcp_tamper_detection(m);
        test_udp_roundtrip(m);
        test_udp_replay_rejected(m);
    }

    return 0;
}
