#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

int verbose = 0;

#include "crypto.h"
#include "ppbloom.h"
#include "utils.h"

/* Provide nonce_cache symbol needed by crypto.cpp */
struct cache *nonce_cache = NULL;

static void
test_crypto_md5(void)
{
    /* MD5("") = d41d8cd98f00b204e9800998ecf8427e */
    unsigned char result[16];
    crypto_md5((const unsigned char *)"", 0, result);

    unsigned char expected[] = {
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
    };
    assert(memcmp(result, expected, 16) == 0);
    (void)expected;

    /* MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 */
    crypto_md5((const unsigned char *)"abc", 3, result);
    unsigned char expected_abc[] = {
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
    };
    assert(memcmp(result, expected_abc, 16) == 0);
    (void)expected_abc;
}

static void
test_crypto_derive_key(void)
{
    uint8_t key[32];

    assert(crypto_derive_key(NULL, key, 32) == 0);

    /* derive_key should produce deterministic output from a password */
    int ret = crypto_derive_key("password", key, 32);
    assert(ret == 32);

    /* Same password should produce same key */
    uint8_t key2[32];
    ret = crypto_derive_key("password", key2, 32);
    assert(ret == 32);
    assert(memcmp(key, key2, 32) == 0);

    /* Different password should produce different key */
    uint8_t key3[32];
    ret = crypto_derive_key("different", key3, 32);
    assert(ret == 32);
    assert(memcmp(key, key3, 32) != 0);
    (void)ret;
}

static void
test_crypto_hkdf(void)
{
    /* RFC 5869 Test Case 1 */
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    assert(md != NULL);

    unsigned char ikm[22];
    memset(ikm, 0x0b, 22);

    unsigned char salt[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };

    unsigned char info[] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };

    unsigned char okm[42];
    int ret = crypto_hkdf(md, salt, sizeof(salt), ikm, sizeof(ikm),
                          info, sizeof(info), okm, sizeof(okm));
    assert(ret == 0);
    (void)ret;

    unsigned char expected_okm[] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };
    assert(memcmp(okm, expected_okm, 42) == 0);
    (void)expected_okm;
}

static void
test_crypto_hkdf_extract(void)
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    assert(md != NULL);

    unsigned char ikm[22];
    memset(ikm, 0x0b, 22);

    unsigned char salt[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };

    unsigned char prk[32];
    int ret = crypto_hkdf_extract(md, salt, sizeof(salt), ikm, sizeof(ikm), prk);
    assert(ret == 0);
    (void)ret;

    /* RFC 5869 Test Case 1 PRK */
    unsigned char expected_prk[] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };
    assert(memcmp(prk, expected_prk, 32) == 0);
    (void)expected_prk;
}

static void
test_crypto_parse_key(void)
{
    /* base64_encode uses URL-safe base64 with -_ instead of +/ */
    uint8_t key[32];

    /* A known base64-encoded 32-byte key (all zeros) */
    /* 32 zero bytes = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" in standard base64 */
    /* With URL-safe: same since no +/ needed */
    int ret = crypto_parse_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", key, 32);
    assert(ret == 32);
    (void)ret;

    /* All bytes should be 0 */
    for (int i = 0; i < 32; i++) {
        assert(key[i] == 0);
    }
}

static void
test_aead_repeat_salt_rejection_releases_context(void)
{
    crypto_t *crypto = crypto_init("password", NULL, "aes-128-gcm");
    assert(crypto != NULL);

    buffer_t packet;
    memset(&packet, 0, sizeof(packet));
    balloc(&packet, 64);
    memcpy(packet.data, "payload", 7);
    packet.len = 7;

    assert(crypto->encrypt_all(&packet, crypto->cipher, 128) == CRYPTO_OK);
    assert(crypto->decrypt_all(&packet, crypto->cipher, 128) == CRYPTO_ERROR);

    bfree(&packet);
    ppbloom_free();
    ss_free(crypto->cipher);
    ss_free(crypto);
}

/* A nonprintable sentinel exposes the selected span without adding wire state.
 * Retain the random tail so every test connection still has a fresh salt. */
static void
test_printable_salt_lengths(const char *method)
{
    crypto_t *crypto = crypto_init("password", NULL, method);
    assert(crypto != NULL);
    unsigned seen = 0;
    buffer_t buf = {0};
    balloc(&buf, 2048);
    for (int sample = 0; sample < 512; sample++) {
        cipher_ctx_t enc;
        crypto->ctx_init(crypto->cipher, &enc, 1);
        enc.printable_salt = 1;
        memset(enc.salt, 0xff, 12);
        uint8_t tail[20];
        memcpy(tail, enc.salt + 12, sizeof(tail));
        buf.data[0] = 'x';
        buf.len = 1;
        assert(crypto->encrypt(&buf, &enc, 2048) == CRYPTO_OK);
        assert(buf.len == 32 + 2 + 32 + 1);
        size_t length = 0;
        while (length < 12 && enc.salt[length] != 0xff) {
            assert(enc.salt[length] >= 0x20 && enc.salt[length] <= 0x7e);
            length++;
        }
        assert(length >= 6 && length <= 12);
        for (size_t i = length; i < 12; i++)
            assert(enc.salt[i] == 0xff);
        assert(memcmp(tail, enc.salt + 12, sizeof(tail)) == 0);
        assert(memcmp(buf.data, enc.salt, 32) == 0);
        seen |= 1u << (length - 6);
        crypto->ctx_release(&enc);
    }
    /* Probability of missing a length with unbiased sampling is < 4e-34. */
    assert(seen == 0x7f);
    bfree(&buf);
    ppbloom_free();
    ss_free(crypto->cipher);
    ss_free(crypto);
}

/* Exercise empty first writes, exact wire overhead, fragmented input, tampering
 * and replay with the receiver's independent bloom filter. */
static void
test_printable_salt(const char *method, int enabled)
{
    crypto_t *crypto = crypto_init("password", NULL, method);
    assert(crypto != NULL);
    cipher_ctx_t enc, dec;
    crypto->ctx_init(crypto->cipher, &enc, 1);
    crypto->ctx_init(crypto->cipher, &dec, 0);
    assert(enc.printable_salt == 0);
    enc.printable_salt = enabled;
    uint8_t original[32];
    memcpy(original, enc.salt, 32);
    buffer_t buf = {0}, fragment = {0};
    balloc(&buf, 2048);
    balloc(&fragment, 2048);
    assert(crypto->encrypt(&buf, &enc, 2048) == CRYPTO_OK);
    assert(enc.init == 0 && buf.len == 0);
    assert(memcmp(original, enc.salt, 32) == 0);
    memcpy(buf.data, "payload", 7);
    buf.len = 7;
    assert(crypto->encrypt(&buf, &enc, 2048) == CRYPTO_OK);
    assert(buf.len == 32 + 2 + 32 + 7);
    assert(memcmp(buf.data, enc.salt, 32) == 0);
    assert(memcmp(original + 12, enc.salt + 12, 20) == 0);
    if (enabled) {
        for (int i = 0; i < 6; i++)
            assert(enc.salt[i] >= 0x20 && enc.salt[i] <= 0x7e);
    } else {
        assert(memcmp(original, enc.salt, 32) == 0);
    }
    uint8_t wire[73];
    memcpy(wire, buf.data, sizeof(wire));
    ppbloom_free();
    ppbloom_init(10000, 1e-15);
    for (size_t i = 0; i < sizeof(wire); i++) {
        fragment.data[0] = wire[i];
        fragment.len = 1;
        int result = crypto->decrypt(&fragment, &dec, 2048);
        if (i + 1 < sizeof(wire)) {
            assert(result == CRYPTO_NEED_MORE);
        } else {
            assert(result == CRYPTO_OK);
            assert(fragment.len == 7 && memcmp(fragment.data, "payload", 7) == 0);
        }
    }
    memcpy(original, enc.salt, 32);
    memcpy(buf.data, "next", 4);
    buf.len = 4;
    assert(crypto->encrypt(&buf, &enc, 2048) == CRYPTO_OK);
    assert(buf.len == 2 + 32 + 4);
    assert(memcmp(original, enc.salt, 32) == 0);
    assert(crypto->decrypt(&buf, &dec, 2048) == CRYPTO_OK);
    assert(buf.len == 4 && memcmp(buf.data, "next", 4) == 0);
    crypto->ctx_release(&dec);
    crypto->ctx_init(crypto->cipher, &dec, 0);
    memcpy(buf.data, wire, sizeof(wire));
    buf.len = sizeof(wire);
    assert(crypto->decrypt(&buf, &dec, 2048) == CRYPTO_ERROR);
    crypto->ctx_release(&dec);
    ppbloom_free();
    ppbloom_init(10000, 1e-15);
    crypto->ctx_init(crypto->cipher, &dec, 0);
    memcpy(buf.data, wire, sizeof(wire));
    buf.data[sizeof(wire) - 1] ^= 1;
    buf.len = sizeof(wire);
    assert(crypto->decrypt(&buf, &dec, 2048) == CRYPTO_ERROR);
    crypto->ctx_release(&dec);
    crypto->ctx_release(&enc);
    bfree(&buf);
    bfree(&fragment);
    ppbloom_free();
    ss_free(crypto->cipher);
    ss_free(crypto);
}

/*
 * Round-trip a multi-segment stream through a stream cipher.
 *
 * The segments deliberately have lengths that are not a multiple of the
 * cipher block size, and there is deliberately more than one of them: only
 * the first segment carries the nonce, so a codec that mishandles the
 * post-nonce steady state still round-trips a single segment correctly.
 */
#if SS_ENABLE_LEGACY
static void
test_stream_multi_segment_roundtrip(const char *method)
{
    static const char *segments[] = {
        "first-segment",
        "second",
        "a third segment that is a good deal longer than one block",
    };

    crypto_t *crypto = crypto_init("password", NULL, method);
    assert(crypto != NULL);

    cipher_ctx_t enc_ctx, dec_ctx;
    crypto->ctx_init(crypto->cipher, &enc_ctx, 1);
    crypto->ctx_init(crypto->cipher, &dec_ctx, 0);

    for (size_t i = 0; i < sizeof(segments) / sizeof(segments[0]); i++) {
        size_t len = strlen(segments[i]);

        buffer_t buf;
        memset(&buf, 0, sizeof(buf));
        balloc(&buf, 2048);
        memcpy(buf.data, segments[i], len);
        buf.len = len;

        assert(crypto->encrypt(&buf, &enc_ctx, 2048) == CRYPTO_OK);
        assert(crypto->decrypt(&buf, &dec_ctx, 2048) == CRYPTO_OK);

        assert(buf.len == len);
        assert(memcmp(buf.data, segments[i], len) == 0);

        bfree(&buf);
    }

    crypto->ctx_release(&enc_ctx);
    crypto->ctx_release(&dec_ctx);
    ppbloom_free();
    ss_free(crypto->cipher);
    ss_free(crypto);
}

#endif

int
main(void)
{
    if (sodium_init() < 0) {
        return 1;
    }

    test_printable_salt_lengths("chacha20-ietf-poly1305");
    test_printable_salt_lengths("aes-256-gcm");
    test_printable_salt("chacha20-ietf-poly1305", 0);
    test_printable_salt("chacha20-ietf-poly1305", 1);
    test_printable_salt("aes-256-gcm", 0);
    test_printable_salt("aes-256-gcm", 1);
    test_crypto_md5();
    test_crypto_derive_key();
    test_crypto_hkdf();
    test_crypto_hkdf_extract();
    test_crypto_parse_key();
    test_aead_repeat_salt_rejection_releases_context();

#if SS_ENABLE_LEGACY
    /* mbedTLS-backed ciphers and libsodium-backed ciphers use different
     * code paths in stream.cpp, so cover both. */
    test_stream_multi_segment_roundtrip("aes-256-cfb");
    test_stream_multi_segment_roundtrip("aes-256-ctr");
    test_stream_multi_segment_roundtrip("camellia-128-cfb");
    test_stream_multi_segment_roundtrip("chacha20-ietf");
    test_stream_multi_segment_roundtrip("salsa20");
#else
    assert(crypto_init("password", NULL, "aes-256-cfb") == NULL);
#endif
    return 0;
}
