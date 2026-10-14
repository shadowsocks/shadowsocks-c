// SPDX-License-Identifier: GPL-3.0-or-later
// Legacy crypto reference (tests/reference/crypto.cpp): MD5, key derivation,
// HKDF, key parsing, AEAD salt replay and the printable-salt experiment.
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include <sodium.h>

#include "test_helpers.hpp"

#include "crypto.h"
#include "ppbloom.h"
#include "utils.h"

extern "C" {
int verbose = 0;
// Provide the nonce_cache symbol needed by the crypto reference.
struct cache *nonce_cache = nullptr;
}

namespace {

void test_crypto_md5()
{
    /* MD5("") = d41d8cd98f00b204e9800998ecf8427e */
    unsigned char result[16];
    crypto_md5(reinterpret_cast<const unsigned char *>(""), 0, result);

    unsigned char expected[] = {
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
    };
    SS_CHECK(std::memcmp(result, expected, 16) == 0);

    /* MD5("abc") = 900150983cd24fb0d6963f7d28e17f72 */
    crypto_md5(reinterpret_cast<const unsigned char *>("abc"), 3, result);
    unsigned char expected_abc[] = {
        0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
        0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72
    };
    SS_CHECK(std::memcmp(result, expected_abc, 16) == 0);
}

void test_crypto_derive_key()
{
    uint8_t key[32];

    SS_CHECK(crypto_derive_key(nullptr, key, 32) == 0);

    /* derive_key should produce deterministic output from a password */
    int ret = crypto_derive_key("password", key, 32);
    SS_CHECK(ret == 32);

    /* Same password should produce same key */
    uint8_t key2[32];
    ret = crypto_derive_key("password", key2, 32);
    SS_CHECK(ret == 32);
    SS_CHECK(std::memcmp(key, key2, 32) == 0);

    /* Different password should produce different key */
    uint8_t key3[32];
    ret = crypto_derive_key("different", key3, 32);
    SS_CHECK(ret == 32);
    SS_CHECK(std::memcmp(key, key3, 32) != 0);
}

void test_crypto_hkdf()
{
    /* RFC 5869 Test Case 1 */
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    SS_CHECK(md != nullptr);

    unsigned char ikm[22];
    std::memset(ikm, 0x0b, 22);

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
    SS_CHECK(ret == 0);

    unsigned char expected_okm[] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };
    SS_CHECK(std::memcmp(okm, expected_okm, 42) == 0);
}

void test_crypto_hkdf_extract()
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    SS_CHECK(md != nullptr);

    unsigned char ikm[22];
    std::memset(ikm, 0x0b, 22);

    unsigned char salt[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };

    unsigned char prk[32];
    int ret = crypto_hkdf_extract(md, salt, sizeof(salt), ikm, sizeof(ikm), prk);
    SS_CHECK(ret == 0);

    /* RFC 5869 Test Case 1 PRK */
    unsigned char expected_prk[] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };
    SS_CHECK(std::memcmp(prk, expected_prk, 32) == 0);
}

void test_crypto_parse_key()
{
    /* base64_encode uses URL-safe base64 with -_ instead of +/ */
    uint8_t key[32];

    /* A known base64-encoded 32-byte key (all zeros) */
    /* 32 zero bytes = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" in standard base64 */
    /* With URL-safe: same since no +/ needed */
    int ret = crypto_parse_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", key, 32);
    SS_CHECK(ret == 32);

    /* All bytes should be 0 */
    for (int i = 0; i < 32; i++) {
        SS_CHECK(key[i] == 0);
    }
}

void test_aead_repeat_salt_rejection_releases_context()
{
    crypto_t *crypto = crypto_init("password", nullptr, "aes-128-gcm");
    SS_CHECK(crypto != nullptr);

    buffer_t packet;
    std::memset(&packet, 0, sizeof(packet));
    balloc(&packet, 64);
    std::memcpy(packet.data, "payload", 7);
    packet.len = 7;

    SS_CHECK(crypto->encrypt_all(&packet, crypto->cipher, 128) == CRYPTO_OK);
    SS_CHECK(crypto->decrypt_all(&packet, crypto->cipher, 128) == CRYPTO_ERROR);

    bfree(&packet);
    ppbloom_free();
    ss_free(crypto->cipher);
    ss_free(crypto);
}

/* A nonprintable sentinel exposes the selected span without adding wire state.
 * Retain the random tail so every test connection still has a fresh salt. */
void test_printable_salt_lengths(const char *method)
{
    crypto_t *crypto = crypto_init("password", nullptr, method);
    SS_CHECK(crypto != nullptr);
    unsigned seen = 0;
    buffer_t buf{};
    balloc(&buf, 2048);
    for (int sample = 0; sample < 512; sample++) {
        cipher_ctx_t enc;
        crypto->ctx_init(crypto->cipher, &enc, 1);
        enc.printable_salt = 1;
        std::memset(enc.salt, 0xff, 12);
        uint8_t tail[20];
        std::memcpy(tail, enc.salt + 12, sizeof(tail));
        buf.data[0] = 'x';
        buf.len = 1;
        SS_CHECK(crypto->encrypt(&buf, &enc, 2048) == CRYPTO_OK);
        SS_CHECK(buf.len == 32 + 2 + 32 + 1);
        size_t length = 0;
        while (length < 12 && enc.salt[length] != 0xff) {
            SS_CHECK(enc.salt[length] >= 0x20 && enc.salt[length] <= 0x7e);
            length++;
        }
        SS_CHECK(length >= 6 && length <= 12);
        for (size_t i = length; i < 12; i++)
            SS_CHECK(enc.salt[i] == 0xff);
        SS_CHECK(std::memcmp(tail, enc.salt + 12, sizeof(tail)) == 0);
        SS_CHECK(std::memcmp(buf.data, enc.salt, 32) == 0);
        seen |= 1u << (length - 6);
        crypto->ctx_release(&enc);
    }
    /* Probability of missing a length with unbiased sampling is < 4e-34. */
    SS_CHECK(seen == 0x7f);
    bfree(&buf);
    ppbloom_free();
    ss_free(crypto->cipher);
    ss_free(crypto);
}

/* Exercise empty first writes, exact wire overhead, fragmented input, tampering
 * and replay with the receiver's independent bloom filter. */
void test_printable_salt(const char *method, int enabled)
{
    crypto_t *crypto = crypto_init("password", nullptr, method);
    SS_CHECK(crypto != nullptr);
    cipher_ctx_t enc, dec;
    crypto->ctx_init(crypto->cipher, &enc, 1);
    crypto->ctx_init(crypto->cipher, &dec, 0);
    SS_CHECK(enc.printable_salt == 0);
    enc.printable_salt = enabled;
    uint8_t original[32];
    std::memcpy(original, enc.salt, 32);
    buffer_t buf{};
    buffer_t fragment{};
    balloc(&buf, 2048);
    balloc(&fragment, 2048);
    SS_CHECK(crypto->encrypt(&buf, &enc, 2048) == CRYPTO_OK);
    SS_CHECK(enc.init == 0 && buf.len == 0);
    SS_CHECK(std::memcmp(original, enc.salt, 32) == 0);
    std::memcpy(buf.data, "payload", 7);
    buf.len = 7;
    SS_CHECK(crypto->encrypt(&buf, &enc, 2048) == CRYPTO_OK);
    SS_CHECK(buf.len == 32 + 2 + 32 + 7);
    SS_CHECK(std::memcmp(buf.data, enc.salt, 32) == 0);
    SS_CHECK(std::memcmp(original + 12, enc.salt + 12, 20) == 0);
    if (enabled) {
        for (int i = 0; i < 6; i++)
            SS_CHECK(enc.salt[i] >= 0x20 && enc.salt[i] <= 0x7e);
    } else {
        SS_CHECK(std::memcmp(original, enc.salt, 32) == 0);
    }
    uint8_t wire[73];
    std::memcpy(wire, buf.data, sizeof(wire));
    ppbloom_free();
    ppbloom_init(10000, 1e-15);
    for (size_t i = 0; i < sizeof(wire); i++) {
        fragment.data[0] = wire[i];
        fragment.len = 1;
        int result = crypto->decrypt(&fragment, &dec, 2048);
        if (i + 1 < sizeof(wire)) {
            SS_CHECK(result == CRYPTO_NEED_MORE);
        } else {
            SS_CHECK(result == CRYPTO_OK);
            SS_CHECK(fragment.len == 7 && std::memcmp(fragment.data, "payload", 7) == 0);
        }
    }
    std::memcpy(original, enc.salt, 32);
    std::memcpy(buf.data, "next", 4);
    buf.len = 4;
    SS_CHECK(crypto->encrypt(&buf, &enc, 2048) == CRYPTO_OK);
    SS_CHECK(buf.len == 2 + 32 + 4);
    SS_CHECK(std::memcmp(original, enc.salt, 32) == 0);
    SS_CHECK(crypto->decrypt(&buf, &dec, 2048) == CRYPTO_OK);
    SS_CHECK(buf.len == 4 && std::memcmp(buf.data, "next", 4) == 0);
    crypto->ctx_release(&dec);
    crypto->ctx_init(crypto->cipher, &dec, 0);
    std::memcpy(buf.data, wire, sizeof(wire));
    buf.len = sizeof(wire);
    SS_CHECK(crypto->decrypt(&buf, &dec, 2048) == CRYPTO_ERROR);
    crypto->ctx_release(&dec);
    ppbloom_free();
    ppbloom_init(10000, 1e-15);
    crypto->ctx_init(crypto->cipher, &dec, 0);
    std::memcpy(buf.data, wire, sizeof(wire));
    buf.data[sizeof(wire) - 1] ^= 1;
    buf.len = sizeof(wire);
    SS_CHECK(crypto->decrypt(&buf, &dec, 2048) == CRYPTO_ERROR);
    crypto->ctx_release(&dec);
    crypto->ctx_release(&enc);
    bfree(&buf);
    bfree(&fragment);
    ppbloom_free();
    ss_free(crypto->cipher);
    ss_free(crypto);
}

} // namespace

int main()
{
    if (sodium_init() < 0) {
        return 1;
    }

    test_printable_salt_lengths("chacha20-ietf-poly1305");
    std::printf("ok test_printable_salt_lengths chacha20-ietf-poly1305\n");
    test_printable_salt_lengths("aes-256-gcm");
    std::printf("ok test_printable_salt_lengths aes-256-gcm\n");
    test_printable_salt("chacha20-ietf-poly1305", 0);
    test_printable_salt("chacha20-ietf-poly1305", 1);
    test_printable_salt("aes-256-gcm", 0);
    test_printable_salt("aes-256-gcm", 1);
    std::printf("ok test_printable_salt\n");
    SS_RUN(test_crypto_md5);
    SS_RUN(test_crypto_derive_key);
    SS_RUN(test_crypto_hkdf);
    SS_RUN(test_crypto_hkdf_extract);
    SS_RUN(test_crypto_parse_key);
    SS_RUN(test_aead_repeat_salt_rejection_releases_context);

    SS_CHECK(crypto_init("password", nullptr, "aes-256-cfb") == nullptr);
    return 0;
}
