/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "crypto/keys.hpp"
#include "crypto/mbedtls_compat.hpp"

#include <algorithm>
#include <cstring>

#include <mbedtls/md5.h>
#include <sodium.h>

#include "base64.h"
#include "utils.h"

namespace ss::crypto {

namespace {

constexpr std::size_t kMaxKey = 64;

} // namespace

bool derive_key(const char *password, std::span<std::uint8_t> key) noexcept
{
    if (password == nullptr) {
        return false;
    }
    const std::size_t len = std::strlen(password);
    std::uint8_t digest[16];
    mbedtls_md5_context md5;
    std::size_t at = 0;
    bool ok        = true;
    for (bool first = true; at < key.size(); first = false) {
        mbedtls_md5_init(&md5);
        ok = ok && mbed::md5_starts(&md5) == 0;
        if (!first) {
            ok = ok && mbed::md5_update(&md5, digest, sizeof(digest)) == 0;
        }
        ok = ok && mbed::md5_update(&md5, reinterpret_cast<const unsigned char *>(password), len) == 0
             && mbed::md5_finish(&md5, digest) == 0;
        mbedtls_md5_free(&md5);
        std::size_t n = std::min(sizeof(digest), key.size() - at);
        std::memcpy(key.data() + at, digest, n);
        at += n;
    }
    sodium_memzero(digest, sizeof(digest));
    return ok;
}

bool parse_key(const char *base64, std::span<std::uint8_t> key, bool exact) noexcept
{
    if (base64 == nullptr || key.size() > kMaxKey) {
        return false;
    }
    // One spare byte tells an over-long key from an exact one; base64_decode
    // never writes past the size it is given.
    std::uint8_t out[kMaxKey + 1];
    int want = static_cast<int>(key.size()) + 1;
    int n    = base64_decode(out, base64, want);
    bool ok  = exact ? n == static_cast<int>(key.size()) : n >= static_cast<int>(key.size());
    if (ok && n > static_cast<int>(key.size())) {
        // Kept for existing configs, but two different strings must not
        // silently be the same key.
        LOGE("the key is longer than %zu bytes; only the first %zu are used", key.size(), key.size());
    }
    if (ok) {
        std::memcpy(key.data(), out, key.size());
    }
    sodium_memzero(out, sizeof(out));
    return ok;
}

void report_bad_key(const char *what, std::size_t key_len) noexcept
{
    std::uint8_t fresh[kMaxKey];
    char encoded[BASE64_SIZE(kMaxKey)];
    key_len = std::min(key_len, kMaxKey);
    randombytes_buf(fresh, key_len);
    base64_encode(encoded, sizeof(encoded), fresh, static_cast<int>(key_len));
    sodium_memzero(fresh, sizeof(fresh));
    LOGE("Invalid %s for your chosen cipher!", what);
    LOGE("It requires a %zu-byte key encoded with Base64", key_len);
    LOGE("Generating a new random key: %s", encoded);
    LOGE("Please use the key above or input a valid key");
}

} // namespace ss::crypto
