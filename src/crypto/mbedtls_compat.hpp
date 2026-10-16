/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CRYPTO_MBEDTLS_COMPAT_HPP
#define SS_CRYPTO_MBEDTLS_COMPAT_HPP

// One interface to the Mbed TLS primitives across its major versions:
//
// - 2.x returns void from the plain SHA-1/MD5 functions and int from their
//   _ret variants; 3.x keeps only the int-returning plain names.
// - 4.x moved the cryptography into TF-PSA-Crypto and made PSA Crypto its
//   only API: the SHA-1, MD5, AES and GCM modules are private there.
//
// Functions returning int return 0 on success.

#include <cstddef>
#include <cstdint>

#include <mbedtls/version.h>

#if MBEDTLS_VERSION_NUMBER >= 0x04000000
#include <psa/crypto.h>
#else
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#endif

namespace ss::crypto::mbed {

#if MBEDTLS_VERSION_NUMBER >= 0x04000000

// Must succeed before any other function here is used.
inline int init() noexcept
{
    return psa_crypto_init() == PSA_SUCCESS ? 0 : -1;
}

namespace detail {

inline int status(psa_status_t s) noexcept
{
    return s == PSA_SUCCESS ? 0 : -1;
}

inline int hash_finish(psa_hash_operation_t *c, unsigned char *out, std::size_t n) noexcept
{
    std::size_t len = 0;
    return status(psa_hash_finish(c, out, n, &len));
}

} // namespace detail

using sha1_context = psa_hash_operation_t;
using md5_context  = psa_hash_operation_t;

inline int sha1(const unsigned char *in, std::size_t n, unsigned char out[20]) noexcept
{
    std::size_t len = 0;
    return detail::status(psa_hash_compute(PSA_ALG_SHA_1, in, n, out, 20, &len));
}
inline void sha1_init(sha1_context *c) noexcept { *c = psa_hash_operation_init(); }
inline void sha1_free(sha1_context *c) noexcept { (void)psa_hash_abort(c); }
inline int sha1_starts(sha1_context *c) noexcept { return detail::status(psa_hash_setup(c, PSA_ALG_SHA_1)); }
inline int sha1_update(sha1_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return detail::status(psa_hash_update(c, in, n));
}
inline int sha1_finish(sha1_context *c, unsigned char out[20]) noexcept { return detail::hash_finish(c, out, 20); }

inline void md5_init(md5_context *c) noexcept { *c = psa_hash_operation_init(); }
inline void md5_free(md5_context *c) noexcept { (void)psa_hash_abort(c); }
inline int md5_starts(md5_context *c) noexcept { return detail::status(psa_hash_setup(c, PSA_ALG_MD5)); }
inline int md5_update(md5_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return detail::status(psa_hash_update(c, in, n));
}
inline int md5_finish(md5_context *c, unsigned char out[16]) noexcept { return detail::hash_finish(c, out, 16); }

// AES-GCM with a 16-byte tag. PSA keeps the key in a key slot.
class Gcm {
public:
    Gcm() noexcept = default;
    ~Gcm() { (void)psa_destroy_key(key_); }
    Gcm(const Gcm &)            = delete;
    Gcm &operator=(const Gcm &) = delete;

    int setkey(const std::uint8_t *key, std::size_t key_len) noexcept
    {
        (void)psa_destroy_key(key_);
        key_                      = PSA_KEY_ID_NULL;
        psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
        psa_set_key_bits(&attr, key_len * 8);
        psa_set_key_algorithm(&attr, PSA_ALG_GCM);
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
        return detail::status(psa_import_key(&attr, key, key_len, &key_));
    }

    // out receives len bytes of ciphertext followed by the tag.
    int seal(std::uint8_t *out, const std::uint8_t *in, std::size_t len, const std::uint8_t *nonce,
             std::size_t nonce_len) noexcept
    {
        std::size_t olen = 0;
        return detail::status(psa_aead_encrypt(key_, PSA_ALG_GCM, nonce, nonce_len, nullptr, 0, in, len, out,
                                               len + kTag, &olen));
    }

    // in holds len bytes of ciphertext followed by the tag.
    int open(std::uint8_t *out, const std::uint8_t *in, std::size_t len, const std::uint8_t *nonce,
             std::size_t nonce_len) noexcept
    {
        std::size_t olen = 0;
        return detail::status(psa_aead_decrypt(key_, PSA_ALG_GCM, nonce, nonce_len, nullptr, 0, in, len + kTag, out,
                                               len, &olen));
    }

    static constexpr std::size_t kTag = 16;

private:
    psa_key_id_t key_ = PSA_KEY_ID_NULL;
};

// One AES block, as the AEAD-2022 UDP separate header uses.
inline int aes_ecb(const std::uint8_t *key, std::size_t key_len, bool encrypt, const std::uint8_t src[16],
                   std::uint8_t dst[16]) noexcept
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, key_len * 8);
    psa_set_key_algorithm(&attr, PSA_ALG_ECB_NO_PADDING);
    psa_set_key_usage_flags(&attr, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_key_id_t id = PSA_KEY_ID_NULL;
    psa_status_t s  = psa_import_key(&attr, key, key_len, &id);
    if (s == PSA_SUCCESS) {
        std::size_t olen = 0;
        s = encrypt ? psa_cipher_encrypt(id, PSA_ALG_ECB_NO_PADDING, src, 16, dst, 16, &olen)
                    : psa_cipher_decrypt(id, PSA_ALG_ECB_NO_PADDING, src, 16, dst, 16, &olen);
        (void)psa_destroy_key(id);
    }
    return detail::status(s);
}

#else

inline int init() noexcept
{
    return 0;
}

using sha1_context = mbedtls_sha1_context;
using md5_context  = mbedtls_md5_context;

inline void sha1_init(sha1_context *c) noexcept { mbedtls_sha1_init(c); }
inline void sha1_free(sha1_context *c) noexcept { mbedtls_sha1_free(c); }
inline void md5_init(md5_context *c) noexcept { mbedtls_md5_init(c); }
inline void md5_free(md5_context *c) noexcept { mbedtls_md5_free(c); }

#if MBEDTLS_VERSION_NUMBER < 0x03000000
inline int sha1(const unsigned char *in, std::size_t n, unsigned char out[20]) noexcept
{
    return mbedtls_sha1_ret(in, n, out);
}
inline int sha1_starts(sha1_context *c) noexcept { return mbedtls_sha1_starts_ret(c); }
inline int sha1_update(sha1_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return mbedtls_sha1_update_ret(c, in, n);
}
inline int sha1_finish(sha1_context *c, unsigned char out[20]) noexcept
{
    return mbedtls_sha1_finish_ret(c, out);
}
inline int md5_starts(md5_context *c) noexcept { return mbedtls_md5_starts_ret(c); }
inline int md5_update(md5_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return mbedtls_md5_update_ret(c, in, n);
}
inline int md5_finish(md5_context *c, unsigned char out[16]) noexcept
{
    return mbedtls_md5_finish_ret(c, out);
}
#else
inline int sha1(const unsigned char *in, std::size_t n, unsigned char out[20]) noexcept
{
    return mbedtls_sha1(in, n, out);
}
inline int sha1_starts(sha1_context *c) noexcept { return mbedtls_sha1_starts(c); }
inline int sha1_update(sha1_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return mbedtls_sha1_update(c, in, n);
}
inline int sha1_finish(sha1_context *c, unsigned char out[20]) noexcept
{
    return mbedtls_sha1_finish(c, out);
}
inline int md5_starts(md5_context *c) noexcept { return mbedtls_md5_starts(c); }
inline int md5_update(md5_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return mbedtls_md5_update(c, in, n);
}
inline int md5_finish(md5_context *c, unsigned char out[16]) noexcept
{
    return mbedtls_md5_finish(c, out);
}
#endif

// AES-GCM with a 16-byte tag.
class Gcm {
public:
    Gcm() noexcept { mbedtls_gcm_init(&ctx_); }
    ~Gcm() { mbedtls_gcm_free(&ctx_); }
    Gcm(const Gcm &)            = delete;
    Gcm &operator=(const Gcm &) = delete;

    int setkey(const std::uint8_t *key, std::size_t key_len) noexcept
    {
        return mbedtls_gcm_setkey(&ctx_, MBEDTLS_CIPHER_ID_AES, key, static_cast<unsigned>(key_len * 8));
    }

    // out receives len bytes of ciphertext followed by the tag.
    int seal(std::uint8_t *out, const std::uint8_t *in, std::size_t len, const std::uint8_t *nonce,
             std::size_t nonce_len) noexcept
    {
        return mbedtls_gcm_crypt_and_tag(&ctx_, MBEDTLS_GCM_ENCRYPT, len, nonce, nonce_len, nullptr, 0, in, out, kTag,
                                         out + len);
    }

    // in holds len bytes of ciphertext followed by the tag.
    int open(std::uint8_t *out, const std::uint8_t *in, std::size_t len, const std::uint8_t *nonce,
             std::size_t nonce_len) noexcept
    {
        return mbedtls_gcm_auth_decrypt(&ctx_, len, nonce, nonce_len, nullptr, 0, in + len, kTag, in, out);
    }

    static constexpr std::size_t kTag = 16;

private:
    mbedtls_gcm_context ctx_;
};

// One AES block, as the AEAD-2022 UDP separate header uses.
inline int aes_ecb(const std::uint8_t *key, std::size_t key_len, bool encrypt, const std::uint8_t src[16],
                   std::uint8_t dst[16]) noexcept
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    auto bits = static_cast<unsigned>(key_len * 8);
    int rc    = encrypt ? mbedtls_aes_setkey_enc(&aes, key, bits) : mbedtls_aes_setkey_dec(&aes, key, bits);
    if (rc == 0) {
        rc = mbedtls_aes_crypt_ecb(&aes, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, src, dst);
    }
    mbedtls_aes_free(&aes);
    return rc;
}

#endif

} // namespace ss::crypto::mbed

#endif
