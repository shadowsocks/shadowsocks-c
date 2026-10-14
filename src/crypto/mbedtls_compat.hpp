/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CRYPTO_MBEDTLS_COMPAT_HPP
#define SS_CRYPTO_MBEDTLS_COMPAT_HPP

// Mbed TLS 2.x returns void from the plain SHA-1/MD5 functions and int
// from their _ret variants; 3.x keeps only the int-returning plain names.
// These wrappers always return 0 on success.

#include <cstddef>

#include <mbedtls/md5.h>
#include <mbedtls/sha1.h>
#include <mbedtls/version.h>

namespace ss::crypto::mbed {

#if MBEDTLS_VERSION_NUMBER < 0x03000000
inline int sha1(const unsigned char *in, std::size_t n, unsigned char out[20]) noexcept
{
    return mbedtls_sha1_ret(in, n, out);
}
inline int sha1_starts(mbedtls_sha1_context *c) noexcept { return mbedtls_sha1_starts_ret(c); }
inline int sha1_update(mbedtls_sha1_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return mbedtls_sha1_update_ret(c, in, n);
}
inline int sha1_finish(mbedtls_sha1_context *c, unsigned char out[20]) noexcept
{
    return mbedtls_sha1_finish_ret(c, out);
}
inline int md5_starts(mbedtls_md5_context *c) noexcept { return mbedtls_md5_starts_ret(c); }
inline int md5_update(mbedtls_md5_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return mbedtls_md5_update_ret(c, in, n);
}
inline int md5_finish(mbedtls_md5_context *c, unsigned char out[16]) noexcept
{
    return mbedtls_md5_finish_ret(c, out);
}
#else
inline int sha1(const unsigned char *in, std::size_t n, unsigned char out[20]) noexcept
{
    return mbedtls_sha1(in, n, out);
}
inline int sha1_starts(mbedtls_sha1_context *c) noexcept { return mbedtls_sha1_starts(c); }
inline int sha1_update(mbedtls_sha1_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return mbedtls_sha1_update(c, in, n);
}
inline int sha1_finish(mbedtls_sha1_context *c, unsigned char out[20]) noexcept
{
    return mbedtls_sha1_finish(c, out);
}
inline int md5_starts(mbedtls_md5_context *c) noexcept { return mbedtls_md5_starts(c); }
inline int md5_update(mbedtls_md5_context *c, const unsigned char *in, std::size_t n) noexcept
{
    return mbedtls_md5_update(c, in, n);
}
inline int md5_finish(mbedtls_md5_context *c, unsigned char out[16]) noexcept
{
    return mbedtls_md5_finish(c, out);
}
#endif

} // namespace ss::crypto::mbed

#endif
