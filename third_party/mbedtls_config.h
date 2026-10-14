/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_MBEDTLS_CONFIG_H
#define SS_MBEDTLS_CONFIG_H
/* Only the primitives used by Shadowsocks. No TLS, X.509, networking, public
 * key operations, PSA storage or independent entropy subsystem. Randomness
 * is supplied by libsodium. MD5/SHA1 remain required by legacy AEAD key
 * derivation even when legacy stream ciphers are disabled. */
#define MBEDTLS_AES_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_GCM_C
/* GCM on the block-cipher layer keeps the AES context inside
 * mbedtls_gcm_context, so mbedtls_gcm_setkey() does not allocate. Mbed TLS
 * only enables this by itself when MBEDTLS_CIPHER_C is off, and the legacy
 * stream ciphers need MBEDTLS_CIPHER_C. */
#define MBEDTLS_BLOCK_CIPHER_C
#define MBEDTLS_MD_C
#define MBEDTLS_MD5_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_PLATFORM_C
/* The programs route Mbed TLS allocations into a bounded heap. */
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_VERSION_C
#define MBEDTLS_VERSION_FEATURES
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CAMELLIA_C
#if defined(__x86_64__) || defined(_M_X64)
#define MBEDTLS_AESNI_C
#if defined(__GNUC__) || defined(__clang__)
#define MBEDTLS_HAVE_ASM
#endif
#endif
#if defined(__aarch64__)
#define MBEDTLS_AESCE_C
#endif
#endif
