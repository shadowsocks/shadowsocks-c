/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CRYPTO_KEYS_HPP
#define SS_CRYPTO_KEYS_HPP

// Turning what the user configured into key bytes.

#include <cstddef>
#include <cstdint>
#include <span>

namespace ss::crypto {

// EVP_BytesToKey with MD5 and no salt, the classic shadowsocks password
// stretching. Returns false for a null password.
bool derive_key(const char *password, std::span<std::uint8_t> key) noexcept;

// A URL-safe or standard base64 key. With `exact` (AEAD-2022) the decoded
// key must be exactly key.size() bytes; otherwise it must be at least that
// long and only the first key.size() bytes are used.
bool parse_key(const char *base64, std::span<std::uint8_t> key, bool exact) noexcept;

// Explain a key that does not fit and show a fresh random one of the right
// size, as the C implementation did before exiting.
void report_bad_key(const char *what, std::size_t key_len) noexcept;

} // namespace ss::crypto

#endif
