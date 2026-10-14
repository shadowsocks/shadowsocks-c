/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CRYPTO_STREAM_HPP
#define SS_CRYPTO_STREAM_HPP

// Legacy (unauthenticated) stream ciphers as value types.
//
// Replaces stream.cpp's per-connection mbedtls_cipher_context_t (allocated by
// mbedtls_cipher_setup), its static scratch buffers and the padding copies
// it makes for the libsodium ciphers. The block-cipher contexts are held by
// value through the AES/Camellia APIs directly; the libsodium ciphers track
// their keystream position and handle partial blocks with a 64-byte stack
// block. Only built with SS_ENABLE_LEGACY.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

#include <mbedtls/aes.h>
#include <mbedtls/camellia.h>

#include "core/result.hpp"
#include "crypto/aead.hpp" // ReplayFilter

namespace ss::crypto {

inline constexpr std::size_t kMaxStreamIv  = 16;
inline constexpr std::size_t kMaxStreamKey = 32;

enum class StreamKind : std::uint8_t {
    aes_cfb,
    aes_ctr,
    camellia_cfb,
    salsa20,
    chacha20,
    chacha20_ietf,
};

struct StreamSpec {
    std::string_view name;
    StreamKind kind;
    std::uint8_t key_len;
    std::uint8_t iv_len;
};

// The stream method called `name`, if this build supports it (RC4, table and
// the ciphers Mbed TLS 3 dropped are not).
std::optional<StreamSpec> find_stream(std::string_view name) noexcept;

struct StreamKey {
    StreamSpec spec;
    std::array<std::uint8_t, kMaxStreamKey> bytes{};

    static Result<StreamKey> from_password(const StreamSpec &spec, const char *password) noexcept;
};

// Keystream for one direction of one connection.
class StreamCipher {
public:
    StreamCipher() noexcept = default;
    StreamCipher(const StreamCipher &)            = delete;
    StreamCipher &operator=(const StreamCipher &) = delete;
    ~StreamCipher() { reset(); }

    Status init(const StreamKey &key, std::span<const std::uint8_t> iv, bool encrypt) noexcept;
    void reset() noexcept;

    // XOR the next n keystream bytes; `in` and `out` may be the same buffer.
    Status apply(const std::uint8_t *in, std::uint8_t *out, std::size_t n) noexcept;

private:
    struct Aes {
        Aes() noexcept { mbedtls_aes_init(&ctx); }
        ~Aes() { mbedtls_aes_free(&ctx); }
        Aes(const Aes &)            = delete;
        Aes &operator=(const Aes &) = delete;
        mbedtls_aes_context ctx;
        std::array<unsigned char, 16> iv{};
        std::array<unsigned char, 16> block{};
        std::size_t offset = 0;
        bool ctr           = false;
        int mode           = MBEDTLS_AES_ENCRYPT;
    };
    struct Camellia {
        Camellia() noexcept { mbedtls_camellia_init(&ctx); }
        ~Camellia() { mbedtls_camellia_free(&ctx); }
        Camellia(const Camellia &)            = delete;
        Camellia &operator=(const Camellia &) = delete;
        mbedtls_camellia_context ctx;
        std::array<unsigned char, 16> iv{};
        std::size_t offset = 0;
        int mode           = MBEDTLS_CAMELLIA_ENCRYPT;
    };
    struct Sodium {
        ~Sodium();
        StreamKind kind = StreamKind::salsa20;
        std::array<std::uint8_t, kMaxStreamKey> key{};
        std::array<std::uint8_t, 12> nonce{};
        std::uint64_t position = 0; // keystream bytes used so far
    };

    std::variant<std::monostate, Aes, Camellia, Sodium> impl_;
};

class StreamTcpEncryptor {
public:
    // A fresh random IV.
    Status init(const StreamKey &key, ReplayFilter filter) noexcept;
    std::size_t sealed_size(std::size_t plaintext_len) const noexcept
    {
        return plaintext_len + (iv_sent_ ? 0 : key_.spec.iv_len);
    }
    // The first call also emits the IV; returns the bytes written.
    Result<std::size_t> seal(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> out) noexcept;
    std::span<const std::uint8_t> iv() const noexcept { return { iv_.data(), key_.spec.iv_len }; }

private:
    StreamKey key_{};
    ReplayFilter filter_{};
    StreamCipher cipher_;
    std::array<std::uint8_t, kMaxStreamIv> iv_{};
    bool iv_sent_ = false;
};

class StreamTcpDecryptor {
public:
    Status init(const StreamKey &key, ReplayFilter filter) noexcept;

    struct Step {
        std::size_t consumed;
        std::size_t produced;
    };
    // Collect the IV, then decrypt min(remaining input, out.size()) bytes.
    // Fails with Errc::crypto when the IV was seen before.
    Result<Step> decrypt(std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept;
    bool iv_received() const noexcept { return ready_; }

private:
    StreamKey key_{};
    ReplayFilter filter_{};
    StreamCipher cipher_;
    std::array<std::uint8_t, kMaxStreamIv> iv_{};
    std::size_t iv_have_ = 0;
    bool ready_          = false;
    bool failed_         = false;
};

// One-shot UDP packet: [iv][ciphertext].
Result<std::size_t> stream_udp_seal(const StreamKey &key, std::span<const std::uint8_t> plaintext,
                                    std::span<std::uint8_t> out, ReplayFilter filter) noexcept;
Result<std::size_t> stream_udp_open(const StreamKey &key, std::span<const std::uint8_t> packet,
                                    std::span<std::uint8_t> out, ReplayFilter filter) noexcept;

} // namespace ss::crypto

#endif
