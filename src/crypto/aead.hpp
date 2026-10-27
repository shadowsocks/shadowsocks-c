/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CRYPTO_AEAD_HPP
#define SS_CRYPTO_AEAD_HPP

// SIP004/SIP007 AEAD ciphers as value types.
//
// Replaces the per-connection heap state of aead.cpp (an mbedtls cipher
// context, an aligned libsodium AES-GCM state and a lazily allocated chunk
// buffer, plus two HMAC contexts allocated by every HKDF call). Everything
// here lives inside the object that uses it:
//
//   AeadEngine        one subkey, ready to seal/open; holds the libsodium
//                     or Mbed TLS GCM state by value
//   AeadTcpEncryptor  salt + length/payload chunk stream
//   AeadTcpDecryptor  the reverse, with a fixed reassembly buffer for one
//                     partial chunk
//   aead_udp_seal/open  one-shot packets
//
// With the bundled Mbed TLS (MBEDTLS_BLOCK_CIPHER_C) GCM key setup does not
// allocate either. System Mbed TLS builds without it may still allocate
// inside mbedtls_gcm_setkey.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>

#include <mbedtls/gcm.h>
#include <sodium.h>

#include "core/buffer.hpp"
#include "core/result.hpp"

namespace ss::crypto {

inline constexpr std::size_t kMaxKey       = 32;
inline constexpr std::size_t kMaxNonce     = 24;
inline constexpr std::size_t kTag          = 16;
inline constexpr std::size_t kChunkLenSize = 2;
inline constexpr std::size_t kMaxChunk     = 0x3FFF; // payload bytes per TCP chunk
// Largest encrypted chunk on the wire.
inline constexpr std::size_t kMaxChunkWire = kChunkLenSize + kTag + kMaxChunk + kTag;

enum class AeadKind : std::uint8_t {
    aes_128_gcm,
    aes_192_gcm,
    aes_256_gcm,
    chacha20_poly1305,
    xchacha20_poly1305,
};

struct AeadSpec {
    std::string_view name;
    AeadKind kind;
    std::uint8_t key_len;
    std::uint8_t nonce_len;
    std::uint8_t tag_len;
};

// The classic (non-2022) AEAD method called `name`, if supported.
std::optional<AeadSpec> find_aead(std::string_view name) noexcept;

// The master key shared by both peers.
struct MasterKey {
    AeadSpec spec;
    std::array<std::uint8_t, kMaxKey> bytes{};

    MasterKey() noexcept = default;
    MasterKey(const AeadSpec &s, const std::array<std::uint8_t, kMaxKey> &b) noexcept : spec(s), bytes(b) {}
    MasterKey(const MasterKey &) noexcept            = default;
    MasterKey &operator=(const MasterKey &) noexcept = default;
    ~MasterKey() { sodium_memzero(bytes.data(), bytes.size()); }

    std::span<const std::uint8_t> key() const noexcept { return { bytes.data(), spec.key_len }; }

    // EVP_BytesToKey(MD5) from a password, as the C implementation does.
    static Result<MasterKey> from_password(const AeadSpec &spec, const char *password) noexcept;
    // A base64 (URL-safe) encoded key of exactly spec.key_len bytes.
    static Result<MasterKey> from_base64(const AeadSpec &spec, const char *key) noexcept;
};

// HKDF-SHA1(salt, ikm, info) -> okm (RFC 5869), using SHA-1 state on the
// stack; okm may be up to 255 * 20 bytes.
Status hkdf_sha1(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm,
                 std::span<const std::uint8_t> info, std::span<std::uint8_t> okm) noexcept;

// Session subkey for a salt: HKDF-SHA1(salt, master, "ss-subkey").
Status derive_subkey(const MasterKey &master, std::span<const std::uint8_t> salt,
                     std::span<std::uint8_t> subkey) noexcept;

// Salt replay protection hook (the ping-pong bloom filter in production).
struct ReplayFilter {
    bool (*seen)(void *ctx, std::span<const std::uint8_t> salt) noexcept = nullptr;
    void (*remember)(void *ctx, std::span<const std::uint8_t> salt) noexcept = nullptr;
    void *ctx = nullptr;

    bool check(std::span<const std::uint8_t> salt) const noexcept { return seen != nullptr && seen(ctx, salt); }
    void add(std::span<const std::uint8_t> salt) const noexcept
    {
        if (remember != nullptr) {
            remember(ctx, salt);
        }
    }

    // The process-wide ppbloom filter used by the C implementation.
    static ReplayFilter ppbloom() noexcept;
};

class AeadEngine {
public:
    AeadEngine() noexcept = default;
    AeadEngine(const AeadEngine &)            = delete;
    AeadEngine &operator=(const AeadEngine &) = delete;
    ~AeadEngine() { reset(); }

    Status init(const AeadSpec &spec, std::span<const std::uint8_t> subkey) noexcept;
    void reset() noexcept;

    // out must hold plaintext.size() + tag bytes.
    Status seal(std::uint8_t *out, std::span<const std::uint8_t> plaintext, const std::uint8_t *nonce) noexcept;
    // out must hold ciphertext.size() - tag bytes; fails on authentication errors.
    Status open(std::uint8_t *out, std::span<const std::uint8_t> ciphertext, const std::uint8_t *nonce) noexcept;

    const AeadSpec &spec() const noexcept { return spec_; }

private:
    struct MbedGcm {
        MbedGcm() noexcept { mbedtls_gcm_init(&ctx); }
        ~MbedGcm() { mbedtls_gcm_free(&ctx); }
        MbedGcm(const MbedGcm &)            = delete;
        MbedGcm &operator=(const MbedGcm &) = delete;
        mbedtls_gcm_context ctx;
    };
    struct SodiumAes256Gcm {
        ~SodiumAes256Gcm() { sodium_memzero(&state, sizeof(state)); }
        alignas(16) crypto_aead_aes256gcm_state state;
    };
    struct SodiumChacha {
        ~SodiumChacha() { sodium_memzero(key.data(), key.size()); }
        std::array<std::uint8_t, kMaxKey> key{};
    };

    AeadSpec spec_{};
    std::variant<std::monostate, MbedGcm, SodiumAes256Gcm, SodiumChacha> impl_;
};

class AeadTcpEncryptor {
public:
    // A fresh random salt; with `printable_salt` the first 6-12 bytes are
    // printable ASCII (the ss-local experiment, TCP only).
    Status init(const MasterKey &master, ReplayFilter filter, bool printable_salt = false) noexcept;

    // Bytes seal() writes for `plaintext_len` input.
    std::size_t sealed_size(std::size_t plaintext_len) const noexcept;

    // Encrypt `plaintext` (any length; split into chunks of at most
    // kMaxChunk) into `out`, which must hold sealed_size() bytes. The first
    // call also emits the salt. Returns the bytes written.
    Result<std::size_t> seal(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> out) noexcept;

    std::span<const std::uint8_t> salt() const noexcept { return { salt_.data(), master_.spec.key_len }; }

private:
    MasterKey master_{};
    ReplayFilter filter_{};
    AeadEngine engine_;
    std::array<std::uint8_t, kMaxKey> salt_{};
    std::array<std::uint8_t, kMaxNonce> nonce_{};
    bool salt_sent_ = false;
};

class AeadTcpDecryptor {
public:
    AeadTcpDecryptor() noexcept = default;
    AeadTcpDecryptor(const AeadTcpDecryptor &) = delete;
    AeadTcpDecryptor &operator=(const AeadTcpDecryptor &) = delete;
    // The reassembly buffer held decrypted payload.
    ~AeadTcpDecryptor() { sodium_memzero(buffer_.storage().data(), buffer_.storage().size()); }

    Status init(const MasterKey &master, ReplayFilter filter) noexcept;

    struct Step {
        std::size_t consumed; // input bytes taken into the reassembly buffer
        std::size_t produced; // plaintext bytes written to `out`
    };

    // Take as much of `in` as fits, then decrypt every complete chunk whose
    // payload fits in `out`. Call again with the rest of the input, or with
    // more output space, until both consumed and produced are 0. Fails with
    // Errc::crypto on authentication errors or a replayed salt and with
    // Errc::protocol on a malformed chunk; the stream is dead after that.
    Result<Step> decrypt(std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept;

    // Bytes received but not yet decrypted.
    std::size_t pending() const noexcept { return buffer_.size(); }
    // Input bytes the next decrypt() takes in full.
    std::size_t accept_limit() const noexcept { return buffer_.capacity() - buffer_.size(); }
    bool salt_received() const noexcept { return engine_ready_; }

private:
    MasterKey master_{};
    ReplayFilter filter_{};
    AeadEngine engine_;
    std::array<std::uint8_t, kMaxKey> salt_{};
    std::array<std::uint8_t, kMaxNonce> nonce_{};
    // One salt plus one complete chunk always fits, so a stalled peer cannot
    // make the buffer grow and a full buffer always holds decryptable data.
    FixedBuffer<kMaxKey + kMaxChunkWire> buffer_;
    std::size_t pending_payload_ = 0; // decoded length of the next chunk, 0 if unknown
    bool engine_ready_           = false;
    bool salt_remembered_        = false;
    bool failed_                 = false;
};

// One-shot UDP packet: [salt][ciphertext][tag]. `out` must hold
// key_len + plaintext.size() + tag bytes. Returns the bytes written.
Result<std::size_t> aead_udp_seal(const MasterKey &master, std::span<const std::uint8_t> plaintext,
                                  std::span<std::uint8_t> out, ReplayFilter filter) noexcept;
// Returns the plaintext length written to `out` (at least packet size -
// salt - tag bytes).
Result<std::size_t> aead_udp_open(const MasterKey &master, std::span<const std::uint8_t> packet,
                                  std::span<std::uint8_t> out, ReplayFilter filter) noexcept;

} // namespace ss::crypto

#endif
