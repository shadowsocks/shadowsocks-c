/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_RELAY_CODEC_HPP
#define SS_RELAY_CODEC_HPP

// The cipher a relay is configured with, and the per-connection encoder and
// decoder built from it. Every connection holds both by value; which kind is
// live is chosen per connection, because a connection that bypasses the
// proxy (ACL) is plain.

#include <cstddef>
#include <cstdint>
#include <span>
#include <variant>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "core/result.hpp"
#include "crypto/aead.hpp"
#include "crypto/aead2022.hpp"

namespace ss::relay {

using crypto::Role;

class Method {
public:
    // The same inputs as crypto_init(): a method name and either a password
    // or a base64 key (AEAD-2022 needs the key). Also initialises libsodium
    // and the process-wide ppbloom replay filter, sized for the role.
    Status init(const char *method, const char *password, const char *key, Role role) noexcept;
    Method() = default;
    // It owns the process-wide replay filter: a copy would free it twice.
    Method(const Method &)            = delete;
    Method &operator=(const Method &) = delete;
    ~Method();

    Role role() const noexcept { return role_; }
    // The key, by family (exactly one is set).
    const crypto::MasterKey *aead() const noexcept { return std::get_if<crypto::MasterKey>(&key_); }
    const crypto::Psk *psk() const noexcept { return std::get_if<crypto::Psk>(&key_); }
    bool is_2022() const noexcept { return std::holds_alternative<crypto::Psk>(key_); }
    // Room a first seal() needs on top of the plaintext.
    static constexpr std::size_t kMaxOverhead = 2048;

    // AEAD-2022 servers remember every request salt for a minute.
    Status reserve_salt_pool(std::uint32_t capacity, std::uint64_t seed) noexcept
    {
        return salt_pool_.reserve(capacity, seed);
    }

private:
    friend class Encoder;
    friend class Decoder;

    using Key = std::variant<crypto::MasterKey, crypto::Psk>;
    Key key_{};
    Role role_        = Role::client;
    bool bloom_ready_ = false;
    crypto::SaltPool salt_pool_;
};

class Decoder;

class Encoder {
public:
    // `plain` skips encryption (a direct connection). An AEAD-2022 server
    // encoder answers the request `peer` decoded.
    Status init(Method &method, bool plain, const Decoder *peer, bool printable_salt = false) noexcept;

    std::size_t sealed_size(std::size_t plaintext_len) const noexcept;
    Result<std::size_t> seal(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> out) noexcept;
    std::span<const std::uint8_t> salt_2022() const noexcept;

private:
    struct Plain {};
    std::variant<Plain, crypto::AeadTcpEncryptor, crypto::Aead2022TcpEncryptor> impl_;
};

class Decoder {
public:
    struct Step {
        std::size_t consumed;
        std::size_t produced;
    };

    // An AEAD-2022 client decoder checks the response against `peer`'s salt.
    Status init(Method &method, bool plain, const Encoder *peer) noexcept;

    // Input bytes the next decrypt() consumes in full.
    std::size_t accept_limit() const noexcept;
    // Decrypt into `out`; a decoder may keep plaintext back when `out` is
    // small, so call again with an empty input to drain it. `out` must hold
    // at least kMinOutput bytes.
    Result<Step> decrypt(std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept;
    bool is_2022() const noexcept { return std::holds_alternative<crypto::Aead2022TcpDecryptor>(impl_); }
    const crypto::Aead2022TcpDecryptor *as_2022() const noexcept
    {
        return std::get_if<crypto::Aead2022TcpDecryptor>(&impl_);
    }

    static constexpr std::size_t kMinOutput = crypto::kMaxChunk;

private:
    struct Plain {};
    std::variant<Plain, crypto::AeadTcpDecryptor, crypto::Aead2022TcpDecryptor> impl_;
};

} // namespace ss::relay

#endif
