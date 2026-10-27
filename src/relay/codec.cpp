/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "relay/codec.hpp"

#include <algorithm>
#include <cstring>

#include "crypto/keys.hpp"
#include "ppbloom.h"
#include "utils.h"

namespace ss::relay {

namespace {

// Ping-pong bloom filter sizing, as in the C implementation.
constexpr int kBloomEntriesServer   = 1000000;
constexpr double kBloomErrorServer  = 1e-10;
constexpr int kBloomEntriesClient   = 10000;
constexpr double kBloomErrorClient  = 1e-15;

} // namespace

Status Method::init(const char *method, const char *password, const char *key, Role role) noexcept
{
    if (method == nullptr) {
        return fail(Errc::config);
    }
    if (sodium_init() == -1) {
        return fail(Errc::crypto);
    }
    role_ = role;
    // The salt/IV replay filter shared by every connection and datagram.
    if (!bloom_ready_) {
        int err = role == Role::server ? ppbloom_init(kBloomEntriesServer, kBloomErrorServer)
                                       : ppbloom_init(kBloomEntriesClient, kBloomErrorClient);
        if (err != 0) {
            LOGE("failed to set up the replay filter");
            return fail(Errc::exhausted);
        }
        bloom_ready_ = true;
    }
    if (auto spec = crypto::find_aead2022(method)) {
        // The password field may carry the base64 PSK too.
        auto psk = crypto::Psk::from_base64(*spec, key != nullptr ? key : password);
        if (!psk) {
            crypto::report_bad_key("pre-shared key", spec->aead.key_len);
            return fail(psk.error());
        }
        key_ = *psk;
        return {};
    }
    if (auto spec = crypto::find_aead(method)) {
        if (key != nullptr) {
            auto master = crypto::MasterKey::from_base64(*spec, key);
            if (!master) {
                crypto::report_bad_key("key", spec->key_len);
                return fail(master.error());
            }
            key_ = *master;
        } else {
            SS_TRY_ASSIGN(master, crypto::MasterKey::from_password(*spec, password));
            key_ = master;
        }
        return {};
    }
    // The unauthenticated stream ciphers (and RC4/table before them) were
    // removed; say so instead of calling the name unknown.
    static constexpr const char *kRemoved[] = {
        "table", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr",
        "aes-256-ctr", "bf-cfb", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "cast5-cfb",
        "des-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "salsa20", "chacha20", "chacha20-ietf",
    };
    for (const char *name : kRemoved) {
        if (std::strcmp(name, method) == 0) {
            LOGE("stream cipher %s is no longer supported; use an AEAD method such as chacha20-ietf-poly1305 "
                 "or 2022-blake3-aes-256-gcm",
                 method);
            return fail(Errc::config);
        }
    }
    LOGE("unsupported method: %s", method);
    return fail(Errc::config);
}

Method::~Method()
{
    if (bloom_ready_) {
        ppbloom_free();
    }
}

Status Encoder::init(Method &method, bool plain, const Decoder *peer, bool printable_salt) noexcept
{
    if (plain) {
        impl_.emplace<Plain>();
        return {};
    }
    const crypto::ReplayFilter filter = crypto::ReplayFilter::ppbloom();
    if (auto *master = std::get_if<crypto::MasterKey>(&method.key_)) {
        return impl_.emplace<crypto::AeadTcpEncryptor>().init(*master, filter, printable_salt);
    }
    if (auto *psk = std::get_if<crypto::Psk>(&method.key_)) {
        const crypto::Aead2022TcpDecryptor *request = peer != nullptr ? peer->as_2022() : nullptr;
        return impl_.emplace<crypto::Aead2022TcpEncryptor>().init(*psk, method.role_, request);
    }
    return fail(Errc::config);
}

// Explicit dispatch: std::visit can report bad_variant_access through the
// C++ runtime, which the programs do not link.
std::size_t Encoder::sealed_size(std::size_t plaintext_len) const noexcept
{
    if (auto *e = std::get_if<crypto::AeadTcpEncryptor>(&impl_)) {
        return e->sealed_size(plaintext_len);
    }
    if (auto *e = std::get_if<crypto::Aead2022TcpEncryptor>(&impl_)) {
        return e->sealed_size(plaintext_len);
    }
    return plaintext_len;
}

Result<std::size_t> Encoder::seal(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> out) noexcept
{
    if (auto *e = std::get_if<crypto::AeadTcpEncryptor>(&impl_)) {
        return e->seal(plaintext, out);
    }
    if (auto *e = std::get_if<crypto::Aead2022TcpEncryptor>(&impl_)) {
        return e->seal(plaintext, out);
    }
    if (out.size() < plaintext.size()) {
        return fail(Errc::invalid);
    }
    if (!plaintext.empty()) {
        std::memcpy(out.data(), plaintext.data(), plaintext.size());
    }
    return plaintext.size();
}

std::span<const std::uint8_t> Encoder::salt_2022() const noexcept
{
    if (auto *e = std::get_if<crypto::Aead2022TcpEncryptor>(&impl_)) {
        return e->salt();
    }
    return {};
}

Status Decoder::init(Method &method, bool plain, const Encoder *peer) noexcept
{
    if (plain) {
        impl_.emplace<Plain>();
        return {};
    }
    const crypto::ReplayFilter filter = crypto::ReplayFilter::ppbloom();
    if (auto *master = std::get_if<crypto::MasterKey>(&method.key_)) {
        return impl_.emplace<crypto::AeadTcpDecryptor>().init(*master, filter);
    }
    if (auto *psk = std::get_if<crypto::Psk>(&method.key_)) {
        if (method.role_ == Role::client) {
            if (peer == nullptr) {
                return fail(Errc::invalid);
            }
            return impl_.emplace<crypto::Aead2022TcpDecryptor>().init(*psk, Role::client, peer->salt_2022());
        }
        return impl_.emplace<crypto::Aead2022TcpDecryptor>().init(*psk, Role::server, {}, &method.salt_pool_);
    }
    return fail(Errc::config);
}

std::size_t Decoder::accept_limit() const noexcept
{
    if (auto *d = std::get_if<crypto::AeadTcpDecryptor>(&impl_)) {
        return d->accept_limit();
    }
    if (auto *d = std::get_if<crypto::Aead2022TcpDecryptor>(&impl_)) {
        return d->accept_limit();
    }
    return SIZE_MAX; // plain decodes as much as there is room for
}

Result<Decoder::Step> Decoder::decrypt(std::span<const std::uint8_t> in, std::span<std::uint8_t> out) noexcept
{
    auto convert = [](auto step) -> Result<Step> {
        if (!step) {
            return fail(step.error());
        }
        return Step{ step->consumed, step->produced };
    };
    if (auto *d = std::get_if<crypto::AeadTcpDecryptor>(&impl_)) {
        return convert(d->decrypt(in, out));
    }
    if (auto *d = std::get_if<crypto::Aead2022TcpDecryptor>(&impl_)) {
        return convert(d->decrypt(in, out));
    }
    std::size_t n = std::min(in.size(), out.size());
    if (n != 0) {
        std::memcpy(out.data(), in.data(), n);
    }
    return Step{ n, n };
}


} // namespace ss::relay
