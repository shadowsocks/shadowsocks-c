/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "crypto/stream.hpp"

#include <algorithm>
#include <cstring>

#include <sodium.h>

#include "crypto.h"

// crypto.h defines min/max macros for the C sources.
#undef min
#undef max

namespace ss::crypto {

namespace {

constexpr StreamSpec kStreams[] = {
    { "aes-128-cfb", StreamKind::aes_cfb, 16, 16 },
    { "aes-192-cfb", StreamKind::aes_cfb, 24, 16 },
    { "aes-256-cfb", StreamKind::aes_cfb, 32, 16 },
    { "aes-128-ctr", StreamKind::aes_ctr, 16, 16 },
    { "aes-192-ctr", StreamKind::aes_ctr, 24, 16 },
    { "aes-256-ctr", StreamKind::aes_ctr, 32, 16 },
    { "camellia-128-cfb", StreamKind::camellia_cfb, 16, 16 },
    { "camellia-192-cfb", StreamKind::camellia_cfb, 24, 16 },
    { "camellia-256-cfb", StreamKind::camellia_cfb, 32, 16 },
    { "salsa20", StreamKind::salsa20, 32, 8 },
    { "chacha20", StreamKind::chacha20, 32, 8 },
    { "chacha20-ietf", StreamKind::chacha20_ietf, 32, 12 },
};

constexpr std::size_t kSodiumBlock = 64;

int sodium_xor(StreamKind kind, std::uint8_t *out, const std::uint8_t *in, std::size_t n, const std::uint8_t *nonce,
               std::uint64_t block, const std::uint8_t *key) noexcept
{
    switch (kind) {
    case StreamKind::salsa20:
        return crypto_stream_salsa20_xor_ic(out, in, n, nonce, block, key);
    case StreamKind::chacha20:
        return crypto_stream_chacha20_xor_ic(out, in, n, nonce, block, key);
    case StreamKind::chacha20_ietf:
        return crypto_stream_chacha20_ietf_xor_ic(out, in, n, nonce, static_cast<std::uint32_t>(block), key);
    default:
        return -1;
    }
}

} // namespace

std::optional<StreamSpec> find_stream(std::string_view name) noexcept
{
    for (const StreamSpec &spec : kStreams) {
        if (spec.name == name) {
            return spec;
        }
    }
    return std::nullopt;
}

Result<StreamKey> StreamKey::from_password(const StreamSpec &spec, const char *password) noexcept
{
    if (password == nullptr) {
        return fail(Errc::config);
    }
    StreamKey key{ spec, {} };
    if (crypto_derive_key(password, key.bytes.data(), spec.key_len) != spec.key_len) {
        return fail(Errc::config);
    }
    return key;
}

StreamCipher::Sodium::~Sodium()
{
    sodium_memzero(key.data(), key.size());
}

Status StreamCipher::init(const StreamKey &key, std::span<const std::uint8_t> iv, bool encrypt) noexcept
{
    if (iv.size() != key.spec.iv_len) {
        return fail(Errc::invalid);
    }
    const unsigned bits = key.spec.key_len * 8U;
    switch (key.spec.kind) {
    case StreamKind::aes_cfb:
    case StreamKind::aes_ctr: {
        auto &aes = impl_.emplace<Aes>();
        // CFB and CTR only ever run the block cipher forwards.
        if (mbedtls_aes_setkey_enc(&aes.ctx, key.bytes.data(), bits) != 0) {
            return fail(Errc::crypto);
        }
        std::memcpy(aes.iv.data(), iv.data(), 16);
        aes.ctr  = key.spec.kind == StreamKind::aes_ctr;
        aes.mode = encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
        return {};
    }
    case StreamKind::camellia_cfb: {
        auto &cam = impl_.emplace<Camellia>();
        if (mbedtls_camellia_setkey_enc(&cam.ctx, key.bytes.data(), bits) != 0) {
            return fail(Errc::crypto);
        }
        std::memcpy(cam.iv.data(), iv.data(), 16);
        cam.mode = encrypt ? MBEDTLS_CAMELLIA_ENCRYPT : MBEDTLS_CAMELLIA_DECRYPT;
        return {};
    }
    case StreamKind::salsa20:
    case StreamKind::chacha20:
    case StreamKind::chacha20_ietf: {
        auto &s = impl_.emplace<Sodium>();
        s.kind  = key.spec.kind;
        std::memcpy(s.key.data(), key.bytes.data(), key.spec.key_len);
        std::memcpy(s.nonce.data(), iv.data(), iv.size());
        s.position = 0;
        return {};
    }
    }
    return fail(Errc::invalid);
}

void StreamCipher::reset() noexcept
{
    impl_.emplace<std::monostate>();
}

Status StreamCipher::apply(const std::uint8_t *in, std::uint8_t *out, std::size_t n) noexcept
{
    if (n == 0) {
        return {};
    }
    int rc = -1;
    if (auto *aes = std::get_if<Aes>(&impl_)) {
        if (aes->ctr) {
            rc = mbedtls_aes_crypt_ctr(&aes->ctx, n, &aes->offset, aes->iv.data(), aes->block.data(), in, out);
        } else {
            rc = mbedtls_aes_crypt_cfb128(&aes->ctx, aes->mode, n, &aes->offset, aes->iv.data(), in, out);
        }
    } else if (auto *cam = std::get_if<Camellia>(&impl_)) {
        rc = mbedtls_camellia_crypt_cfb128(&cam->ctx, cam->mode, n, &cam->offset, cam->iv.data(), in, out);
    } else if (auto *s = std::get_if<Sodium>(&impl_)) {
        rc                = 0;
        std::size_t inner = static_cast<std::size_t>(s->position % kSodiumBlock);
        if (inner != 0) {
            // Finish the current keystream block from a scratch copy.
            std::uint8_t block[kSodiumBlock] = {};
            rc = sodium_xor(s->kind, block, block, kSodiumBlock, s->nonce.data(), s->position / kSodiumBlock,
                            s->key.data());
            std::size_t take = std::min(kSodiumBlock - inner, n);
            for (std::size_t i = 0; i < take; ++i) {
                out[i] = in[i] ^ block[inner + i];
            }
            sodium_memzero(block, sizeof(block));
            in += take;
            out += take;
            n -= take;
            s->position += take;
        }
        if (rc == 0 && n != 0) {
            rc = sodium_xor(s->kind, out, in, n, s->nonce.data(), s->position / kSodiumBlock, s->key.data());
            s->position += n;
        }
    }
    if (rc != 0) {
        return fail(Errc::crypto);
    }
    return {};
}

Status StreamTcpEncryptor::init(const StreamKey &key, ReplayFilter filter) noexcept
{
    key_     = key;
    filter_  = filter;
    iv_sent_ = false;
    randombytes_buf(iv_.data(), key.spec.iv_len);
    return cipher_.init(key_, iv(), true);
}

Result<std::size_t> StreamTcpEncryptor::seal(std::span<const std::uint8_t> plaintext,
                                             std::span<std::uint8_t> out) noexcept
{
    if (plaintext.empty()) {
        return std::size_t{ 0 };
    }
    if (out.size() < sealed_size(plaintext.size())) {
        return fail(Errc::invalid);
    }
    std::size_t at = 0;
    if (!iv_sent_) {
        std::memcpy(out.data(), iv_.data(), key_.spec.iv_len);
        at += key_.spec.iv_len;
        filter_.add(iv());
        iv_sent_ = true;
    }
    SS_TRY(cipher_.apply(plaintext.data(), out.data() + at, plaintext.size()));
    return at + plaintext.size();
}

Status StreamTcpDecryptor::init(const StreamKey &key, ReplayFilter filter) noexcept
{
    key_     = key;
    filter_  = filter;
    iv_have_ = 0;
    ready_   = false;
    failed_  = false;
    cipher_.reset();
    return {};
}

Result<StreamTcpDecryptor::Step> StreamTcpDecryptor::decrypt(std::span<const std::uint8_t> in,
                                                              std::span<std::uint8_t> out) noexcept
{
    if (failed_) {
        return fail(Errc::closed);
    }
    Step step{ 0, 0 };
    if (!ready_) {
        std::size_t want = key_.spec.iv_len - iv_have_;
        std::size_t take = std::min(want, in.size());
        if (take != 0) { // an empty span may have a null data()
            std::memcpy(iv_.data() + iv_have_, in.data(), take);
        }
        iv_have_ += take;
        step.consumed += take;
        in = in.subspan(take);
        if (iv_have_ < key_.spec.iv_len) {
            return step;
        }
        std::span<const std::uint8_t> iv(iv_.data(), key_.spec.iv_len);
        // Register the IV as soon as it is known, as the C decoder does, so
        // a concurrent connection cannot replay it in the meantime.
        if (filter_.check(iv)) {
            failed_ = true;
            return fail(Errc::crypto);
        }
        filter_.add(iv);
        Status st = cipher_.init(key_, iv, false);
        if (!st) {
            failed_ = true;
            return fail(st.error());
        }
        ready_ = true;
    }
    std::size_t n = std::min(in.size(), out.size());
    SS_TRY(cipher_.apply(in.data(), out.data(), n));
    step.consumed += n;
    step.produced = n;
    return step;
}

Result<std::size_t> stream_udp_seal(const StreamKey &key, std::span<const std::uint8_t> plaintext,
                                    std::span<std::uint8_t> out, ReplayFilter filter) noexcept
{
    const std::size_t iv_len = key.spec.iv_len;
    if (out.size() < iv_len + plaintext.size()) {
        return fail(Errc::invalid);
    }
    randombytes_buf(out.data(), iv_len);
    std::span<const std::uint8_t> iv(out.data(), iv_len);
    filter.add(iv);
    StreamCipher cipher;
    SS_TRY(cipher.init(key, iv, true));
    SS_TRY(cipher.apply(plaintext.data(), out.data() + iv_len, plaintext.size()));
    return iv_len + plaintext.size();
}

Result<std::size_t> stream_udp_open(const StreamKey &key, std::span<const std::uint8_t> packet,
                                    std::span<std::uint8_t> out, ReplayFilter filter) noexcept
{
    const std::size_t iv_len = key.spec.iv_len;
    if (packet.size() <= iv_len) {
        return fail(Errc::protocol);
    }
    std::size_t n = packet.size() - iv_len;
    if (out.size() < n) {
        return fail(Errc::invalid);
    }
    std::span<const std::uint8_t> iv = packet.first(iv_len);
    if (filter.check(iv)) {
        return fail(Errc::crypto);
    }
    StreamCipher cipher;
    SS_TRY(cipher.init(key, iv, false));
    SS_TRY(cipher.apply(packet.data() + iv_len, out.data(), n));
    filter.add(iv);
    return n;
}

} // namespace ss::crypto
