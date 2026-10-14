/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "crypto/aead.hpp"
#include "crypto/mbedtls_compat.hpp"

#include <algorithm>
#include <cstring>

#include <mbedtls/sha1.h>

#include "crypto/keys.hpp"
#include "ppbloom.h"

namespace ss::crypto {

namespace {

// [cli-aead-ciphers]
constexpr AeadSpec kSpecs[] = {
    { "aes-128-gcm", AeadKind::aes_128_gcm, 16, 12, 16 },
    { "aes-192-gcm", AeadKind::aes_192_gcm, 24, 12, 16 },
    { "aes-256-gcm", AeadKind::aes_256_gcm, 32, 12, 16 },
    { "chacha20-ietf-poly1305", AeadKind::chacha20_poly1305, 32, 12, 16 },
#ifdef crypto_aead_xchacha20poly1305_ietf_ABYTES
    { "xchacha20-ietf-poly1305", AeadKind::xchacha20_poly1305, 32, 24, 16 },
#endif
};
// [cli-aead-ciphers]

constexpr std::string_view kSubkeyInfo = "ss-subkey";

bool is_gcm(AeadKind kind) noexcept
{
    return kind == AeadKind::aes_128_gcm || kind == AeadKind::aes_192_gcm || kind == AeadKind::aes_256_gcm;
}

// RFC 2104 HMAC-SHA1 with all state on the stack.
class HmacSha1 {
public:
    static constexpr std::size_t kSize  = 20;
    static constexpr std::size_t kBlock = 64;

    explicit HmacSha1(std::span<const std::uint8_t> key) noexcept
    {
        std::array<std::uint8_t, kBlock> block{};
        if (key.size() > kBlock) {
            (void)mbed::sha1(key.data(), key.size(), block.data());
        } else if (!key.empty()) {
            std::memcpy(block.data(), key.data(), key.size());
        }
        for (std::size_t i = 0; i < kBlock; ++i) {
            ipad_[i] = block[i] ^ 0x36;
            opad_[i] = block[i] ^ 0x5c;
        }
        sodium_memzero(block.data(), block.size());
        mbedtls_sha1_init(&inner_);
        ok_ = mbed::sha1_starts(&inner_) == 0 && mbed::sha1_update(&inner_, ipad_.data(), kBlock) == 0;
    }
    ~HmacSha1()
    {
        mbedtls_sha1_free(&inner_);
        sodium_memzero(ipad_.data(), ipad_.size());
        sodium_memzero(opad_.data(), opad_.size());
    }
    HmacSha1(const HmacSha1 &)            = delete;
    HmacSha1 &operator=(const HmacSha1 &) = delete;

    void update(std::span<const std::uint8_t> data) noexcept
    {
        ok_ = ok_ && mbed::sha1_update(&inner_, data.data(), data.size()) == 0;
    }

    bool finish(std::uint8_t (&mac)[kSize]) noexcept
    {
        std::uint8_t inner_hash[kSize];
        ok_ = ok_ && mbed::sha1_finish(&inner_, inner_hash) == 0;
        mbedtls_sha1_context outer;
        mbedtls_sha1_init(&outer);
        ok_ = ok_ && mbed::sha1_starts(&outer) == 0 && mbed::sha1_update(&outer, opad_.data(), kBlock) == 0
              && mbed::sha1_update(&outer, inner_hash, kSize) == 0 && mbed::sha1_finish(&outer, mac) == 0;
        mbedtls_sha1_free(&outer);
        sodium_memzero(inner_hash, sizeof(inner_hash));
        return ok_;
    }

private:
    mbedtls_sha1_context inner_;
    std::array<std::uint8_t, kBlock> ipad_;
    std::array<std::uint8_t, kBlock> opad_;
    bool ok_ = false;
};

bool ppbloom_seen(void *, std::span<const std::uint8_t> salt) noexcept
{
    return ppbloom_check(salt.data(), static_cast<int>(salt.size())) == 1;
}

void ppbloom_remember(void *, std::span<const std::uint8_t> salt) noexcept
{
    (void)ppbloom_add(salt.data(), static_cast<int>(salt.size()));
}

void store16_be(std::uint8_t *p, std::uint16_t v) noexcept
{
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v);
}

std::uint16_t load16_be(const std::uint8_t *p) noexcept
{
    return static_cast<std::uint16_t>((p[0] << 8) | p[1]);
}

} // namespace

std::optional<AeadSpec> find_aead(std::string_view name) noexcept
{
    for (const AeadSpec &spec : kSpecs) {
        if (spec.name == name) {
            return spec;
        }
    }
    return std::nullopt;
}

Result<MasterKey> MasterKey::from_password(const AeadSpec &spec, const char *password) noexcept
{
    if (password == nullptr) {
        return fail(Errc::config);
    }
    MasterKey master{ spec, {} };
    if (!derive_key(password, { master.bytes.data(), spec.key_len })) {
        return fail(Errc::config);
    }
    return master;
}

Result<MasterKey> MasterKey::from_base64(const AeadSpec &spec, const char *key) noexcept
{
    if (key == nullptr) {
        return fail(Errc::config);
    }
    MasterKey master{ spec, {} };
    if (!parse_key(key, { master.bytes.data(), spec.key_len }, false)) {
        return fail(Errc::config);
    }
    return master;
}

ReplayFilter ReplayFilter::ppbloom() noexcept
{
    return ReplayFilter{ &ppbloom_seen, &ppbloom_remember, nullptr };
}

Status hkdf_sha1(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm,
                 std::span<const std::uint8_t> info, std::span<std::uint8_t> okm) noexcept
{
    constexpr std::size_t kHash = HmacSha1::kSize;
    if (okm.size() > 255 * kHash) {
        return fail(Errc::invalid);
    }
    std::uint8_t zero_salt[kHash] = {};
    std::uint8_t prk[kHash];
    {
        HmacSha1 extract(salt.empty() ? std::span<const std::uint8_t>(zero_salt) : salt);
        extract.update(ikm);
        if (!extract.finish(prk)) {
            return fail(Errc::crypto);
        }
    }
    std::uint8_t t[kHash];
    std::size_t t_len = 0;
    std::size_t done  = 0;
    for (std::uint8_t counter = 1; done < okm.size(); ++counter) {
        HmacSha1 expand(prk);
        expand.update({ t, t_len });
        expand.update(info);
        expand.update({ &counter, 1 });
        if (!expand.finish(t)) {
            sodium_memzero(prk, sizeof(prk));
            return fail(Errc::crypto);
        }
        t_len         = kHash;
        std::size_t n = std::min(kHash, okm.size() - done);
        std::memcpy(okm.data() + done, t, n);
        done += n;
    }
    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(t, sizeof(t));
    return {};
}

Status derive_subkey(const MasterKey &master, std::span<const std::uint8_t> salt,
                     std::span<std::uint8_t> subkey) noexcept
{
    auto info = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(kSubkeyInfo.data()),
                                              kSubkeyInfo.size());
    return hkdf_sha1(salt, master.key(), info, subkey);
}

Status AeadEngine::init(const AeadSpec &spec, std::span<const std::uint8_t> subkey) noexcept
{
    if (subkey.size() != spec.key_len) {
        return fail(Errc::invalid);
    }
    reset();
    spec_ = spec;
    if (spec.kind == AeadKind::aes_256_gcm && crypto_aead_aes256gcm_is_available()) {
        auto &aes = impl_.emplace<SodiumAes256Gcm>();
        if (crypto_aead_aes256gcm_beforenm(&aes.state, subkey.data()) != 0) {
            return fail(Errc::crypto);
        }
    } else if (is_gcm(spec.kind)) {
        auto &gcm = impl_.emplace<MbedGcm>();
        if (mbedtls_gcm_setkey(&gcm.ctx, MBEDTLS_CIPHER_ID_AES, subkey.data(),
                               static_cast<unsigned>(subkey.size() * 8)) != 0) {
            return fail(Errc::crypto);
        }
    } else {
        auto &chacha = impl_.emplace<SodiumChacha>();
        std::memcpy(chacha.key.data(), subkey.data(), subkey.size());
    }
    return {};
}

void AeadEngine::reset() noexcept
{
    impl_.emplace<std::monostate>();
}

Status AeadEngine::seal(std::uint8_t *out, std::span<const std::uint8_t> plaintext, const std::uint8_t *nonce) noexcept
{
    int rc = -1;
    if (auto *aes = std::get_if<SodiumAes256Gcm>(&impl_)) {
        unsigned long long clen = 0;
        rc = crypto_aead_aes256gcm_encrypt_afternm(out, &clen, plaintext.data(), plaintext.size(), nullptr, 0,
                                                   nullptr, nonce, &aes->state);
    } else if (auto *gcm = std::get_if<MbedGcm>(&impl_)) {
        rc = mbedtls_gcm_crypt_and_tag(&gcm->ctx, MBEDTLS_GCM_ENCRYPT, plaintext.size(), nonce, spec_.nonce_len,
                                       nullptr, 0, plaintext.data(), out, spec_.tag_len, out + plaintext.size());
    } else if (auto *chacha = std::get_if<SodiumChacha>(&impl_)) {
        unsigned long long clen = 0;
        if (spec_.kind == AeadKind::xchacha20_poly1305) {
            rc = crypto_aead_xchacha20poly1305_ietf_encrypt(out, &clen, plaintext.data(), plaintext.size(), nullptr,
                                                            0, nullptr, nonce, chacha->key.data());
        } else {
            rc = crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, plaintext.data(), plaintext.size(), nullptr,
                                                           0, nullptr, nonce, chacha->key.data());
        }
    }
    if (rc != 0) {
        return fail(Errc::crypto);
    }
    return {};
}

Status AeadEngine::open(std::uint8_t *out, std::span<const std::uint8_t> ciphertext, const std::uint8_t *nonce) noexcept
{
    if (ciphertext.size() < spec_.tag_len) {
        return fail(Errc::crypto);
    }
    std::size_t mlen = ciphertext.size() - spec_.tag_len;
    int rc           = -1;
    if (auto *aes = std::get_if<SodiumAes256Gcm>(&impl_)) {
        unsigned long long plen = 0;
        rc = crypto_aead_aes256gcm_decrypt_afternm(out, &plen, nullptr, ciphertext.data(), ciphertext.size(), nullptr,
                                                   0, nonce, &aes->state);
    } else if (auto *gcm = std::get_if<MbedGcm>(&impl_)) {
        rc = mbedtls_gcm_auth_decrypt(&gcm->ctx, mlen, nonce, spec_.nonce_len, nullptr, 0,
                                      ciphertext.data() + mlen, spec_.tag_len, ciphertext.data(), out);
    } else if (auto *chacha = std::get_if<SodiumChacha>(&impl_)) {
        unsigned long long plen = 0;
        if (spec_.kind == AeadKind::xchacha20_poly1305) {
            rc = crypto_aead_xchacha20poly1305_ietf_decrypt(out, &plen, nullptr, ciphertext.data(), ciphertext.size(),
                                                            nullptr, 0, nonce, chacha->key.data());
        } else {
            rc = crypto_aead_chacha20poly1305_ietf_decrypt(out, &plen, nullptr, ciphertext.data(), ciphertext.size(),
                                                           nullptr, 0, nonce, chacha->key.data());
        }
    }
    if (rc != 0) {
        return fail(Errc::crypto);
    }
    return {};
}

Status AeadTcpEncryptor::init(const MasterKey &master, ReplayFilter filter, bool printable_salt) noexcept
{
    master_    = master;
    filter_    = filter;
    salt_sent_ = false;
    nonce_.fill(0);
    randombytes_buf(salt_.data(), master.spec.key_len);
    if (printable_salt) {
        // Vary the constrained span without adding a delimiter or marker.
        std::size_t prefix = 6 + randombytes_uniform(7);
        for (std::size_t i = 0; i < prefix; ++i) {
            salt_[i] = static_cast<std::uint8_t>(0x20 + randombytes_uniform(95));
        }
    }
    std::array<std::uint8_t, kMaxKey> subkey{};
    Status st = derive_subkey(master_, salt(), { subkey.data(), master.spec.key_len });
    if (st) {
        st = engine_.init(master.spec, { subkey.data(), master.spec.key_len });
    }
    sodium_memzero(subkey.data(), subkey.size());
    return st;
}

std::size_t AeadTcpEncryptor::sealed_size(std::size_t plaintext_len) const noexcept
{
    std::size_t chunks = (plaintext_len + kMaxChunk - 1) / kMaxChunk;
    std::size_t per    = kChunkLenSize + 2 * master_.spec.tag_len;
    return (salt_sent_ ? 0 : master_.spec.key_len) + plaintext_len + chunks * per;
}

Result<std::size_t> AeadTcpEncryptor::seal(std::span<const std::uint8_t> plaintext, std::span<std::uint8_t> out) noexcept
{
    if (plaintext.empty()) {
        return std::size_t{ 0 };
    }
    if (out.size() < sealed_size(plaintext.size())) {
        return fail(Errc::invalid);
    }
    std::size_t at = 0;
    if (!salt_sent_) {
        std::memcpy(out.data(), salt_.data(), master_.spec.key_len);
        at += master_.spec.key_len;
        filter_.add(salt());
        salt_sent_ = true;
    }
    const std::size_t tag = master_.spec.tag_len;
    while (!plaintext.empty()) {
        std::size_t n = std::min(plaintext.size(), kMaxChunk);
        std::uint8_t len[kChunkLenSize];
        store16_be(len, static_cast<std::uint16_t>(n));
        SS_TRY(engine_.seal(out.data() + at, { len, kChunkLenSize }, nonce_.data()));
        sodium_increment(nonce_.data(), master_.spec.nonce_len);
        at += kChunkLenSize + tag;
        SS_TRY(engine_.seal(out.data() + at, plaintext.first(n), nonce_.data()));
        sodium_increment(nonce_.data(), master_.spec.nonce_len);
        at += n + tag;
        plaintext = plaintext.subspan(n);
    }
    return at;
}

Status AeadTcpDecryptor::init(const MasterKey &master, ReplayFilter filter) noexcept
{
    master_          = master;
    filter_          = filter;
    engine_ready_    = false;
    salt_remembered_ = false;
    failed_          = false;
    pending_payload_ = 0;
    nonce_.fill(0);
    buffer_.clear();
    engine_.reset();
    return {};
}

Result<AeadTcpDecryptor::Step> AeadTcpDecryptor::decrypt(std::span<const std::uint8_t> in,
                                                          std::span<std::uint8_t> out) noexcept
{
    if (failed_) {
        return fail(Errc::closed);
    }
    Step step{ 0, 0 };
    if (buffer_.writable().size() < in.size()) {
        buffer_.compact();
    }
    std::size_t take = std::min(in.size(), buffer_.writable().size());
    if (take != 0) {
        std::memcpy(buffer_.writable().data(), in.data(), take);
        (void)buffer_.commit(take);
        step.consumed = take;
    }
    auto bytes = [this]() {
        auto r = buffer_.readable();
        return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(r.data()), r.size());
    };
    const std::size_t salt_len = master_.spec.key_len;
    const std::size_t tag      = master_.spec.tag_len;

    if (!engine_ready_) {
        if (buffer_.size() <= salt_len) {
            return step; // the salt alone is not enough to make progress
        }
        std::memcpy(salt_.data(), bytes().data(), salt_len);
        std::span<const std::uint8_t> salt(salt_.data(), salt_len);
        if (filter_.check(salt)) {
            failed_ = true;
            return fail(Errc::crypto);
        }
        std::array<std::uint8_t, kMaxKey> subkey{};
        Status st = derive_subkey(master_, salt, { subkey.data(), salt_len });
        if (st) {
            st = engine_.init(master_.spec, { subkey.data(), salt_len });
        }
        sodium_memzero(subkey.data(), subkey.size());
        if (!st) {
            failed_ = true;
            return fail(st.error());
        }
        (void)buffer_.consume(salt_len);
        engine_ready_ = true;
    }

    for (;;) {
        auto data = bytes();
        if (pending_payload_ == 0) {
            // Same threshold as the C decoder: wait for more than an empty
            // chunk's worth of bytes before decoding the length.
            if (data.size() <= kChunkLenSize + 2 * tag) {
                break;
            }
            std::uint8_t len[kChunkLenSize];
            if (!engine_.open(len, data.first(kChunkLenSize + tag), nonce_.data())) {
                failed_ = true;
                return fail(Errc::crypto);
            }
            std::size_t payload = load16_be(len) & kMaxChunk;
            if (payload == 0) {
                failed_ = true;
                return fail(Errc::protocol);
            }
            sodium_increment(nonce_.data(), master_.spec.nonce_len);
            pending_payload_ = payload;
            (void)buffer_.consume(kChunkLenSize + tag);
            data = bytes();
        }
        if (data.size() < pending_payload_ + tag || out.size() - step.produced < pending_payload_) {
            break;
        }
        if (!engine_.open(out.data() + step.produced, data.first(pending_payload_ + tag), nonce_.data())) {
            failed_ = true;
            return fail(Errc::crypto);
        }
        sodium_increment(nonce_.data(), master_.spec.nonce_len);
        step.produced += pending_payload_;
        (void)buffer_.consume(pending_payload_ + tag);
        pending_payload_ = 0;
    }

    if (step.produced != 0 && !salt_remembered_) {
        // Like the C decoder: remember the salt once the stream has proven
        // authentic, rechecking in case a concurrent stream used it.
        std::span<const std::uint8_t> salt(salt_.data(), salt_len);
        if (filter_.check(salt)) {
            failed_ = true;
            return fail(Errc::crypto);
        }
        filter_.add(salt);
        salt_remembered_ = true;
    }
    return step;
}

Result<std::size_t> aead_udp_seal(const MasterKey &master, std::span<const std::uint8_t> plaintext,
                                  std::span<std::uint8_t> out, ReplayFilter filter) noexcept
{
    const std::size_t salt_len = master.spec.key_len;
    const std::size_t total    = salt_len + plaintext.size() + master.spec.tag_len;
    if (out.size() < total) {
        return fail(Errc::invalid);
    }
    randombytes_buf(out.data(), salt_len);
    std::span<const std::uint8_t> salt(out.data(), salt_len);
    filter.add(salt);
    std::array<std::uint8_t, kMaxKey> subkey{};
    std::array<std::uint8_t, kMaxNonce> nonce{};
    AeadEngine engine;
    Status st = derive_subkey(master, salt, { subkey.data(), salt_len });
    if (st) {
        st = engine.init(master.spec, { subkey.data(), salt_len });
    }
    sodium_memzero(subkey.data(), subkey.size());
    SS_TRY(st);
    SS_TRY(engine.seal(out.data() + salt_len, plaintext, nonce.data()));
    return total;
}

Result<std::size_t> aead_udp_open(const MasterKey &master, std::span<const std::uint8_t> packet,
                                  std::span<std::uint8_t> out, ReplayFilter filter) noexcept
{
    const std::size_t salt_len = master.spec.key_len;
    const std::size_t tag      = master.spec.tag_len;
    if (packet.size() <= salt_len + tag) {
        return fail(Errc::protocol);
    }
    std::size_t plaintext_len = packet.size() - salt_len - tag;
    if (out.size() < plaintext_len) {
        return fail(Errc::invalid);
    }
    std::span<const std::uint8_t> salt = packet.first(salt_len);
    if (filter.check(salt)) {
        return fail(Errc::crypto);
    }
    std::array<std::uint8_t, kMaxKey> subkey{};
    std::array<std::uint8_t, kMaxNonce> nonce{};
    AeadEngine engine;
    Status st = derive_subkey(master, salt, { subkey.data(), salt_len });
    if (st) {
        st = engine.init(master.spec, { subkey.data(), salt_len });
    }
    sodium_memzero(subkey.data(), subkey.size());
    SS_TRY(st);
    SS_TRY(engine.open(out.data(), packet.subspan(salt_len), nonce.data()));
    filter.add(salt);
    return plaintext_len;
}

} // namespace ss::crypto
