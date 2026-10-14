/* SPDX-License-Identifier: GPL-3.0-or-later */
// The C++ AEAD codecs (src/crypto/aead.hpp) against RFC 5869 vectors and,
// differentially, against the C implementation in aead.cpp: every stream
// and packet produced by one side must be accepted by the other.
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <sodium.h>

#include "crypto/aead.hpp"
#include "alloc_audit/alloc_probe.hpp"
#include "test_helpers.hpp"

#include "crypto.h"
#include "netutils.h"
#include "ppbloom.h"
#include "utils.h"

#undef min
#undef max

extern "C" {
int verbose = 0;
struct cache *nonce_cache = nullptr;
}

namespace sc = ss::crypto;

namespace {

std::vector<std::uint8_t> unhex(const char *hex)
{
    std::vector<std::uint8_t> out;
    for (; hex[0] && hex[1]; hex += 2) {
        char pair[3] = { hex[0], hex[1], '\0' };
        char *end    = nullptr;
        unsigned long v = std::strtoul(pair, &end, 16);
        SS_CHECK(end == pair + 2);
        out.push_back(static_cast<std::uint8_t>(v));
    }
    return out;
}

std::vector<std::uint8_t> random_bytes(std::size_t n)
{
    std::vector<std::uint8_t> v(n);
    randombytes_buf(v.data(), n);
    return v;
}

// A replay filter backed by a small set, independent of ppbloom.
struct SaltSet {
    std::vector<std::vector<std::uint8_t> > salts;
    static bool seen(void *ctx, std::span<const std::uint8_t> salt) noexcept
    {
        for (auto &s : static_cast<SaltSet *>(ctx)->salts) {
            if (s.size() == salt.size() && std::memcmp(s.data(), salt.data(), salt.size()) == 0) {
                return true;
            }
        }
        return false;
    }
    static void remember(void *ctx, std::span<const std::uint8_t> salt) noexcept
    {
        static_cast<SaltSet *>(ctx)->salts.emplace_back(salt.begin(), salt.end());
    }
    sc::ReplayFilter filter() { return { &seen, &remember, this }; }
};

void test_hkdf_rfc5869()
{
    // RFC 5869 test case 4 (SHA-1).
    auto ikm  = unhex("0b0b0b0b0b0b0b0b0b0b0b");
    auto salt = unhex("000102030405060708090a0b0c");
    auto info = unhex("f0f1f2f3f4f5f6f7f8f9");
    std::uint8_t okm[42];
    SS_CHECK(sc::hkdf_sha1(salt, ikm, info, okm));
    auto expect = unhex("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896");
    SS_CHECK(std::memcmp(okm, expect.data(), 42) == 0);

    // Test case 7: no salt (treated as 20 zero bytes), empty info.
    auto ikm7 = unhex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    SS_CHECK(sc::hkdf_sha1({}, ikm7, {}, okm));
    auto expect7 = unhex("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48");
    SS_CHECK(std::memcmp(okm, expect7.data(), 42) == 0);
}

void test_hkdf_matches_c()
{
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    for (int i = 0; i < 64; ++i) {
        auto salt = random_bytes(16 + (i % 17));
        auto ikm  = random_bytes(16 + (i % 23));
        const char *info = "ss-subkey";
        std::uint8_t mine[32], theirs[32];
        SS_CHECK(sc::hkdf_sha1(salt, ikm, { reinterpret_cast<const std::uint8_t *>(info), 9 }, mine));
        SS_CHECK(crypto_hkdf(md, salt.data(), (int)salt.size(), ikm.data(), (int)ikm.size(),
                             reinterpret_cast<const unsigned char *>(info), 9, theirs, 32) == 0);
        SS_CHECK(std::memcmp(mine, theirs, 32) == 0);
    }
}

struct CMethod {
    crypto_t *crypto = nullptr;
    explicit CMethod(const char *method)
    {
        crypto = crypto_init("password", nullptr, method);
        SS_CHECK(crypto != nullptr);
    }
    ~CMethod()
    {
        ppbloom_free();
        ss_free(crypto->cipher);
        ss_free(crypto);
    }
};

// C encrypts a stream, C++ decrypts it from irregular fragments.
void tcp_c_to_cpp(const char *method, const sc::MasterKey &master)
{
    CMethod c(method);
    cipher_ctx_t enc;
    c.crypto->ctx_init(c.crypto->cipher, &enc, 1);

    auto plaintext = random_bytes(200000);
    std::vector<std::uint8_t> wire;
    buffer_t buf{};
    SS_CHECK(balloc(&buf, SOCKET_BUF_SIZE * 2) > 0);
    for (std::size_t off = 0; off < plaintext.size();) {
        std::size_t n = std::min<std::size_t>(1 + randombytes_uniform(16383), plaintext.size() - off);
        std::memcpy(buf.data, plaintext.data() + off, n);
        buf.len = n;
        SS_CHECK(c.crypto->encrypt(&buf, &enc, SOCKET_BUF_SIZE * 2) == CRYPTO_OK);
        wire.insert(wire.end(), buf.data, buf.data + buf.len);
        off += n;
    }
    bfree(&buf);
    c.crypto->ctx_release(&enc);

    SaltSet seen;
    sc::AeadTcpDecryptor dec;
    SS_CHECK(dec.init(master, seen.filter()));
    std::vector<std::uint8_t> got;
    std::vector<std::uint8_t> out(sc::kMaxChunk);
    for (std::size_t off = 0; off < wire.size();) {
        std::size_t n = std::min<std::size_t>(1 + randombytes_uniform(40000), wire.size() - off);
        std::span<const std::uint8_t> in(wire.data() + off, n);
        for (;;) {
            auto step = dec.decrypt(in, out);
            SS_CHECK(step);
            got.insert(got.end(), out.begin(), out.begin() + step->produced);
            in = in.subspan(step->consumed);
            if (step->consumed == 0 && step->produced == 0) {
                break;
            }
        }
        SS_CHECK(in.empty());
        off += n;
    }
    SS_CHECK(got == plaintext);
    SS_CHECK(dec.pending() == 0);
    SS_CHECK(seen.salts.size() == 1);
}

// C++ encrypts, C decrypts.
void tcp_cpp_to_c(const char *method, const sc::MasterKey &master)
{
    CMethod c(method);
    cipher_ctx_t dec;
    c.crypto->ctx_init(c.crypto->cipher, &dec, 0);

    SaltSet seen;
    sc::AeadTcpEncryptor enc;
    SS_CHECK(enc.init(master, seen.filter()));
    auto plaintext = random_bytes(100000);
    std::vector<std::uint8_t> got;
    buffer_t buf{};
    const std::size_t cap = 4 * SOCKET_BUF_SIZE;
    SS_CHECK(balloc(&buf, cap) > 0);
    for (std::size_t off = 0; off < plaintext.size();) {
        // Larger than one chunk on purpose: the C++ side splits.
        std::size_t n = std::min<std::size_t>(1 + randombytes_uniform(30000), plaintext.size() - off);
        std::vector<std::uint8_t> wire(enc.sealed_size(n));
        auto written = enc.seal({ plaintext.data() + off, n }, wire);
        SS_CHECK(written && *written == wire.size());
        std::memcpy(buf.data, wire.data(), wire.size());
        buf.len = wire.size();
        SS_CHECK(c.crypto->decrypt(&buf, &dec, cap) == CRYPTO_OK);
        got.insert(got.end(), buf.data, buf.data + buf.len);
        off += n;
    }
    bfree(&buf);
    c.crypto->ctx_release(&dec);
    SS_CHECK(got == plaintext);
    SS_CHECK(seen.salts.size() == 1);
}

void udp_both_ways(const char *method, const sc::MasterKey &master)
{
    CMethod c(method);
    const std::size_t cap = 65536;
    for (std::size_t size : { 1u, 100u, 1400u, 9000u }) {
        auto payload = random_bytes(size);
        // C -> C++
        buffer_t buf{};
        SS_CHECK(balloc(&buf, cap) > 0);
        std::memcpy(buf.data, payload.data(), size);
        buf.len = size;
        SS_CHECK(c.crypto->encrypt_all(&buf, c.crypto->cipher, cap) == CRYPTO_OK);
        std::vector<std::uint8_t> out(size);
        SaltSet seen;
        auto n = sc::aead_udp_open(master, { reinterpret_cast<std::uint8_t *>(buf.data), buf.len }, out,
                                   seen.filter());
        SS_CHECK(n && *n == size && std::memcmp(out.data(), payload.data(), size) == 0);
        // A second delivery of the same packet is a replay.
        auto again = sc::aead_udp_open(master, { reinterpret_cast<std::uint8_t *>(buf.data), buf.len }, out,
                                       seen.filter());
        SS_CHECK(!again && again.error().code == ss::Errc::crypto);

        // C++ -> C
        std::vector<std::uint8_t> packet(master.spec.key_len + size + master.spec.tag_len);
        auto w = sc::aead_udp_seal(master, payload, packet, {});
        SS_CHECK(w && *w == packet.size());
        std::memcpy(buf.data, packet.data(), packet.size());
        buf.len = packet.size();
        SS_CHECK(c.crypto->decrypt_all(&buf, c.crypto->cipher, cap) == CRYPTO_OK);
        SS_CHECK(buf.len == size && std::memcmp(buf.data, payload.data(), size) == 0);
        bfree(&buf);
    }
}

void tampering_and_framing(const sc::MasterKey &master)
{
    sc::AeadTcpEncryptor enc;
    SS_CHECK(enc.init(master, {}));
    auto plaintext = random_bytes(1000);
    std::vector<std::uint8_t> wire(enc.sealed_size(plaintext.size()));
    SS_CHECK(enc.seal(plaintext, wire));
    std::vector<std::uint8_t> out(sc::kMaxChunk);

    // Any flipped byte after the salt is rejected, and the stream stays dead.
    for (std::size_t pos : { (std::size_t)master.spec.key_len, wire.size() - 1 }) {
        auto bad = wire;
        bad[pos] ^= 0x01;
        sc::AeadTcpDecryptor dec;
        SS_CHECK(dec.init(master, {}));
        auto r = dec.decrypt(bad, out);
        SS_CHECK(!r && r.error().code == ss::Errc::crypto);
        auto again = dec.decrypt({}, out);
        SS_CHECK(!again && again.error().code == ss::Errc::closed);
    }

    // A salt alone, or a partial header, yields nothing yet.
    sc::AeadTcpDecryptor dec;
    SS_CHECK(dec.init(master, {}));
    auto step = dec.decrypt(std::span<const std::uint8_t>(wire.data(), master.spec.key_len), out);
    SS_CHECK(step && step->produced == 0 && !dec.salt_received());
    step = dec.decrypt(std::span<const std::uint8_t>(wire.data() + master.spec.key_len, 10), out);
    SS_CHECK(step && step->produced == 0 && dec.salt_received());

    // An output buffer too small for the next chunk stalls instead of
    // truncating.
    sc::AeadTcpDecryptor small;
    SS_CHECK(small.init(master, {}));
    std::uint8_t tiny[10];
    step = small.decrypt(wire, tiny);
    SS_CHECK(step && step->consumed == wire.size() && step->produced == 0);
    step = small.decrypt({}, out);
    SS_CHECK(step && step->produced == plaintext.size());
    SS_CHECK(std::memcmp(out.data(), plaintext.data(), plaintext.size()) == 0);

    // A replayed salt is refused before any key work.
    SaltSet seen;
    sc::AeadTcpDecryptor first, second;
    SS_CHECK(first.init(master, seen.filter()) && second.init(master, seen.filter()));
    SS_CHECK(first.decrypt(wire, out));
    auto replay = second.decrypt(wire, out);
    SS_CHECK(!replay && replay.error().code == ss::Errc::crypto);
}

void test_method(const char *name)
{
    auto spec = sc::find_aead(name);
    SS_CHECK(spec);
    auto master = sc::MasterKey::from_password(*spec, "password");
    SS_CHECK(master);
    tcp_c_to_cpp(name, *master);
    tcp_cpp_to_c(name, *master);
    udp_both_ways(name, *master);
    tampering_and_framing(*master);
    std::printf("ok %s\n", name);
}

void test_lookup()
{
    SS_CHECK(!sc::find_aead("2022-blake3-aes-128-gcm"));
    SS_CHECK(!sc::find_aead("aes-256-cfb"));
    auto chacha = sc::find_aead("chacha20-ietf-poly1305");
    SS_CHECK(chacha && chacha->key_len == 32 && chacha->nonce_len == 12);
}

// New connections and packets through the C++ codecs, with every buffer
// preallocated: under check_steady.py this phase must not touch the heap.
void steady_state(const sc::MasterKey &master)
{
    static std::uint8_t plain[sc::kMaxChunk];
    static std::uint8_t wire[2 * sc::kMaxChunkWire];
    static std::uint8_t out[sc::kMaxChunk];
    randombytes_buf(plain, sizeof(plain));
    for (int conn = 0; conn < 200; ++conn) {
        sc::AeadTcpEncryptor enc;
        sc::AeadTcpDecryptor dec;
        SS_CHECK(enc.init(master, {}) && dec.init(master, {}));
        for (std::size_t n : { (std::size_t)1, (std::size_t)1400, sc::kMaxChunk }) {
            auto w = enc.seal({ plain, n }, wire);
            SS_CHECK(w);
            auto step = dec.decrypt({ wire, *w }, out);
            SS_CHECK(step && step->consumed == *w && step->produced == n);
        }
        auto p = sc::aead_udp_seal(master, { plain, 1200 }, wire, {});
        SS_CHECK(p);
        auto q = sc::aead_udp_open(master, { wire, *p }, out, {});
        SS_CHECK(q && *q == 1200);
    }
}

void test_no_heap_in_steady_state()
{
    // Deriving the master key from a password is startup work (and uses
    // Mbed TLS's allocating MD API); keep it outside the measured phase.
    sc::MasterKey keys[3];
    int i = 0;
    for (const char *name : { "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305" }) {
        auto spec = sc::find_aead(name);
        SS_CHECK(spec.has_value());
        auto master = sc::MasterKey::from_password(spec.value(), "password");
        SS_CHECK(master);
        keys[i++] = *master;
        steady_state(*master); // warm-up: lazy library initialisation
    }
    ss::test::alloc_mark();
    for (const sc::MasterKey &master : keys) {
        steady_state(master);
    }
    ss::test::alloc_mark();
}

} // namespace

int main()
{
    SS_CHECK(sodium_init() != -1);
    SS_RUN(test_hkdf_rfc5869);
    SS_RUN(test_hkdf_matches_c);
    SS_RUN(test_lookup);
    for (const char *m : { "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
                           "xchacha20-ietf-poly1305" }) {
        test_method(m);
    }
    SS_RUN(test_no_heap_in_steady_state);
    return 0;
}
