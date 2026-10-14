/* SPDX-License-Identifier: GPL-3.0-or-later */
// The C++ stream codecs (src/crypto/stream.hpp) differentially against the C
// implementation in stream.cpp, plus replay handling and a zero-allocation
// steady phase.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include <sodium.h>

#include "alloc_audit/alloc_probe.hpp"
#include "crypto.h"
#include "crypto/stream.hpp"
#include "ppbloom.h"
#include "test_helpers.hpp"
#include "utils.h"

#undef min
#undef max

extern "C" {
int verbose = 0;
struct cache *nonce_cache = nullptr;
}

namespace sc = ss::crypto;

namespace {

std::vector<std::uint8_t> random_bytes(std::size_t n)
{
    std::vector<std::uint8_t> v(n);
    randombytes_buf(v.data(), n);
    return v;
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

// Odd sizes so that writes start and end inside 64-byte keystream blocks.
std::size_t piece(std::size_t left)
{
    return std::min<std::size_t>(1 + randombytes_uniform(3000), left);
}

void tcp_c_to_cpp(const char *method, const sc::StreamKey &key)
{
    CMethod c(method);
    cipher_ctx_t enc;
    c.crypto->ctx_init(c.crypto->cipher, &enc, 1);
    auto plaintext = random_bytes(60000);
    std::vector<std::uint8_t> wire;
    buffer_t buf{};
    const std::size_t cap = 8192;
    SS_CHECK(balloc(&buf, cap) > 0);
    for (std::size_t off = 0; off < plaintext.size();) {
        std::size_t n = piece(plaintext.size() - off);
        std::memcpy(buf.data, plaintext.data() + off, n);
        buf.len = n;
        SS_CHECK(c.crypto->encrypt(&buf, &enc, cap) == CRYPTO_OK);
        wire.insert(wire.end(), buf.data, buf.data + buf.len);
        off += n;
    }
    bfree(&buf);
    c.crypto->ctx_release(&enc);

    sc::StreamTcpDecryptor dec;
    SS_CHECK(dec.init(key, {}));
    std::vector<std::uint8_t> got;
    std::vector<std::uint8_t> out(1000); // smaller than some inputs on purpose
    for (std::size_t off = 0; off < wire.size();) {
        std::size_t n = std::min<std::size_t>(1 + randombytes_uniform(5000), wire.size() - off);
        std::span<const std::uint8_t> in(wire.data() + off, n);
        while (!in.empty()) {
            auto step = dec.decrypt(in, out);
            SS_CHECK(step);
            got.insert(got.end(), out.begin(), out.begin() + step->produced);
            in = in.subspan(step->consumed);
        }
        off += n;
    }
    SS_CHECK(got == plaintext);
}

void tcp_cpp_to_c(const char *method, const sc::StreamKey &key)
{
    CMethod c(method);
    cipher_ctx_t dec;
    c.crypto->ctx_init(c.crypto->cipher, &dec, 0);
    sc::StreamTcpEncryptor enc;
    SS_CHECK(enc.init(key, {}));
    auto plaintext = random_bytes(60000);
    std::vector<std::uint8_t> got;
    buffer_t buf{};
    const std::size_t cap = 8192;
    SS_CHECK(balloc(&buf, cap) > 0);
    for (std::size_t off = 0; off < plaintext.size();) {
        std::size_t n = piece(plaintext.size() - off);
        std::vector<std::uint8_t> wire(enc.sealed_size(n));
        auto w = enc.seal({ plaintext.data() + off, n }, wire);
        SS_CHECK(w && *w == wire.size());
        std::memcpy(buf.data, wire.data(), wire.size());
        buf.len = wire.size();
        int rc  = c.crypto->decrypt(&buf, &dec, cap);
        SS_CHECK(rc == CRYPTO_OK || (rc == CRYPTO_NEED_MORE && buf.len == 0));
        got.insert(got.end(), buf.data, buf.data + buf.len);
        off += n;
    }
    bfree(&buf);
    c.crypto->ctx_release(&dec);
    SS_CHECK(got == plaintext);
}

void udp_both_ways(const char *method, const sc::StreamKey &key)
{
    CMethod c(method);
    const std::size_t cap = 65536;
    for (std::size_t size : { 1u, 63u, 64u, 65u, 1400u }) {
        auto payload = random_bytes(size);
        buffer_t buf{};
        SS_CHECK(balloc(&buf, cap) > 0);
        std::memcpy(buf.data, payload.data(), size);
        buf.len = size;
        SS_CHECK(c.crypto->encrypt_all(&buf, c.crypto->cipher, cap) == CRYPTO_OK);
        std::vector<std::uint8_t> out(size);
        auto n = sc::stream_udp_open(key, { reinterpret_cast<std::uint8_t *>(buf.data), buf.len }, out, {});
        SS_CHECK(n && *n == size && std::memcmp(out.data(), payload.data(), size) == 0);

        std::vector<std::uint8_t> packet(key.spec.iv_len + size);
        auto w = sc::stream_udp_seal(key, payload, packet, {});
        SS_CHECK(w && *w == packet.size());
        std::memcpy(buf.data, packet.data(), packet.size());
        buf.len = packet.size();
        SS_CHECK(c.crypto->decrypt_all(&buf, c.crypto->cipher, cap) == CRYPTO_OK);
        SS_CHECK(buf.len == size && std::memcmp(buf.data, payload.data(), size) == 0);
        bfree(&buf);
    }
}

struct IvSet {
    std::vector<std::vector<std::uint8_t> > ivs;
    static bool seen(void *ctx, std::span<const std::uint8_t> iv) noexcept
    {
        for (auto &s : static_cast<IvSet *>(ctx)->ivs) {
            if (s.size() == iv.size() && std::memcmp(s.data(), iv.data(), iv.size()) == 0) {
                return true;
            }
        }
        return false;
    }
    static void remember(void *ctx, std::span<const std::uint8_t> iv) noexcept
    {
        static_cast<IvSet *>(ctx)->ivs.emplace_back(iv.begin(), iv.end());
    }
    sc::ReplayFilter filter() { return { &seen, &remember, this }; }
};

void replay(const sc::StreamKey &key)
{
    sc::StreamTcpEncryptor enc;
    SS_CHECK(enc.init(key, {}));
    std::uint8_t msg[10] = {};
    std::vector<std::uint8_t> wire(enc.sealed_size(sizeof(msg)));
    SS_CHECK(enc.seal(msg, wire));
    IvSet seen;
    std::uint8_t out[16];
    sc::StreamTcpDecryptor first, second;
    SS_CHECK(first.init(key, seen.filter()) && second.init(key, seen.filter()));
    // An empty read before the IV arrives is a no-op.
    auto none = first.decrypt(std::span<const std::uint8_t>(), out);
    SS_CHECK(none && none->consumed == 0 && none->produced == 0 && !first.iv_received());
    // The IV alone is enough to register it.
    auto step = first.decrypt(std::span<const std::uint8_t>(wire.data(), key.spec.iv_len), out);
    SS_CHECK(step && step->produced == 0 && first.iv_received());
    auto again = second.decrypt(wire, out);
    SS_CHECK(!again && again.error().code == ss::Errc::crypto);
}

void steady(const sc::StreamKey &key)
{
    static std::uint8_t plain[4096], wire[4096 + 16], out[4096];
    for (int conn = 0; conn < 100; ++conn) {
        sc::StreamTcpEncryptor enc;
        sc::StreamTcpDecryptor dec;
        SS_CHECK(enc.init(key, {}) && dec.init(key, {}));
        for (std::size_t n : { (std::size_t)1, (std::size_t)100, (std::size_t)4000 }) {
            auto w = enc.seal({ plain, n }, wire);
            SS_CHECK(w);
            auto step = dec.decrypt({ wire, *w }, out);
            SS_CHECK(step && step->produced == n);
        }
        auto p = sc::stream_udp_seal(key, { plain, 1200 }, wire, {});
        SS_CHECK(p && sc::stream_udp_open(key, { wire, *p }, out, {}));
    }
}

const char *const kMethods[] = { "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr",
                                 "aes-256-ctr", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
                                 "salsa20", "chacha20", "chacha20-ietf" };

sc::StreamKey key_for(const char *name)
{
    auto spec = sc::find_stream(name);
    SS_CHECK(spec.has_value());
    auto key = sc::StreamKey::from_password(spec.value(), "password");
    SS_CHECK(key);
    return *key;
}

void test_methods()
{
    for (const char *m : kMethods) {
        sc::StreamKey key = key_for(m);
        tcp_c_to_cpp(m, key);
        tcp_cpp_to_c(m, key);
        udp_both_ways(m, key);
        replay(key);
        std::printf("ok %s\n", m);
    }
    SS_CHECK(!sc::find_stream("rc4-md5") && !sc::find_stream("aes-256-gcm"));
}

void test_no_heap_in_steady_state()
{
    sc::StreamKey keys[sizeof(kMethods) / sizeof(kMethods[0])];
    std::size_t i = 0;
    for (const char *m : kMethods) {
        keys[i] = key_for(m);
        steady(keys[i++]);
    }
    ss::test::alloc_mark();
    for (const sc::StreamKey &key : keys) {
        steady(key);
    }
    ss::test::alloc_mark();
}

} // namespace

int main()
{
    SS_CHECK(sodium_init() != -1);
    SS_RUN(test_methods);
    SS_RUN(test_no_heap_in_steady_state);
    return 0;
}
