/* SPDX-License-Identifier: GPL-3.0-or-later */
// The C++ SIP022 codecs (src/crypto/aead2022.hpp) differentially against the
// C implementation in aead2022.cpp / aead2022_udp.cpp, in both roles, plus
// replay protection and a zero-allocation steady phase.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <vector>

#include <sodium.h>

#include "alloc_audit/alloc_probe.hpp"
#include "crypto/aead2022.hpp"
#include "test_helpers.hpp"

#include "aead.h"
#include "crypto.h"
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

const char kPsk16[] = "AAECAwQFBgcICQoLDA0ODw==";
const char kPsk32[] = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

const char *const kMethods[] = { "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
                                 "2022-blake3-chacha20-poly1305" };

const char *psk_for(const char *method)
{
    return std::strcmp(method, "2022-blake3-aes-128-gcm") == 0 ? kPsk16 : kPsk32;
}

sc::Psk psk_of(const char *method)
{
    auto spec = sc::find_aead2022(method);
    SS_CHECK(spec.has_value());
    auto psk = sc::Psk::from_base64(*spec, psk_for(method));
    SS_CHECK(psk);
    return *psk;
}

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
        crypto = crypto_init(psk_for(method), nullptr, method);
        SS_CHECK(crypto != nullptr);
    }
    ~CMethod()
    {
        ppbloom_free();
        ss_free(crypto->cipher);
        ss_free(crypto);
    }
};

// A C cipher context of a fixed role.
struct CCtx {
    crypto_t *crypto;
    cipher_ctx_t ctx{};
    CCtx(crypto_t *c, int enc, int role) : crypto(c)
    {
        aead_set_role(role);
        c->ctx_init(c->cipher, &ctx, enc);
        ctx.role = role;
    }
    ~CCtx() { crypto->ctx_release(&ctx); }
};

const std::uint8_t kAddr[] = { 0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xBB };

// Run C ciphertext through a C++ decryptor in random slices.
std::vector<std::uint8_t> cpp_decrypt_all(sc::Aead2022TcpDecryptor &dec, const std::vector<std::uint8_t> &wire)
{
    std::vector<std::uint8_t> got;
    std::vector<std::uint8_t> out(70000);
    for (std::size_t off = 0; off < wire.size();) {
        std::size_t n = std::min<std::size_t>(1 + randombytes_uniform(9000), wire.size() - off);
        std::span<const std::uint8_t> in(wire.data() + off, n);
        for (;;) {
            // Output windows of any size, down to one byte.
            std::size_t room = randombytes_uniform(4) == 0 ? 1 + randombytes_uniform(16) : 1 + randombytes_uniform(70000);
            auto step = dec.decrypt(in, std::span<std::uint8_t>(out).first(room));
            SS_CHECK(step);
            got.insert(got.end(), out.begin(), out.begin() + step->produced);
            in = in.subspan(step->consumed);
            if (step->consumed == 0 && step->produced == 0) {
                break;
            }
        }
        off += n;
    }
    return got;
}

std::vector<std::uint8_t> c_encrypt(CCtx &enc, std::span<const std::uint8_t> plain)
{
    const std::size_t cap = 4 * 65536;
    buffer_t buf{};
    SS_CHECK(balloc(&buf, cap) > 0);
    std::memcpy(buf.data, plain.data(), plain.size());
    buf.len = plain.size();
    SS_CHECK(enc.crypto->encrypt(&buf, &enc.ctx, cap) == CRYPTO_OK);
    std::vector<std::uint8_t> wire(buf.data, buf.data + buf.len);
    bfree(&buf);
    return wire;
}

std::vector<std::uint8_t> c_decrypt(CCtx &dec, std::span<const std::uint8_t> wire)
{
    const std::size_t cap = 4 * 65536;
    std::vector<std::uint8_t> got;
    buffer_t buf{};
    SS_CHECK(balloc(&buf, cap) > 0);
    for (std::size_t off = 0; off < wire.size();) {
        std::size_t n = std::min<std::size_t>(1 + randombytes_uniform(9000), wire.size() - off);
        std::memcpy(buf.data, wire.data() + off, n);
        buf.len = n;
        int rc  = dec.crypto->decrypt(&buf, &dec.ctx, cap);
        SS_CHECK(rc == CRYPTO_OK || rc == CRYPTO_NEED_MORE);
        if (rc == CRYPTO_OK) {
            got.insert(got.end(), buf.data, buf.data + buf.len);
        }
        off += n;
    }
    bfree(&buf);
    return got;
}

std::vector<std::uint8_t> cpp_seal(sc::Aead2022TcpEncryptor &enc, std::span<const std::uint8_t> plain)
{
    std::vector<std::uint8_t> wire(enc.sealed_size(plain.size()));
    auto n = enc.seal(plain, wire);
    SS_CHECK(n);
    wire.resize(*n);
    return wire;
}

// C client -> C++ server, then C++ server -> C client.
void tcp_c_client(const char *method)
{
    CMethod c(method);
    sc::Psk psk = psk_of(method);
    CCtx enc(c.crypto, 1, CRYPTO_ROLE_CLIENT);
    CCtx dec(c.crypto, 0, CRYPTO_ROLE_CLIENT);
    cipher_ctx_pair(&enc.ctx, &dec.ctx);

    auto body = random_bytes(200000); // spans several 64 KiB chunks
    std::vector<std::uint8_t> first(kAddr, kAddr + sizeof(kAddr));
    first.insert(first.end(), body.begin(), body.begin() + 100);
    auto wire = c_encrypt(enc, first);
    auto more = c_encrypt(enc, { body.data() + 100, body.size() - 100 });
    wire.insert(wire.end(), more.begin(), more.end());

    sc::SaltPool pool;
    SS_CHECK(pool.reserve(64, 1));
    sc::Aead2022TcpDecryptor sdec;
    SS_CHECK(sdec.init(psk, sc::Role::server, {}, &pool));
    auto got = cpp_decrypt_all(sdec, wire);
    std::vector<std::uint8_t> want(kAddr, kAddr + sizeof(kAddr));
    want.insert(want.end(), body.begin(), body.end());
    SS_CHECK(got == want);

    sc::Aead2022TcpEncryptor senc;
    SS_CHECK(senc.init(psk, sc::Role::server, &sdec));
    auto reply = random_bytes(150000);
    auto rwire = cpp_seal(senc, reply);
    auto rest  = cpp_seal(senc, { reply.data(), 10 });
    rwire.insert(rwire.end(), rest.begin(), rest.end());
    auto rgot = c_decrypt(dec, rwire);
    reply.insert(reply.end(), reply.begin(), reply.begin() + 10);
    SS_CHECK(rgot == reply);

    // Replaying the request is refused by the salt pool.
    sc::Aead2022TcpDecryptor again;
    SS_CHECK(again.init(psk, sc::Role::server, {}, &pool));
    std::vector<std::uint8_t> out(sc::k2022MaxChunk);
    auto step = again.decrypt(wire, out);
    SS_CHECK(!step && step.error().code == ss::Errc::crypto);
}

// C++ client -> C server, then C server -> C++ client.
void tcp_cpp_client(const char *method)
{
    CMethod c(method);
    sc::Psk psk = psk_of(method);
    CCtx dec(c.crypto, 0, CRYPTO_ROLE_SERVER);
    CCtx enc(c.crypto, 1, CRYPTO_ROLE_SERVER);
    cipher_ctx_pair(&enc.ctx, &dec.ctx);

    sc::Aead2022TcpEncryptor cenc;
    SS_CHECK(cenc.init(psk, sc::Role::client));
    // The address alone: the request header gets padding.
    auto wire = cpp_seal(cenc, kAddr);
    auto body = random_bytes(70000);
    auto more = cpp_seal(cenc, body);
    wire.insert(wire.end(), more.begin(), more.end());
    auto got = c_decrypt(dec, wire);
    std::vector<std::uint8_t> want(kAddr, kAddr + sizeof(kAddr));
    want.insert(want.end(), body.begin(), body.end());
    SS_CHECK(got == want);

    sc::Aead2022TcpDecryptor cdec;
    SS_CHECK(cdec.init(psk, sc::Role::client, cenc.salt()));
    auto reply = random_bytes(5000);
    auto rwire = c_encrypt(enc, reply);
    SS_CHECK(cpp_decrypt_all(cdec, rwire) == reply);

    // A response that echoes another salt is rejected.
    sc::Aead2022TcpEncryptor other;
    SS_CHECK(other.init(psk, sc::Role::client));
    sc::Aead2022TcpDecryptor wrong;
    SS_CHECK(wrong.init(psk, sc::Role::client, other.salt()));
    std::vector<std::uint8_t> out(sc::k2022MaxChunk);
    SS_CHECK(!wrong.decrypt(rwire, out));
}

void tcp_rejects()
{
    sc::Psk psk = psk_of("2022-blake3-aes-256-gcm");
    sc::Aead2022TcpEncryptor enc;
    SS_CHECK(enc.init(psk, sc::Role::client));
    std::uint8_t junk[3] = { 9, 9, 9 };
    std::vector<std::uint8_t> out(enc.sealed_size(sizeof(junk)));
    SS_CHECK(!enc.seal(junk, out)); // not a SOCKS address
    sc::Aead2022TcpDecryptor dec;
    SS_CHECK(!enc.init(psk, sc::Role::server, nullptr));
    SS_CHECK(dec.init(psk, sc::Role::server));
    sc::Aead2022TcpEncryptor server;
    SS_CHECK(server.init(psk, sc::Role::server, &dec));
    std::uint8_t data[4] = {};
    std::vector<std::uint8_t> sout(server.sealed_size(4));
    SS_CHECK(!server.seal(data, sout)); // no request yet
    // A tampered byte fails authentication.
    sc::Aead2022TcpEncryptor client;
    SS_CHECK(client.init(psk, sc::Role::client));
    auto wire = cpp_seal(client, kAddr);
    wire[psk.size() + 3] ^= 1;
    std::vector<std::uint8_t> plain(sc::k2022MaxChunk);
    auto step = dec.decrypt(wire, plain);
    SS_CHECK(!step && step.error().code == ss::Errc::crypto);
}

void udp(const char *method)
{
    CMethod c(method);
    sc::Psk psk = psk_of(method);
    const std::size_t cap = 65536;
    std::vector<std::uint8_t> plain(kAddr, kAddr + sizeof(kAddr));
    auto payload = random_bytes(1200);
    plain.insert(plain.end(), payload.begin(), payload.end());

    // C client -> C++ server -> C client.
    aead_set_role(CRYPTO_ROLE_CLIENT);
    void *slot = nullptr;
    buffer_t buf{};
    SS_CHECK(balloc(&buf, cap) > 0);
    std::memcpy(buf.data, plain.data(), plain.size());
    buf.len = plain.size();
    SS_CHECK(c.crypto->encrypt_udp(&buf, c.crypto->cipher, cap, &slot) == CRYPTO_OK);

    sc::UdpSession2022 server;
    std::vector<std::uint8_t> out(buf.len);
    auto pkt = sc::udp2022_decrypt(psk, { reinterpret_cast<std::uint8_t *>(buf.data), buf.len }, out);
    SS_CHECK(pkt);
    auto n = sc::udp2022_accept(sc::Role::server, server, *pkt, out, std::time(nullptr));
    SS_CHECK(n && *n == plain.size() && std::memcmp(out.data(), plain.data(), plain.size()) == 0);
    // The same packet again is a replay.
    auto pkt2 = sc::udp2022_decrypt(psk, { reinterpret_cast<std::uint8_t *>(buf.data), buf.len }, out);
    SS_CHECK(pkt2 && !sc::udp2022_accept(sc::Role::server, server, *pkt2, out, std::time(nullptr)));

    std::vector<std::uint8_t> reply(plain.size() + sc::udp2022_overhead(psk, sc::Role::server));
    auto w = sc::udp2022_seal(psk, sc::Role::server, server, plain, reply);
    SS_CHECK(w && *w == reply.size());
    std::memcpy(buf.data, reply.data(), reply.size());
    buf.len = reply.size();
    SS_CHECK(c.crypto->decrypt_udp(&buf, c.crypto->cipher, cap, &slot) == CRYPTO_OK);
    SS_CHECK(buf.len == plain.size() - 0 || buf.len == plain.size());
    SS_CHECK(std::memcmp(buf.data, plain.data(), plain.size()) == 0);
    c.crypto->udp_session_release(slot);
    slot = nullptr;

    // C++ client -> C server -> C++ client.
    sc::UdpSession2022 client;
    std::vector<std::uint8_t> req(plain.size() + sc::udp2022_overhead(psk, sc::Role::client));
    w = sc::udp2022_seal(psk, sc::Role::client, client, plain, req);
    SS_CHECK(w);
    aead_set_role(CRYPTO_ROLE_SERVER);
    std::memcpy(buf.data, req.data(), *w);
    buf.len = *w;
    SS_CHECK(c.crypto->decrypt_udp(&buf, c.crypto->cipher, cap, &slot) == CRYPTO_OK);
    SS_CHECK(buf.len == plain.size() && std::memcmp(buf.data, plain.data(), plain.size()) == 0);
    std::memcpy(buf.data, plain.data(), plain.size());
    buf.len = plain.size();
    SS_CHECK(c.crypto->encrypt_udp(&buf, c.crypto->cipher, cap, &slot) == CRYPTO_OK);
    std::vector<std::uint8_t> back(buf.len);
    pkt = sc::udp2022_decrypt(psk, { reinterpret_cast<std::uint8_t *>(buf.data), buf.len }, back);
    SS_CHECK(pkt);
    n = sc::udp2022_accept(sc::Role::client, client, *pkt, back, std::time(nullptr));
    SS_CHECK(n && *n == plain.size() && std::memcmp(back.data(), plain.data(), plain.size()) == 0);
    c.crypto->udp_session_release(slot);
    bfree(&buf);
}

void udp_window()
{
    sc::Psk psk = psk_of("2022-blake3-aes-128-gcm");
    sc::UdpSession2022 client, server;
    std::uint8_t plain[sizeof(kAddr)];
    std::memcpy(plain, kAddr, sizeof(kAddr));
    std::vector<std::vector<std::uint8_t> > packets;
    for (int i = 0; i < 300; ++i) {
        std::vector<std::uint8_t> p(sizeof(plain) + sc::udp2022_overhead(psk, sc::Role::client));
        SS_CHECK(sc::udp2022_seal(psk, sc::Role::client, client, plain, p));
        packets.push_back(p);
    }
    auto deliver = [&](std::size_t i) {
        std::vector<std::uint8_t> out(packets[i].size());
        auto pkt = sc::udp2022_decrypt(psk, packets[i], out);
        SS_CHECK(pkt && pkt->packet_id == i);
        return static_cast<bool>(sc::udp2022_accept(sc::Role::server, server, *pkt, out, std::time(nullptr)));
    };
    SS_CHECK(deliver(5) && deliver(0) && deliver(3) && !deliver(3));
    SS_CHECK(deliver(299));
    SS_CHECK(!deliver(10)); // fell out of the 256-packet window
    SS_CHECK(deliver(100) && !deliver(100));
    // Stale timestamps are refused.
    std::vector<std::uint8_t> p(sizeof(plain) + sc::udp2022_overhead(psk, sc::Role::client));
    SS_CHECK(sc::udp2022_seal(psk, sc::Role::client, client, plain, p));
    std::vector<std::uint8_t> out(p.size());
    auto pkt = sc::udp2022_decrypt(psk, p, out);
    SS_CHECK(pkt && !sc::udp2022_accept(sc::Role::server, server, *pkt, out, std::time(nullptr) + 31));
}

void salt_pool()
{
    sc::SaltPool pool;
    SS_CHECK(pool.reserve(2, 7));
    std::uint8_t a[32] = { 1 }, b[32] = { 2 }, d[32] = { 3 };
    SS_CHECK(pool.check_and_add(a, 100) && !pool.check_and_add(a, 159));
    SS_CHECK(pool.check_and_add(a, 160)); // retention over
    SS_CHECK(pool.check_and_add(b, 161) && pool.check_and_add(d, 161) && pool.size() == 2);
}

void steady(const sc::Psk &psk, sc::SaltPool &pool)
{
    static std::uint8_t plain[16384], wire[16384 + 2048], out[sc::k2022MaxChunk];
    std::memcpy(plain, kAddr, sizeof(kAddr));
    for (int conn = 0; conn < 50; ++conn) {
        sc::Aead2022TcpEncryptor cenc;
        sc::Aead2022TcpDecryptor sdec;
        SS_CHECK(cenc.init(psk, sc::Role::client) && sdec.init(psk, sc::Role::server, {}, &pool));
        for (std::size_t n : { sizeof(kAddr) + 1, (std::size_t)100, (std::size_t)16000 }) {
            auto w = cenc.seal({ plain, n }, wire);
            SS_CHECK(w);
            auto step = sdec.decrypt({ wire, *w }, out);
            SS_CHECK(step && step->consumed == *w);
        }
        sc::UdpSession2022 cs, ss2;
        for (int i = 0; i < 3; ++i) {
            auto p = sc::udp2022_seal(psk, sc::Role::client, cs, { plain, 1200 }, wire);
            SS_CHECK(p);
            auto pkt = sc::udp2022_decrypt(psk, { wire, *p }, out);
            SS_CHECK(pkt && sc::udp2022_accept(sc::Role::server, ss2, *pkt, out, std::time(nullptr)));
        }
    }
}

void test_methods()
{
    for (const char *m : kMethods) {
        tcp_c_client(m);
        tcp_cpp_client(m);
        udp(m);
        std::printf("ok %s\n", m);
    }
    tcp_rejects();
    udp_window();
    salt_pool();
    SS_CHECK(!sc::find_aead2022("aes-256-gcm"));
    auto spec = sc::find_aead2022("2022-blake3-aes-256-gcm");
    SS_CHECK(spec.has_value());
    SS_CHECK(!sc::Psk::from_base64(spec.value(), kPsk16)); // too short
    SS_CHECK(!sc::Psk::from_base64(spec.value(), "not base64"));
}

void test_no_heap_in_steady_state()
{
    sc::SaltPool pool;
    SS_CHECK(pool.reserve(4096, 42));
    sc::Psk keys[3] = { psk_of(kMethods[0]), psk_of(kMethods[1]), psk_of(kMethods[2]) };
    for (const sc::Psk &k : keys) {
        steady(k, pool);
    }
    ss::test::alloc_mark();
    for (const sc::Psk &k : keys) {
        steady(k, pool);
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
