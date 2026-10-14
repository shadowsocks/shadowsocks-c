// SPDX-License-Identifier: GPL-3.0-or-later
// ss:// URI parsing (src/ssurl.cpp): SIP002, the legacy form and malformed
// input.
#include <cstddef>
#include <cstring>

#include "ssurl.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

bool streq(const char *a, const char *b)
{
    return a != nullptr && std::strcmp(a, b) == 0;
}

/* ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.168.100.1:8888 */
void test_sip002_basic()
{
    ss_url_t u;

    SS_CHECK(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.168.100.1:8888",
                        &u) == 0);
    SS_CHECK(streq(u.method, "aes-256-gcm"));
    SS_CHECK(streq(u.password, "password"));
    SS_CHECK(streq(u.host, "192.168.100.1"));
    SS_CHECK(streq(u.port, "8888"));
    SS_CHECK(u.plugin == nullptr);
    ss_url_free(&u);
}

/* A tag after '#' is descriptive only and must not leak into the fields. */
void test_sip002_tag()
{
    ss_url_t u;

    SS_CHECK(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.168.100.1:8888"
                        "#Example%20Server", &u) == 0);
    SS_CHECK(streq(u.host, "192.168.100.1"));
    SS_CHECK(streq(u.tag, "Example Server"));
    ss_url_free(&u);
}

/* SIP003 plugin, with its options after the ';'. */
void test_sip002_plugin()
{
    ss_url_t u;

    SS_CHECK(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.168.100.1:8888"
                        "/?plugin=obfs-local%3Bobfs%3Dhttp#tag", &u) == 0);
    SS_CHECK(streq(u.host, "192.168.100.1"));
    SS_CHECK(streq(u.port, "8888"));
    SS_CHECK(streq(u.plugin, "obfs-local"));
    SS_CHECK(streq(u.plugin_opts, "obfs=http"));
    SS_CHECK(streq(u.tag, "tag"));
    ss_url_free(&u);
}

/* The trailing slash before a query is allowed, and so is no query at all. */
void test_sip002_trailing_slash()
{
    ss_url_t u;

    SS_CHECK(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388/",
                        &u) == 0);
    SS_CHECK(streq(u.host, "example.com"));
    SS_CHECK(streq(u.port, "8388"));
    ss_url_free(&u);
}

/* A bracketed IPv6 literal must keep its address and port apart. */
void test_sip002_ipv6()
{
    ss_url_t u;

    SS_CHECK(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@[2001:db8::1]:8388",
                        &u) == 0);
    SS_CHECK(streq(u.host, "2001:db8::1"));
    SS_CHECK(streq(u.port, "8388"));
    ss_url_free(&u);
}

/* Some producers write the userinfo in the clear rather than base64. */
void test_sip002_plain_userinfo()
{
    ss_url_t u;

    SS_CHECK(ss_url_parse("ss://aes-256-gcm:secret@example.com:8388", &u) == 0);
    SS_CHECK(streq(u.method, "aes-256-gcm"));
    SS_CHECK(streq(u.password, "secret"));
    SS_CHECK(streq(u.host, "example.com"));
    ss_url_free(&u);
}

/*
 * A 2022 pre-shared key is base64 and can contain '+', '/' and '='. Encoded
 * into the userinfo it must survive the round trip byte for byte.
 */
void test_sip002_2022_psk()
{
    ss_url_t u;

    /* base64("2022-blake3-aes-256-gcm:ZG9uJ3QgdXNlIHRoaXMga2V5Pz8/Pz8/Pz8=") */
    const char *uri =
        "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206Wkc5dUozUWdkWE5sSUhSb2FYTWdhMlY1"
        "Pz8_Pz8_Pz89@example.com:8388";

    SS_CHECK(ss_url_parse(uri, &u) == 0);
    SS_CHECK(streq(u.method, "2022-blake3-aes-256-gcm"));
    SS_CHECK(streq(u.host, "example.com"));
    SS_CHECK(streq(u.port, "8388"));
    ss_url_free(&u);
}

/* Legacy form: the whole body is one base64 blob. */
void test_legacy()
{
    ss_url_t u;

    /* base64("aes-256-cfb:password@192.168.100.1:8888") */
    SS_CHECK(ss_url_parse("ss://YWVzLTI1Ni1jZmI6cGFzc3dvcmRAMTkyLjE2OC4xMDAuMTo4ODg4",
                        &u) == 0);
    SS_CHECK(streq(u.method, "aes-256-cfb"));
    SS_CHECK(streq(u.password, "password"));
    SS_CHECK(streq(u.host, "192.168.100.1"));
    SS_CHECK(streq(u.port, "8888"));
    ss_url_free(&u);
}

/* Malformed input must be rejected, not half-parsed. */
void test_rejects_malformed()
{
    ss_url_t u;

    static const char *const bad[] = {
        nullptr,
        "",
        "http://example.com",
        "ss://",
        "ss://@example.com:8388",             /* empty userinfo */
        "ss://YWVzOnB3@example.com",          /* no port */
        "ss://YWVzOnB3@:8388",                /* no host */
        "ss://YWVzOnB3@example.com:",         /* empty port */
        "ss://bm9jb2xvbg@example.com:8388",   /* userinfo lacks ':' */
        "ss://YWVzOnB3@[2001:db8::1",         /* unterminated bracket */
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        std::memset(&u, 0xa5, sizeof(u));
        SS_CHECK(ss_url_parse(bad[i], &u) == -1);
        /* a rejected parse must leave nothing behind to free */
        SS_CHECK(u.method == nullptr && u.host == nullptr && u.port == nullptr);
    }
}

/*
 * URIs emitted by shadowsocks-rust's `ssurl --encode`, copied verbatim.
 * These pin the shapes another implementation actually produces, which is
 * what the parser has to accept in the field.
 */
void test_rust_ssurl_output()
{
    ss_url_t u;

    /* A 2022 cipher: plain userinfo, '=' of the key percent-encoded. */
    SS_CHECK(ss_url_parse("ss://2022-blake3-aes-256-gcm:"
                        "ZG9uJ3QgdXNlIHRoaXMga2V5ISEhISEhISEhISEhISE%3D"
                        "@192.168.100.1:8888", &u) == 0);
    SS_CHECK(streq(u.method, "2022-blake3-aes-256-gcm"));
    SS_CHECK(streq(u.password, "ZG9uJ3QgdXNlIHRoaXMga2V5ISEhISEhISEhISEhISE="));
    SS_CHECK(streq(u.host, "192.168.100.1"));
    SS_CHECK(streq(u.port, "8888"));
    ss_url_free(&u);

    /* A legacy cipher: unpadded base64 userinfo, plugin in the query. */
    SS_CHECK(ss_url_parse("ss://YWVzLTI1Ni1nY206dGVzdC1wYXNzd29yZA"
                        "@192.168.100.1:8888/?plugin=obfs%2Dlocal%3Bobfs%3Dhttp",
                        &u) == 0);
    SS_CHECK(streq(u.method, "aes-256-gcm"));
    SS_CHECK(streq(u.password, "test-password"));
    SS_CHECK(streq(u.plugin, "obfs-local"));
    SS_CHECK(streq(u.plugin_opts, "obfs=http"));
    ss_url_free(&u);

    /* An IPv6 server. */
    SS_CHECK(ss_url_parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw"
                        "@[2001:db8::1]:8388", &u) == 0);
    SS_CHECK(streq(u.method, "chacha20-ietf-poly1305"));
    SS_CHECK(streq(u.password, "pw"));
    SS_CHECK(streq(u.host, "2001:db8::1"));
    SS_CHECK(streq(u.port, "8388"));
    ss_url_free(&u);
}

/* Freeing a zeroed struct, or nullptr, must be safe. */
void test_free_is_safe()
{
    ss_url_t u{};

    ss_url_free(&u);
    ss_url_free(nullptr);
}

} // namespace

int main()
{
    SS_RUN(test_sip002_basic);
    SS_RUN(test_sip002_tag);
    SS_RUN(test_sip002_plugin);
    SS_RUN(test_sip002_trailing_slash);
    SS_RUN(test_sip002_ipv6);
    SS_RUN(test_sip002_plain_userinfo);
    SS_RUN(test_sip002_2022_psk);
    SS_RUN(test_legacy);
    SS_RUN(test_rejects_malformed);
    SS_RUN(test_rust_ssurl_output);
    SS_RUN(test_free_is_safe);
    return 0;
}
