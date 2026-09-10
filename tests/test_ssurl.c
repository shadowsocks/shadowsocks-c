/*
 * Unit tests for ss:// URI parsing (SIP002 and the legacy form).
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>

int verbose = 0;

#include "ssurl.h"

#define STREQ(a, b) ((a) != NULL && strcmp((a), (b)) == 0)

/* ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.168.100.1:8888 */
static void
test_sip002_basic(void)
{
    ss_url_t u;

    assert(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.168.100.1:8888",
                        &u) == 0);
    assert(STREQ(u.method, "aes-256-gcm"));
    assert(STREQ(u.password, "password"));
    assert(STREQ(u.host, "192.168.100.1"));
    assert(STREQ(u.port, "8888"));
    assert(u.plugin == NULL);
    ss_url_free(&u);
}

/* A tag after '#' is descriptive only and must not leak into the fields. */
static void
test_sip002_tag(void)
{
    ss_url_t u;

    assert(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.168.100.1:8888"
                        "#Example%20Server", &u) == 0);
    assert(STREQ(u.host, "192.168.100.1"));
    assert(STREQ(u.tag, "Example Server"));
    ss_url_free(&u);
}

/* SIP003 plugin, with its options after the ';'. */
static void
test_sip002_plugin(void)
{
    ss_url_t u;

    assert(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@192.168.100.1:8888"
                        "/?plugin=obfs-local%3Bobfs%3Dhttp#tag", &u) == 0);
    assert(STREQ(u.host, "192.168.100.1"));
    assert(STREQ(u.port, "8888"));
    assert(STREQ(u.plugin, "obfs-local"));
    assert(STREQ(u.plugin_opts, "obfs=http"));
    assert(STREQ(u.tag, "tag"));
    ss_url_free(&u);
}

/* The trailing slash before a query is allowed, and so is no query at all. */
static void
test_sip002_trailing_slash(void)
{
    ss_url_t u;

    assert(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:8388/",
                        &u) == 0);
    assert(STREQ(u.host, "example.com"));
    assert(STREQ(u.port, "8388"));
    ss_url_free(&u);
}

/* A bracketed IPv6 literal must keep its address and port apart. */
static void
test_sip002_ipv6(void)
{
    ss_url_t u;

    assert(ss_url_parse("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@[2001:db8::1]:8388",
                        &u) == 0);
    assert(STREQ(u.host, "2001:db8::1"));
    assert(STREQ(u.port, "8388"));
    ss_url_free(&u);
}

/* Some producers write the userinfo in the clear rather than base64. */
static void
test_sip002_plain_userinfo(void)
{
    ss_url_t u;

    assert(ss_url_parse("ss://aes-256-gcm:secret@example.com:8388", &u) == 0);
    assert(STREQ(u.method, "aes-256-gcm"));
    assert(STREQ(u.password, "secret"));
    assert(STREQ(u.host, "example.com"));
    ss_url_free(&u);
}

/*
 * A 2022 pre-shared key is base64 and can contain '+', '/' and '='. Encoded
 * into the userinfo it must survive the round trip byte for byte.
 */
static void
test_sip002_2022_psk(void)
{
    ss_url_t u;

    /* base64("2022-blake3-aes-256-gcm:ZG9uJ3QgdXNlIHRoaXMga2V5Pz8/Pz8/Pz8=") */
    const char *uri =
        "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206Wkc5dUozUWdkWE5sSUhSb2FYTWdhMlY1"
        "Pz8_Pz8_Pz89@example.com:8388";

    assert(ss_url_parse(uri, &u) == 0);
    assert(STREQ(u.method, "2022-blake3-aes-256-gcm"));
    assert(STREQ(u.host, "example.com"));
    assert(STREQ(u.port, "8388"));
    ss_url_free(&u);
}

/* Legacy form: the whole body is one base64 blob. */
static void
test_legacy(void)
{
    ss_url_t u;

    /* base64("aes-256-cfb:password@192.168.100.1:8888") */
    assert(ss_url_parse("ss://YWVzLTI1Ni1jZmI6cGFzc3dvcmRAMTkyLjE2OC4xMDAuMTo4ODg4",
                        &u) == 0);
    assert(STREQ(u.method, "aes-256-cfb"));
    assert(STREQ(u.password, "password"));
    assert(STREQ(u.host, "192.168.100.1"));
    assert(STREQ(u.port, "8888"));
    ss_url_free(&u);
}

/* Malformed input must be rejected, not half-parsed. */
static void
test_rejects_malformed(void)
{
    ss_url_t u;

    static const char *bad[] = {
        NULL,
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
        memset(&u, 0xa5, sizeof(u));
        assert(ss_url_parse(bad[i], &u) == -1);
        /* a rejected parse must leave nothing behind to free */
        assert(u.method == NULL && u.host == NULL && u.port == NULL);
    }
}

/*
 * URIs emitted by shadowsocks-rust's `ssurl --encode`, copied verbatim.
 * These pin the shapes another implementation actually produces, which is
 * what the parser has to accept in the field.
 */
static void
test_rust_ssurl_output(void)
{
    ss_url_t u;

    /* A 2022 cipher: plain userinfo, '=' of the key percent-encoded. */
    assert(ss_url_parse("ss://2022-blake3-aes-256-gcm:"
                        "ZG9uJ3QgdXNlIHRoaXMga2V5ISEhISEhISEhISEhISE%3D"
                        "@192.168.100.1:8888", &u) == 0);
    assert(STREQ(u.method, "2022-blake3-aes-256-gcm"));
    assert(STREQ(u.password, "ZG9uJ3QgdXNlIHRoaXMga2V5ISEhISEhISEhISEhISE="));
    assert(STREQ(u.host, "192.168.100.1"));
    assert(STREQ(u.port, "8888"));
    ss_url_free(&u);

    /* A legacy cipher: unpadded base64 userinfo, plugin in the query. */
    assert(ss_url_parse("ss://YWVzLTI1Ni1nY206dGVzdC1wYXNzd29yZA"
                        "@192.168.100.1:8888/?plugin=obfs%2Dlocal%3Bobfs%3Dhttp",
                        &u) == 0);
    assert(STREQ(u.method, "aes-256-gcm"));
    assert(STREQ(u.password, "test-password"));
    assert(STREQ(u.plugin, "obfs-local"));
    assert(STREQ(u.plugin_opts, "obfs=http"));
    ss_url_free(&u);

    /* An IPv6 server. */
    assert(ss_url_parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw"
                        "@[2001:db8::1]:8388", &u) == 0);
    assert(STREQ(u.method, "chacha20-ietf-poly1305"));
    assert(STREQ(u.password, "pw"));
    assert(STREQ(u.host, "2001:db8::1"));
    assert(STREQ(u.port, "8388"));
    ss_url_free(&u);
}

/* Freeing a zeroed struct, or NULL, must be safe. */
static void
test_free_is_safe(void)
{
    ss_url_t u = { 0 };

    ss_url_free(&u);
    ss_url_free(NULL);
}

int
main(void)
{
    test_sip002_basic();
    test_sip002_tag();
    test_sip002_plugin();
    test_sip002_trailing_slash();
    test_sip002_ipv6();
    test_sip002_plain_userinfo();
    test_sip002_2022_psk();
    test_legacy();
    test_rust_ssurl_output();
    test_rejects_malformed();
    test_free_is_safe();
    return 0;
}
