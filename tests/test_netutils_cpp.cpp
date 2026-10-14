#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "test_helpers.h"

int verbose = 0;

#include "netutils.h"

static void
test_get_sockaddr_len(void)
{
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    struct sockaddr_storage unknown;

    memset(&addr4, 0, sizeof(addr4));
    addr4.sin_family = AF_INET;
    assert(get_sockaddr_len((struct sockaddr *)&addr4) == sizeof(struct sockaddr_in));

    memset(&addr6, 0, sizeof(addr6));
    addr6.sin6_family = AF_INET6;
    assert(get_sockaddr_len((struct sockaddr *)&addr6) == sizeof(struct sockaddr_in6));

    memset(&unknown, 0, sizeof(unknown));
    unknown.ss_family = AF_UNSPEC;
    assert(get_sockaddr_len((struct sockaddr *)&unknown) == 0);
}

static void
test_sockaddr_cmp(void)
{
    struct sockaddr_storage a, b;
    struct sockaddr_in *a4 = (struct sockaddr_in *)&a;
    struct sockaddr_in *b4 = (struct sockaddr_in *)&b;

    /* Same address and port */
    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a4->sin_family = AF_INET;
    b4->sin_family = AF_INET;
    a4->sin_port = htons(80);
    b4->sin_port = htons(80);
    inet_pton(AF_INET, "127.0.0.1", &a4->sin_addr);
    inet_pton(AF_INET, "127.0.0.1", &b4->sin_addr);
    assert(sockaddr_cmp(&a, &b, sizeof(struct sockaddr_in)) == 0);

    /* Different port */
    b4->sin_port = htons(81);
    assert(sockaddr_cmp(&a, &b, sizeof(struct sockaddr_in)) != 0);
}

static void
test_sockaddr_cmp_addr(void)
{
    struct sockaddr_storage a, b;
    struct sockaddr_in *a4 = (struct sockaddr_in *)&a;
    struct sockaddr_in *b4 = (struct sockaddr_in *)&b;

    memset(&a, 0, sizeof(a));
    memset(&b, 0, sizeof(b));
    a4->sin_family = AF_INET;
    b4->sin_family = AF_INET;
    a4->sin_port = htons(80);
    b4->sin_port = htons(443);
    inet_pton(AF_INET, "10.0.0.1", &a4->sin_addr);
    inet_pton(AF_INET, "10.0.0.1", &b4->sin_addr);

    /* Same address, different port - should be equal */
    assert(sockaddr_cmp_addr(&a, &b, sizeof(struct sockaddr_in)) == 0);

    /* Different address */
    inet_pton(AF_INET, "10.0.0.2", &b4->sin_addr);
    assert(sockaddr_cmp_addr(&a, &b, sizeof(struct sockaddr_in)) != 0);
}

static void
test_validate_hostname(void)
{
    /* Valid hostnames */
    assert(validate_hostname("example.com", 11) == 1);
    assert(validate_hostname("sub.example.com", 15) == 1);
    assert(validate_hostname("a", 1) == 1);
    assert(validate_hostname("a-b", 3) == 1);
    assert(validate_hostname("123.456", 7) == 1);

    /* Invalid hostnames */
    assert(validate_hostname(NULL, 0) == 0);
    assert(validate_hostname("", 0) == 0);
    assert(validate_hostname(".example.com", 12) == 0);     /* starts with dot */
    assert(validate_hostname("-example.com", 12) == 0);     /* label starts with hyphen */
    assert(validate_hostname("example-.com", 12) == 0);     /* label ends with hyphen */

    /* Too long hostname (> 255) */
    char long_name[260];
    memset(long_name, 'a', 259);
    long_name[259] = '\0';
    assert(validate_hostname(long_name, 259) == 0);

    /* Explicit length must be honored; callers may pass non-NUL data. */
    char raw_name[3] = { 'a', 'b', 'c' };
    assert(validate_hostname(raw_name, 3) == 1);
}

static void
test_get_sockaddr_rejects_invalid_ip_literal_ports(void)
{
    struct sockaddr_storage storage;
    struct sockaddr_in *addr4 = (struct sockaddr_in *)&storage;

    memset(&storage, 0, sizeof(storage));
    assert(get_sockaddr("localhost", "8388", &storage, 0, 0) == -1);
    assert(get_sockaddr("127.0.0.1", "8388", &storage, 0, 0) == 0);
    assert(addr4->sin_family == AF_INET);
    assert(ntohs(addr4->sin_port) == 8388);

    memset(&storage, 0, sizeof(storage));
    assert(get_sockaddr("127.0.0.1", "70000", &storage, 0, 0) == -1);

    memset(&storage, 0, sizeof(storage));
    assert(get_sockaddr("127.0.0.1", "12x", &storage, 0, 0) == -1);
}

int
main(void)
{
    test_network_init();
    test_get_sockaddr_len();
    test_sockaddr_cmp();
    test_sockaddr_cmp_addr();
    test_validate_hostname();
    test_get_sockaddr_rejects_invalid_ip_literal_ports();
    return 0;
}
