// SPDX-License-Identifier: GPL-3.0-or-later
// Address helpers (src/netutils.cpp): sockaddr comparison, hostname
// validation and literal-address parsing.
#include <cstring>

#include "netutils.h"
#include "test_helpers.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

// get_sockaddr() takes writable strings; copy the literals.
ssize_t resolve(const char *host, const char *port, sockaddr_storage *storage)
{
    char host_buf[64];
    char port_buf[16];
    SS_CHECK(std::strlen(host) < sizeof(host_buf) && std::strlen(port) < sizeof(port_buf));
    std::strcpy(host_buf, host);
    std::strcpy(port_buf, port);
    return get_sockaddr(host_buf, port_buf, storage, 0, 0);
}

void test_get_sockaddr_len()
{
    sockaddr_in addr4{};
    addr4.sin_family = AF_INET;
    SS_CHECK(get_sockaddr_len(reinterpret_cast<sockaddr *>(&addr4)) == sizeof(sockaddr_in));

    sockaddr_in6 addr6{};
    addr6.sin6_family = AF_INET6;
    SS_CHECK(get_sockaddr_len(reinterpret_cast<sockaddr *>(&addr6)) == sizeof(sockaddr_in6));

    sockaddr_storage unknown{};
    unknown.ss_family = AF_UNSPEC;
    SS_CHECK(get_sockaddr_len(reinterpret_cast<sockaddr *>(&unknown)) == 0);
}

void test_sockaddr_cmp()
{
    sockaddr_storage a{};
    sockaddr_storage b{};
    auto *a4 = reinterpret_cast<sockaddr_in *>(&a);
    auto *b4 = reinterpret_cast<sockaddr_in *>(&b);

    // Same address and port.
    a4->sin_family = AF_INET;
    b4->sin_family = AF_INET;
    a4->sin_port   = htons(80);
    b4->sin_port   = htons(80);
    inet_pton(AF_INET, "127.0.0.1", &a4->sin_addr);
    inet_pton(AF_INET, "127.0.0.1", &b4->sin_addr);
    SS_CHECK(sockaddr_cmp(&a, &b, sizeof(sockaddr_in)) == 0);

    // Different port.
    b4->sin_port = htons(81);
    SS_CHECK(sockaddr_cmp(&a, &b, sizeof(sockaddr_in)) != 0);
}

void test_sockaddr_cmp_addr()
{
    sockaddr_storage a{};
    sockaddr_storage b{};
    auto *a4 = reinterpret_cast<sockaddr_in *>(&a);
    auto *b4 = reinterpret_cast<sockaddr_in *>(&b);

    a4->sin_family = AF_INET;
    b4->sin_family = AF_INET;
    a4->sin_port   = htons(80);
    b4->sin_port   = htons(443);
    inet_pton(AF_INET, "10.0.0.1", &a4->sin_addr);
    inet_pton(AF_INET, "10.0.0.1", &b4->sin_addr);

    // Same address, different port - should be equal.
    SS_CHECK(sockaddr_cmp_addr(&a, &b, sizeof(sockaddr_in)) == 0);

    // Different address.
    inet_pton(AF_INET, "10.0.0.2", &b4->sin_addr);
    SS_CHECK(sockaddr_cmp_addr(&a, &b, sizeof(sockaddr_in)) != 0);
}

void test_validate_hostname()
{
    // Valid hostnames.
    SS_CHECK(validate_hostname("example.com", 11) == 1);
    SS_CHECK(validate_hostname("sub.example.com", 15) == 1);
    SS_CHECK(validate_hostname("a", 1) == 1);
    SS_CHECK(validate_hostname("a-b", 3) == 1);
    SS_CHECK(validate_hostname("123.456", 7) == 1);

    // Invalid hostnames.
    SS_CHECK(validate_hostname(nullptr, 0) == 0);
    SS_CHECK(validate_hostname("", 0) == 0);
    SS_CHECK(validate_hostname(".example.com", 12) == 0); // starts with dot
    SS_CHECK(validate_hostname("-example.com", 12) == 0); // label starts with hyphen
    SS_CHECK(validate_hostname("example-.com", 12) == 0); // label ends with hyphen

    // Too long hostname (> 255).
    char long_name[260];
    std::memset(long_name, 'a', 259);
    long_name[259] = '\0';
    SS_CHECK(validate_hostname(long_name, 259) == 0);

    // Explicit length must be honored; callers may pass non-NUL data.
    const char raw_name[3] = { 'a', 'b', 'c' };
    SS_CHECK(validate_hostname(raw_name, 3) == 1);
}

void test_get_sockaddr_rejects_invalid_ip_literal_ports()
{
    sockaddr_storage storage{};
    auto *addr4 = reinterpret_cast<sockaddr_in *>(&storage);

    SS_CHECK(resolve("localhost", "8388", &storage) == -1);
    SS_CHECK(resolve("127.0.0.1", "8388", &storage) == 0);
    SS_CHECK(addr4->sin_family == AF_INET);
    SS_CHECK(ntohs(addr4->sin_port) == 8388);

    storage = sockaddr_storage{};
    SS_CHECK(resolve("127.0.0.1", "70000", &storage) == -1);

    storage = sockaddr_storage{};
    SS_CHECK(resolve("127.0.0.1", "12x", &storage) == -1);
}

} // namespace

int main()
{
    test_network_init();
    SS_RUN(test_get_sockaddr_len);
    SS_RUN(test_sockaddr_cmp);
    SS_RUN(test_sockaddr_cmp_addr);
    SS_RUN(test_validate_hostname);
    SS_RUN(test_get_sockaddr_rejects_invalid_ip_literal_ports);
    return 0;
}
