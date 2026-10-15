/* SPDX-License-Identifier: GPL-3.0-or-later */
// Configuration parsing: the address splitters and read_jconf, whose result
// lives in the configuration arena.

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "test_helpers.hpp"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "test_helpers.h"
#ifndef _WIN32
#include <sys/wait.h>
#endif

extern "C" int verbose;
int verbose = 0;

#include "netutils.h" // defines ss_addr_t, which jconf.h uses
#include "jconf.h"

namespace {

bool
same(const char *a, const char *b)
{
    return a == nullptr ? b == nullptr : b != nullptr && std::strcmp(a, b) == 0;
}

struct AddrCase {
    const char *input;
    const char *host;
    const char *port;
};

// parse_addr keeps anything it cannot split whole, so malformed bracketed
// IPv6 and IPv6-like host names are not rewritten.
constexpr AddrCase kAddrCases[] = {
    { "192.168.1.1:8080", "192.168.1.1", "8080" },
    { "[::1]:443", "::1", "443" },
    { "example.com:1234", "example.com", "1234" },
    { "10.0.0.1", "10.0.0.1", nullptr },
    { "::1", "::1", nullptr },
    { "[::1", "[::1", nullptr },
    { "bad::host", "bad::host", nullptr },
    { "[::1]:", "::1", nullptr },
    { "[::1]junk", "::1", nullptr },
    { "host:", "host", nullptr },
    { "", "", nullptr },
};

void
test_parse_addr()
{
    for (const AddrCase &c : kAddrCases) {
        ss_addr_t addr = {};
        parse_addr(c.input, &addr);
        SS_CHECK(same(addr.host, c.host));
        SS_CHECK(same(addr.port, c.port));
        free_addr(&addr);
    }
}

void
write_config(const char *path, const char *body)
{
    FILE *f = std::fopen(path, "wb");
    SS_CHECK(f != nullptr);
    std::fputs(body, f);
    std::fclose(f);
}

void
test_read_jconf_preserves_64bit_integer_strings()
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    SS_CHECK(f != nullptr);
    std::fclose(f);
    write_config(path, "{\n\"server\":\"127.0.0.1\",\n\"server_port\":4294967296,\n"
                       "\"password\":\"password\",\n\"method\":\"aes-128-gcm\"\n}\n");

    jconf_t *conf = read_jconf(path);
    SS_CHECK(conf != nullptr);
    SS_CHECK(same(conf->remote_port, "4294967296"));
    std::remove(path);
}

// Every field that read_jconf copies out of the parse tree, which is gone by
// the time it returns.
void
test_read_jconf_copies_out_of_the_parse_tree()
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    SS_CHECK(f != nullptr);
    std::fclose(f);
    write_config(path,
                 "{\n"
                 "  \"server\": [\"192.168.1.1:8080\", \"[::1]:443\", \"example.com\", \"bad::host\"],\n"
                 "  \"server_port\": 8388,\n"
                 "  \"local_address\": \"127.0.0.1\",\n"
                 "  \"local_port\": \"1080\",\n"
                 "  \"password\": \"pass\\u00e9word\",\n"
                 "  \"method\": \"chacha20-ietf-poly1305\",\n"
                 "  \"timeout\": 60,\n"
                 "  \"plugin\": \"\",\n"
                 "  \"plugin_opts\": \"a=b;c=d\",\n"
                 "  \"mode\": \"tcp_and_udp\",\n"
                 "  \"port_password\": {\"8381\": \"one\", \"8382\": \"two\", \"8383\": 3},\n"
                 "  \"dscp\": {\"8381\": \"EF\", \"8382\": \"AF41\"},\n"
                 "  \"acl\": null,\n"
                 "  \"max_connections\": 64\n"
                 "}\n");

    jconf_t *conf = read_jconf(path);
    SS_CHECK(conf != nullptr);
    SS_CHECK(conf->remote_num == 4);
    SS_CHECK(same(conf->remote_addr[0].host, "192.168.1.1") && same(conf->remote_addr[0].port, "8080"));
    SS_CHECK(same(conf->remote_addr[1].host, "::1") && same(conf->remote_addr[1].port, "443"));
    SS_CHECK(same(conf->remote_addr[2].host, "example.com") && conf->remote_addr[2].port == nullptr);
    SS_CHECK(same(conf->remote_addr[3].host, "bad::host") && conf->remote_addr[3].port == nullptr);
    SS_CHECK(same(conf->remote_port, "8388"));
    SS_CHECK(same(conf->local_addr, "127.0.0.1"));
    SS_CHECK(same(conf->local_port, "1080"));
    SS_CHECK(same(conf->password, "pass\xc3\xa9word"));
    SS_CHECK(same(conf->method, "chacha20-ietf-poly1305"));
    SS_CHECK(same(conf->timeout, "60"));
    SS_CHECK(conf->plugin == nullptr);
    SS_CHECK(same(conf->plugin_opts, "a=b;c=d"));
    SS_CHECK(conf->mode == TCP_AND_UDP);
    // Non-string passwords are skipped, as before.
    SS_CHECK(conf->port_password_num == 2);
    SS_CHECK(same(conf->port_password[0].port, "8381") && same(conf->port_password[0].password, "one"));
    SS_CHECK(same(conf->port_password[1].port, "8382") && same(conf->port_password[1].password, "two"));
    SS_CHECK(conf->dscp_num == 2);
    SS_CHECK(same(conf->dscp[0].port, "8381") && conf->dscp[0].dscp == 46);
    SS_CHECK(same(conf->dscp[1].port, "8382") && conf->dscp[1].dscp == 34);
    SS_CHECK(conf->acl == nullptr);
    SS_CHECK(conf->max_connections == 64);

    // A second read replaces the first one.
    write_config(path, "{\"server\":\"10.0.0.1:1\",\"method\":\"aes-256-gcm\",\"password\":\"x\"}");
    conf = read_jconf(path);
    SS_CHECK(conf != nullptr);
    SS_CHECK(conf->remote_num == 1);
    SS_CHECK(same(conf->remote_addr[0].host, "10.0.0.1") && same(conf->remote_addr[0].port, "1"));
    SS_CHECK(same(conf->method, "aes-256-gcm"));
    SS_CHECK(conf->remote_port == nullptr && conf->port_password_num == 0);
    std::remove(path);
}

// The largest accepted file must fit both arenas: many short values cost the
// most tree per input byte.
void
test_read_jconf_dense_file_fits()
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    SS_CHECK(f != nullptr);
    std::fputs("{\"method\":\"aes-128-gcm\",\"password\":\"p\",\"server\":\"h\",\"x\":[", f);
    long written = std::ftell(f);
    while (written < MAX_CONF_SIZE - 16) {
        std::fputs("[0],", f);
        written += 4;
    }
    std::fputs("0]}", f);
    std::fclose(f);

    jconf_t *conf = read_jconf(path);
    SS_CHECK(conf != nullptr);
    SS_CHECK(same(conf->method, "aes-128-gcm"));
    SS_CHECK(same(conf->remote_addr[0].host, "h"));
    std::remove(path);
}

const char *test_executable;

void
test_read_jconf_rejects_out_of_range_int_options()
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    SS_CHECK(f != nullptr);
    std::fclose(f);
    write_config(path, "{\n\"server\":\"127.0.0.1\",\n\"server_port\":8388,\n\"password\":\"password\",\n"
                       "\"method\":\"aes-128-gcm\",\n\"tcp_incoming_sndbuf\":2147483648\n}\n");

#ifdef _WIN32
    char command[3 * 4096];
    SS_CHECK(std::snprintf(command, sizeof(command), "\"%s\" --read-config \"%s\"", test_executable, path)
             < static_cast<int>(sizeof(command)));
    STARTUPINFOA startup       = {};
    PROCESS_INFORMATION child  = {};
    startup.cb                 = sizeof(startup);
    SS_CHECK(CreateProcessA(test_executable, command, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &startup,
                            &child));
    CloseHandle(child.hThread);
    SS_CHECK(WaitForSingleObject(child.hProcess, 10000) == WAIT_OBJECT_0);
    DWORD status;
    SS_CHECK(GetExitCodeProcess(child.hProcess, &status));
    CloseHandle(child.hProcess);
    // FATAL exits with -1, which is a valid nonzero DWORD exit status.
    SS_CHECK(status != 0);
#else
    std::fflush(stdout); // the child's FATAL exit would flush it again
    pid_t pid = fork();
    SS_CHECK(pid >= 0);
    if (pid == 0) {
        read_jconf(path);
        _exit(0);
    }

    int status;
    SS_CHECK(waitpid(pid, &status, 0) == pid);
    SS_CHECK(WIFEXITED(status));
    SS_CHECK(WEXITSTATUS(status) != 0);
#endif

    std::remove(path);
}

void
test_server_endpoints()
{
    const AddrCase valid[] = {
        { "example.com:8388", "example.com", "8388" },
        { "127.0.0.1:1", "127.0.0.1", "1" },
        { "[2001:db8::1]:65535", "2001:db8::1", "65535" },
        { "[fe80::1%eth0]:8388", "fe80::1%eth0", "8388" },
        { "[fe80::1%3]:8388", "fe80::1%3", "8388" },
        { "2001:db8::1:8388", "2001:db8::1:8388", nullptr },
        { "fe80::1%eth0", "fe80::1%eth0", nullptr },
        { "::", "::", nullptr },
        { "[::1]", "::1", nullptr },
        { "example.com", "example.com", nullptr },
    };
    for (const AddrCase &c : valid) {
        ss_addr_t addr = {};
        SS_CHECK(parse_server_endpoint(c.input, &addr) == 0);
        SS_CHECK(same(addr.host, c.host));
        SS_CHECK(same(addr.port, c.port));
        free_addr(&addr);
    }
    const char *invalid[] = { "", ":8388", "host:", "host:0", "host:65536",
                              "host:-1", "host:+1", "host:abc", "host:80:90", "[::1", "[::1]junk",
                              "[::1]:", "[::1]:0", "[::1]:65536", "[::1]:80:90", "[]:80",
                              "[example.com]:80", "[127.0.0.1]:80", "[bad::host]:80", "host]:80",
                              "[fe80::1%]:80", "[fe80::1%a%b]:80", "host :80", "ss://host:80" };
    for (const char *input : invalid) {
        ss_addr_t addr = {};
        SS_CHECK(parse_server_endpoint(input, &addr) == -1);
        SS_CHECK(addr.host == nullptr && addr.port == nullptr);
    }
    ss_addr_t addr[2] = {};
    SS_CHECK(parse_server_endpoint("[::1]:8388", &addr[0]) == 0);
    SS_CHECK(parse_server_endpoint("localhost:8389", &addr[1]) == 0);
    SS_CHECK(complete_server_ports(addr, 2, nullptr, 0) == 0);
    SS_CHECK(complete_server_ports(addr, 2, "9000", 0) == 0);
    SS_CHECK(same(addr[0].port, "8388") && same(addr[1].port, "8389"));
    SS_CHECK(complete_server_ports(addr, 2, nullptr, 1) == -1);
    free_addr(&addr[1]);
    addr[1] = {};
    SS_CHECK(parse_server_endpoint("::1", &addr[1]) == 0);
    SS_CHECK(complete_server_ports(addr, 2, nullptr, 0) == -1);
    SS_CHECK(complete_server_ports(addr, 2, "8388", 1) == 0);
    SS_CHECK(same(addr[1].port, "8388"));
    free_addr(&addr[0]);
    free_addr(&addr[1]);
}

} // namespace

int
main(int argc, char **argv)
{
    test_executable = argv[0];
    test_network_init();
    if (argc == 3 && std::strcmp(argv[1], "--read-config") == 0) {
        read_jconf(argv[2]);
        return 0;
    }
    SS_RUN(test_server_endpoints);
    SS_RUN(test_parse_addr);
    SS_RUN(test_read_jconf_preserves_64bit_integer_strings);
    SS_RUN(test_read_jconf_copies_out_of_the_parse_tree);
    SS_RUN(test_read_jconf_dense_file_fits);
    SS_RUN(test_read_jconf_rejects_out_of_range_int_options);
    return 0;
}
