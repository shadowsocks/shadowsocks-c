// SPDX-License-Identifier: GPL-3.0-or-later
// ACL file parsing (src/acl.cpp): an invalid entry fails the whole load,
// valid ones match, and IPv4-mapped addresses meet the IPv4 rules.
#include <cstdio>
#include <cstdlib>
#include <initializer_list>

#include "acl.h"
#include "test_helpers.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

// Writes `body` to a temporary ACL file and loads it.
int load_acl(const char *body)
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    SS_CHECK(f != nullptr);
    std::fputs(body, f);
    std::fclose(f);
    int rc = init_acl(path);
    std::remove(path);
    return rc;
}

void test_invalid_regex_fails_the_load()
{
    // An unusable rule must not silently drop out of a block list: the
    // whole file is refused and nothing stays installed.
    SS_CHECK(load_acl("[black_list]\n[invalid\n^blocked\\.example$\n") == -1);
    SS_CHECK(acl_match_host("blocked.example") == 0);
    SS_CHECK(load_acl("[outbound_block_list]\n^outbound\\.example$\n[also-invalid\n") == -1);
    SS_CHECK(outbound_block_match_host("outbound.example") == 0);
    SS_CHECK(get_acl_mode() == BLACK_LIST);

    SS_CHECK(load_acl("[black_list]\n^blocked\\.example$\n[outbound_block_list]\n^outbound\\.example$\n") == 0);
    SS_CHECK(acl_match_host("does-not-crash.example") == 0);
    SS_CHECK(acl_match_host("blocked.example") == 1);
    SS_CHECK(outbound_block_match_host("does-not-crash.example") == 0);
    SS_CHECK(outbound_block_match_host("outbound.example") == 1);
    free_acl();
}

void test_reload_starts_from_nothing()
{
    SS_CHECK(load_acl("[reject_all]\n[white_list]\n1.1.1.1\n") == 0);
    SS_CHECK(get_acl_mode() == WHITE_LIST);
    SS_CHECK(load_acl("[black_list]\n2.2.2.2\n") == 0);
    SS_CHECK(get_acl_mode() == BLACK_LIST);
    SS_CHECK(acl_match_host("1.1.1.1") == 0);
    SS_CHECK(acl_match_host("2.2.2.2") == 1);
    free_acl();
}

void test_rules_ignore_case_and_trailing_dot()
{
    SS_CHECK(load_acl("[outbound_block_list]\n(^|\\.)localhost$\nfull:internal.example\n") == 0);
    SS_CHECK(outbound_block_match_host("LOCALHOST") == 1);
    SS_CHECK(outbound_block_match_host("localhost.") == 1);
    SS_CHECK(outbound_block_match_host("Internal.Example.") == 1);
    SS_CHECK(outbound_block_match_host("example") == 0);
    free_acl();
}

void test_ipv4_mapped_addresses_match_ipv4_rules()
{
    SS_CHECK(load_acl("[outbound_block_list]\n127.0.0.0/8\n169.254.169.254\n::ffff:10.0.0.0/104\n") == 0);
    SS_CHECK(outbound_block_match_host("127.0.0.1") == 1);
    SS_CHECK(outbound_block_match_host("::ffff:127.0.0.1") == 1);
    SS_CHECK(outbound_block_match_host("::FFFF:169.254.169.254") == 1);
    SS_CHECK(outbound_block_match_host("10.1.2.3") == 1); // from the mapped /104
    SS_CHECK(outbound_block_match_host("::ffff:10.1.2.3") == 1);
    SS_CHECK(outbound_block_match_host("::ffff:8.8.8.8") == 0);
    SS_CHECK(outbound_block_match_host("::1") == 0);
    free_acl();

    SS_CHECK(load_acl("[black_list]\n203.0.113.0/24\n") == 0);
    SS_CHECK(acl_match_host("::ffff:203.0.113.7") == 1); // a v4 client on a dual-stack socket
    free_acl();
}

void test_long_acl_line_is_discarded()
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    SS_CHECK(f != nullptr);
    std::fprintf(f, "[black_list]\n");
    for (int i = 0; i < 400; i++) {
        std::fputc('a', f);
    }
    std::fprintf(f, "\n");
    std::fprintf(f, "^kept\\.example$\n");
    std::fclose(f);

    SS_CHECK(init_acl(path) == 0);
    SS_CHECK(acl_match_host("kept.example") == 1);
    free_acl();

    std::remove(path);
}

void test_invalid_cidr_fails_the_load()
{
    for (const char *line : { "1.2.3.0/999\n", "2.2.2.2/-1\n", "3.3.3.3/abc\n", "::1/129\n", "::ffff:1.2.3.4/64\n" }) {
        char body[64];
        std::snprintf(body, sizeof(body), "[black_list]\n4.4.4.0/24\n%s", line);
        SS_CHECK(load_acl(body) == -1);
        SS_CHECK(acl_match_host("4.4.4.8") == 0);
    }
    SS_CHECK(load_acl("[black_list]\n4.4.4.0/24\n^path/with/slash\\.example$\n") == 0);
    SS_CHECK(acl_match_host("4.4.4.8") == 1);
    SS_CHECK(acl_match_host("path/with/slash.example") == 1);
    free_acl();
}

} // namespace

int main()
{
    SS_RUN(test_invalid_regex_fails_the_load);
    SS_RUN(test_reload_starts_from_nothing);
    SS_RUN(test_rules_ignore_case_and_trailing_dot);
    SS_RUN(test_ipv4_mapped_addresses_match_ipv4_rules);
    SS_RUN(test_long_acl_line_is_discarded);
    SS_RUN(test_invalid_cidr_fails_the_load);
    return 0;
}
