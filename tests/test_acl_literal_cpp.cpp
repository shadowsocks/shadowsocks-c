// SPDX-License-Identifier: GPL-3.0-or-later
// ACL literal rules (full:/suffix:), CIDR sets and runtime IP edits
// (src/acl.cpp).
#include <cstdio>

#ifdef HAVE_CONFIG_H
#include "config.h" // SS_ENABLE_REGEX
#endif

#include "acl.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

void write_file(const char *path, const char *content)
{
    FILE *file = std::fopen(path, "w");
    SS_CHECK(file != nullptr);
    std::fputs(content, file);
    std::fclose(file);
}

void test_acl_literal(const char *argv0)
{
    char path[4096];
    SS_CHECK(std::snprintf(path, sizeof(path), "%s.acl", argv0) < static_cast<int>(sizeof(path)));
    write_file(path,
               "[black_list]\nfull:Exact.example\nsuffix:blocked.example\n10.0.0.0/8\n"
               "2001:db8::/32\n[white_list]\nsuffix:allowed.example\n"
               "[outbound_block_list]\nfull:outbound.example\n");
    SS_CHECK(init_acl(path) == 0);
    SS_CHECK(acl_match_host("EXACT.example") == 1);
    SS_CHECK(acl_match_host("sub.exact.example") == 0);
    SS_CHECK(acl_match_host("blocked.example") == 1);
    SS_CHECK(acl_match_host("a.blocked.example") == 1);
    SS_CHECK(acl_match_host("notblocked.example") == 0);
    SS_CHECK(acl_match_host("blocked.example.evil") == 0);
    SS_CHECK(acl_match_host("a.allowed.example") == -1);
    SS_CHECK(outbound_block_match_host("outbound.example") == 1);
    SS_CHECK(outbound_block_match_host("a.outbound.example") == 0);
    SS_CHECK(acl_match_host("10.42.1.2") == 1);
    SS_CHECK(acl_remove_ip("10.42.1.2") == 0);
    SS_CHECK(acl_match_host("10.42.1.2") == 0);
    SS_CHECK(acl_match_host("10.42.1.3") == 1);
    SS_CHECK(acl_add_ip("10.42.1.2") == 0);
    SS_CHECK(acl_match_host("10.42.1.2") == 1);
    SS_CHECK(acl_remove_ip("2001:db8::42") == 0);
    SS_CHECK(acl_match_host("2001:db8::42") == 0);
    SS_CHECK(acl_match_host("2001:db8::43") == 1);
    free_acl();
#if !SS_ENABLE_REGEX
    write_file(path, "[black_list]\n10.0.0.0/8\n^old\\.regex$\n");
    SS_CHECK(init_acl(path) == -1);
    SS_CHECK(acl_match_host("10.1.1.1") == 0);
#endif
    std::remove(path);
}

} // namespace

int main(int argc, char **argv)
{
    SS_CHECK(argc >= 1);
    test_acl_literal(argv[0]);
    std::printf("ok test_acl_literal\n");
    return 0;
}
