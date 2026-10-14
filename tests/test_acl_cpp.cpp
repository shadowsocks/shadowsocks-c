// SPDX-License-Identifier: GPL-3.0-or-later
// ACL file parsing (src/acl.cpp): invalid rules are discarded, valid ones
// still match.
#include <cstdio>
#include <cstdlib>

#include "acl.h"
#include "test_helpers.h"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

void test_invalid_regex_is_not_installed()
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    SS_CHECK(f != nullptr);
    std::fprintf(f, "[black_list]\n");
    std::fprintf(f, "[invalid\n");
    std::fprintf(f, "^blocked\\.example$\n");
    std::fprintf(f, "[outbound_block_list]\n");
    std::fprintf(f, "[also-invalid\n");
    std::fprintf(f, "^outbound\\.example$\n");
    std::fclose(f);

    SS_CHECK(init_acl(path) == 0);
    SS_CHECK(acl_match_host("does-not-crash.example") == 0);
    SS_CHECK(acl_match_host("blocked.example") == 1);
    SS_CHECK(outbound_block_match_host("does-not-crash.example") == 0);
    SS_CHECK(outbound_block_match_host("outbound.example") == 1);
    free_acl();

    std::remove(path);
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

void test_invalid_cidr_is_discarded()
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    SS_CHECK(f != nullptr);
    std::fprintf(f, "[black_list]\n");
    std::fprintf(f, "1.2.3.0/999\n");
    std::fprintf(f, "2.2.2.2/-1\n");
    std::fprintf(f, "3.3.3.3/abc\n");
    std::fprintf(f, "4.4.4.0/24\n");
    std::fprintf(f, "^path/with/slash\\.example$\n");
    std::fclose(f);

    SS_CHECK(init_acl(path) == 0);
    SS_CHECK(acl_match_host("1.2.3.1") == 0);
    SS_CHECK(acl_match_host("2.2.2.2") == 0);
    SS_CHECK(acl_match_host("3.3.3.3") == 0);
    SS_CHECK(acl_match_host("4.4.4.8") == 1);
    SS_CHECK(acl_match_host("path/with/slash.example") == 1);
    free_acl();

    std::remove(path);
}

} // namespace

int main()
{
    SS_RUN(test_invalid_regex_is_not_installed);
    SS_RUN(test_long_acl_line_is_discarded);
    SS_RUN(test_invalid_cidr_is_discarded);
    return 0;
}
