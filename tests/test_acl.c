#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "test_helpers.h"

#include "acl.h"

int verbose = 0;

static void
test_invalid_regex_is_not_installed(void)
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    assert(f != NULL);
    fprintf(f, "[black_list]\n");
    fprintf(f, "[invalid\n");
    fprintf(f, "^blocked\\.example$\n");
    fprintf(f, "[outbound_block_list]\n");
    fprintf(f, "[also-invalid\n");
    fprintf(f, "^outbound\\.example$\n");
    fclose(f);

    assert(init_acl(path) == 0);
    assert(acl_match_host("does-not-crash.example") == 0);
    assert(acl_match_host("blocked.example") == 1);
    assert(outbound_block_match_host("does-not-crash.example") == 0);
    assert(outbound_block_match_host("outbound.example") == 1);
    free_acl();

    remove(path);
}

static void
test_long_acl_line_is_discarded(void)
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    assert(f != NULL);
    fprintf(f, "[black_list]\n");
    for (int i = 0; i < 400; i++) {
        fputc('a', f);
    }
    fprintf(f, "\n");
    fprintf(f, "^kept\\.example$\n");
    fclose(f);

    assert(init_acl(path) == 0);
    assert(acl_match_host("kept.example") == 1);
    free_acl();

    remove(path);
}

static void
test_invalid_cidr_is_discarded(void)
{
    char path[4096];
    FILE *f = test_tempfile(path, sizeof(path));
    assert(f != NULL);
    fprintf(f, "[black_list]\n");
    fprintf(f, "1.2.3.0/999\n");
    fprintf(f, "2.2.2.2/-1\n");
    fprintf(f, "3.3.3.3/abc\n");
    fprintf(f, "4.4.4.0/24\n");
    fprintf(f, "^path/with/slash\\.example$\n");
    fclose(f);

    assert(init_acl(path) == 0);
    assert(acl_match_host("1.2.3.1") == 0);
    assert(acl_match_host("2.2.2.2") == 0);
    assert(acl_match_host("3.3.3.3") == 0);
    assert(acl_match_host("4.4.4.8") == 1);
    assert(acl_match_host("path/with/slash.example") == 1);
    free_acl();

    remove(path);
}

int
main(void)
{
    test_invalid_regex_is_not_installed();
    test_long_acl_line_is_discarded();
    test_invalid_cidr_is_discarded();
    return 0;
}
