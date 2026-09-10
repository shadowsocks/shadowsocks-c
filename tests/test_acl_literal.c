#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "acl.h"
#include "rule.h"
int verbose = 0;

int
main(int argc, char **argv)
{
    (void)argc;
    char path[4096];
    assert(snprintf(path, sizeof(path), "%s.acl", argv[0]) < (int)sizeof(path));
    FILE *file = fopen(path, "w");
    assert(file != NULL);
    fputs("[black_list]\nfull:Exact.example\nsuffix:blocked.example\n10.0.0.0/8\n"
          "2001:db8::/32\n[white_list]\nsuffix:allowed.example\n"
          "[outbound_block_list]\nfull:outbound.example\n", file);
    fclose(file);
    assert(init_acl(path) == 0);
    assert(acl_match_host("EXACT.example") == 1);
    assert(acl_match_host("sub.exact.example") == 0);
    assert(acl_match_host("blocked.example") == 1);
    assert(acl_match_host("a.blocked.example") == 1);
    assert(acl_match_host("notblocked.example") == 0);
    assert(acl_match_host("blocked.example.evil") == 0);
    assert(acl_match_host("a.allowed.example") == -1);
    assert(outbound_block_match_host("outbound.example") == 1);
    assert(outbound_block_match_host("a.outbound.example") == 0);
    assert(acl_match_host("10.42.1.2") == 1);
    assert(acl_remove_ip("10.42.1.2") == 0);
    assert(acl_match_host("10.42.1.2") == 0);
    assert(acl_match_host("10.42.1.3") == 1);
    assert(acl_add_ip("10.42.1.2") == 0);
    assert(acl_match_host("10.42.1.2") == 1);
    assert(acl_remove_ip("2001:db8::42") == 0);
    assert(acl_match_host("2001:db8::42") == 0);
    assert(acl_match_host("2001:db8::43") == 1);
    free_acl();
#if !SS_ENABLE_REGEX
    file = fopen(path, "w");
    assert(file != NULL);
    fputs("[black_list]\n10.0.0.0/8\n^old\\.regex$\n", file);
    fclose(file);
    assert(init_acl(path) == -1);
    assert(acl_match_host("10.1.1.1") == 0);
#endif
    remove(path);
    return 0;
}
