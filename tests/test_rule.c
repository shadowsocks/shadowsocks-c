#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <string.h>
#include <stdlib.h>

int verbose = 0;

#include "rule.h"
#include "utils.h"

static void
test_new_rule(void)
{
    rule_t *rule = new_rule();
    assert(rule != NULL);
    assert(rule->pattern == NULL);
    assert(rule->pattern_re == NULL);
    free(rule);
}

static void
test_accept_rule_arg(void)
{
    rule_t *rule = new_rule();
    assert(rule != NULL);

    int ret = accept_rule_arg(rule, "^example\\.com$");
    assert(ret == 1);
    assert(rule->pattern != NULL);
    assert(strcmp(rule->pattern, "^example\\.com$") == 0);

    /* Second call should fail - pattern already set */
    ret = accept_rule_arg(rule, "another");
    assert(ret == -1);
    (void)ret;

    free_rule(rule);
}

static void
test_init_rule(void)
{
    rule_t *rule = new_rule();
    accept_rule_arg(rule, "^test.*$");

    int ret = init_rule(rule);
    assert(ret == 1);
    (void)ret;
    assert(rule->pattern_re != NULL);

    free_rule(rule);
}

static void
test_init_rule_invalid(void)
{
    rule_t *rule = new_rule();
    accept_rule_arg(rule, "[invalid");  /* Unclosed bracket */

    int ret = init_rule(rule);
    assert(ret == 0);  /* Should fail */
    (void)ret;

    free_rule(rule);
}

static void
test_lookup_rule(void)
{
    struct ss_list rules;
    ss_list_init(&rules);

    rule_t *rule1 = new_rule();
    accept_rule_arg(rule1, "^google\\.com$");
    init_rule(rule1);
    add_rule(&rules, rule1);

    rule_t *rule2 = new_rule();
    accept_rule_arg(rule2, ".*\\.example\\.com$");
    init_rule(rule2);
    add_rule(&rules, rule2);

    /* Should match rule1 */
    rule_t *found = lookup_rule(&rules, "google.com", 10);
    assert(found == rule1);

    /* Should match rule2 */
    found = lookup_rule(&rules, "sub.example.com", 15);
    assert(found == rule2);

    /* Should not match */
    found = lookup_rule(&rules, "other.net", 9);
    assert(found == NULL);
    (void)found;

    /* Clean up */
    free_rule(rule1);
    free_rule(rule2);
}

int
main(void)
{
    test_new_rule();
    test_accept_rule_arg();
    test_init_rule();
    test_init_rule_invalid();
    test_lookup_rule();
    return 0;
}
