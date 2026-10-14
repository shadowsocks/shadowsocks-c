/* SPDX-License-Identifier: GPL-3.0-or-later */
// Domain rules (src/rule.cpp): parsing, compilation and lookup on an
// intrusive rule list.
#include <cstring>

#include "rule.h"
#include "test_helpers.hpp"
#include "utils.h"

extern "C" {
int verbose = 0;
}

namespace {

void test_new_rule()
{
    rule_t *rule = new_rule();
    SS_CHECK(rule != nullptr && rule->pattern == nullptr && !rule->linked());
#if SS_ENABLE_REGEX
    SS_CHECK(rule->pattern_re == nullptr);
#endif
    free_rule(rule);
}

void test_accept_rule_arg()
{
    rule_t *rule = new_rule();
    SS_CHECK(accept_rule_arg(rule, "^example\\.com$") == 1);
    SS_CHECK(rule->pattern != nullptr && std::strcmp(rule->pattern, "^example\\.com$") == 0);
    // The pattern is already set.
    SS_CHECK(accept_rule_arg(rule, "another") == -1);
    free_rule(rule);
}

void test_literal_rules()
{
    rule_list_t rules;
    rule_t *full = new_rule();
    SS_CHECK(accept_rule_arg(full, "full:Example.com") == 1 && init_rule(full) == 1);
    add_rule(&rules, full);
    rule_t *suffix = new_rule();
    SS_CHECK(accept_rule_arg(suffix, "suffix:test.org") == 1 && init_rule(suffix) == 1);
    add_rule(&rules, suffix);

    SS_CHECK(lookup_rule(&rules, "example.com", 11) == full); // case-insensitive
    SS_CHECK(lookup_rule(&rules, "a.example.com", 13) == nullptr);
    SS_CHECK(lookup_rule(&rules, "test.org", 8) == suffix); // the apex
    SS_CHECK(lookup_rule(&rules, "x.test.org", 10) == suffix);
    SS_CHECK(lookup_rule(&rules, "xtest.org", 9) == nullptr);
    SS_CHECK(lookup_rule(&rules, nullptr, 0) == nullptr);

    rule_t *empty = new_rule();
    SS_CHECK(accept_rule_arg(empty, "full:") == 1 && init_rule(empty) == 0);
    free_rule(empty);

    remove_rule(full);
    SS_CHECK(lookup_rule(&rules, "example.com", 11) == nullptr && rules.size() == 1);
    remove_rule(suffix);
    SS_CHECK(rules.empty());
}

#if SS_ENABLE_REGEX
void test_regex_rules()
{
    rule_t *bad = new_rule();
    SS_CHECK(accept_rule_arg(bad, "[invalid") == 1 && init_rule(bad) == 0);
    free_rule(bad);

    rule_list_t rules;
    rule_t *rule1 = new_rule();
    SS_CHECK(accept_rule_arg(rule1, "^google\\.com$") == 1 && init_rule(rule1) == 1);
    SS_CHECK(rule1->pattern_re != nullptr);
    add_rule(&rules, rule1);
    rule_t *rule2 = new_rule();
    SS_CHECK(accept_rule_arg(rule2, ".*\\.example\\.com$") == 1 && init_rule(rule2) == 1);
    add_rule(&rules, rule2);

    SS_CHECK(lookup_rule(&rules, "google.com", 10) == rule1);
    SS_CHECK(lookup_rule(&rules, "sub.example.com", 15) == rule2);
    SS_CHECK(lookup_rule(&rules, "other.net", 9) == nullptr);

    // Freeing a linked rule unlinks it.
    free_rule(rule1);
    free_rule(rule2);
    SS_CHECK(rules.empty());
}
#endif

} // namespace

int main()
{
    SS_RUN(test_new_rule);
    SS_RUN(test_accept_rule_arg);
    SS_RUN(test_literal_rules);
#if SS_ENABLE_REGEX
    SS_RUN(test_regex_rules);
#endif
    return 0;
}
