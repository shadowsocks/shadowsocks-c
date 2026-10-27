/*
 * Copyright (c) 2011 and 2012, Dustin Lundquist <dustin@null-ptr.net>
 * Copyright (c) 2011 Manuel Kasper <mk@neon1.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <new>

#include "rule.h"
#include "utils.h"

rule_t *
new_rule()
{
    void *mem = malloc(sizeof(rule_t)); // heap-ok: ACL rules are built at startup
    if (mem == NULL) {
        ERROR("malloc");
        return NULL;
    }

    return ::new (mem) rule_t();
}

int
accept_rule_arg(rule_t *rule, const char *arg)
{
    if (rule->pattern == NULL) {
        rule->pattern = strdup(arg);
        if (rule->pattern == NULL) {
            ERROR("strdup failed");
            return -1;
        }
    } else {
        LOGE("Unexpected table rule argument: %s", arg);
        return -1;
    }

    return 1;
}

void
add_rule(rule_list_t *rules, rule_t *rule)
{
    rules->push_back(*rule);
}

#if SS_ENABLE_REGEX
static pcre2_match_context *match_context = NULL;
#endif

int
init_rule(rule_t *rule)
{
    if (strncmp(rule->pattern, "full:", 5) == 0) {
        rule->kind = 1;
        rule->literal = rule->pattern + 5;
    } else if (strncmp(rule->pattern, "suffix:", 7) == 0) {
        rule->kind = 2;
        rule->literal = rule->pattern + 7;
    }
    if (rule->kind != 0) {
        return *rule->literal != '\0' ? 1 : 0;
    }
#if SS_ENABLE_REGEX
    // Bounds the backtracking a rule can do on a client-chosen host name;
    // made here, at startup, not on a first match.
    if (match_context == NULL) {
        match_context = pcre2_match_context_create(NULL);
        if (match_context == NULL) {
            return -1;
        }
        pcre2_set_match_limit(match_context, 100000);
        pcre2_set_depth_limit(match_context, 1000);
    }
    if (rule->pattern_re == NULL) {
        int errcode;
        PCRE2_SIZE erroffset;
        // Host names are case-insensitive.
        rule->pattern_re = pcre2_compile((PCRE2_SPTR)rule->pattern,
            PCRE2_ZERO_TERMINATED, PCRE2_CASELESS, &errcode, &erroffset, NULL);
        if (rule->pattern_re == NULL) {
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
            LOGE("Regex compilation of \"%s\" failed: %s, offset %d",
                 rule->pattern, errbuf, (int)erroffset);
            return 0;
        }
        rule->match_data = pcre2_match_data_create_from_pattern(rule->pattern_re, NULL);
        if (rule->match_data == NULL) {
            pcre2_code_free(rule->pattern_re);
            rule->pattern_re = NULL;
            return 0;
        }
    }
    return 1;
#else
    LOGE("Regex ACL support is disabled; use full:domain or suffix:domain: %s", rule->pattern);
    return -1;
#endif
}

static bool
literal_equal(const char *a, const char *b, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'A' && x <= 'Z') x += 'a' - 'A';
        if (y >= 'A' && y <= 'Z') y += 'a' - 'A';
        if (x != y) return false;
    }
    return true;
}

static bool
rule_matches(rule_t *rule, const char *name, size_t name_len)
{
    if (rule->kind != 0) {
        size_t length = strlen(rule->literal);
        return name_len >= length &&
               (name_len == length || (rule->kind == 2 && name[name_len - length - 1] == '.')) &&
               literal_equal(name + name_len - length, rule->literal, length);
    }
#if SS_ENABLE_REGEX
    return pcre2_match(rule->pattern_re, (PCRE2_SPTR)name,
                       name_len, 0, 0, rule->match_data, match_context) >= 0;
#else
    return false;
#endif
}

rule_t *
lookup_rule(rule_list_t *rules, const char *name, size_t name_len)
{
    if (name == NULL) {
        name     = "";
        name_len = 0;
    }
    // "example.com." is the same name as "example.com".
    while (name_len > 0 && name[name_len - 1] == '.') {
        name_len--;
    }

    return rules->find_if([&](rule_t &rule) { return rule_matches(&rule, name, name_len); });
}

void
remove_rule(rule_t *rule)
{
    free_rule(rule); // the destructor unlinks it
}

void
free_rule(rule_t *rule)
{
    if (rule == NULL)
        return;

    ss_free(rule->pattern);
#if SS_ENABLE_REGEX
    if (rule->match_data != NULL)
        pcre2_match_data_free(rule->match_data);
    if (rule->pattern_re != NULL)
        pcre2_code_free(rule->pattern_re);
#endif
    rule->~rule_t();
    ss_free(rule);
}
