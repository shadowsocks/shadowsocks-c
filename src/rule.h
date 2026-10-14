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
#ifndef RULE_H
#define RULE_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "core.h"
#include "core/intrusive_list.hpp"

#if SS_ENABLE_REGEX
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

/* A domain rule, linked into one of the ACL's rule lists. Rules are built
 * while the ACL loads and are immutable afterwards. Destroying a rule
 * unlinks it. */
typedef struct rule : ss::ListNode<> {
    char *pattern = nullptr;

    /* 0: regex, 1: full domain, 2: domain suffix (including the apex). */
    unsigned kind       = 0;
    const char *literal = nullptr;
#if SS_ENABLE_REGEX
    /* Runtime fields */
    pcre2_code *pattern_re         = nullptr;
    pcre2_match_data *match_data   = nullptr;
#endif
} rule_t;

using rule_list_t = ss::IntrusiveList<rule_t>;

void add_rule(rule_list_t *, rule_t *);
int init_rule(rule_t *);
rule_t *lookup_rule(rule_list_t *, const char *, size_t);
void free_rule(rule_t *);
void remove_rule(rule_t *);
rule_t *new_rule();
int accept_rule_arg(rule_t *, const char *);

#endif
