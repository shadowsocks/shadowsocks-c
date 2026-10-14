// SPDX-License-Identifier: GPL-3.0-or-later
// Intrusive reference counting (tests/reference/ss_ref.h): assignment,
// move and release helpers used by the legacy relay code.
#include <cstdlib>

#include "ss_ref.h"
#include "test_helpers.hpp"

namespace {

struct test_object_t {
    ss_ref_t ref;
    int *destroyed;
};

void destroy_object(void *object)
{
    auto *value = static_cast<test_object_t *>(object);
    ++*value->destroyed;
    std::free(value);
}

void *new_object(int *destroyed)
{
    auto *value = static_cast<test_object_t *>(std::malloc(sizeof(test_object_t)));
    SS_CHECK(value != nullptr);
    ss_ref_init(value, destroy_object);
    value->destroyed = destroyed;
    return value;
}

void test_ref_lifecycle()
{
    int destroyed = 0;
    void *table   = new_object(&destroyed);
    void *relay   = nullptr;
    ss_ref_assign(&relay, table);
    ss_ref_assign(&relay, relay);         // Self-assignment must preserve ownership.
    ss_ptr_reset(&table, ss_ref_release); // Simulate eviction.
    SS_CHECK(table == nullptr && destroyed == 0);
    ss_ptr_reset(&relay, ss_ref_release);
    SS_CHECK(relay == nullptr && destroyed == 1);
    ss_ptr_reset(&relay, ss_ref_release); // Repeated cleanup is harmless.
    SS_CHECK(destroyed == 1);

    void *query = new_object(&destroyed);
    relay       = new_object(&destroyed);
    ss_ptr_move(&relay, &query, ss_ref_release);
    SS_CHECK(query == nullptr && relay != nullptr && destroyed == 2);
    ss_ptr_move(&relay, &relay, ss_ref_release); // Self-move.
    SS_CHECK(relay != nullptr && destroyed == 2);
    ss_ref_assign(&query, relay);
    ss_ptr_move(&relay, &query, ss_ref_release); // Two owners, same object.
    SS_CHECK(query == nullptr && relay != nullptr && destroyed == 2);
    ss_ref_assign(&relay, nullptr);
    SS_CHECK(relay == nullptr && destroyed == 3);

    relay = new_object(&destroyed);
    ss_ptr_move(&relay, &query, ss_ref_release); // Move an empty source.
    SS_CHECK(relay == nullptr && query == nullptr && destroyed == 4);
    SS_CHECK(ss_ref_retain(nullptr) == nullptr);
    ss_ref_release(nullptr);
    ss_ptr_reset(&relay, nullptr); // Legacy crypto has no session/callback.
}

} // namespace

int main()
{
    SS_RUN(test_ref_lifecycle);
    return 0;
}
