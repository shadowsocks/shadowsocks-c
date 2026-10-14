#include <assert.h>
#include <stdlib.h>

#include "ss_ref.h"

typedef struct {
    ss_ref_t ref;
    int *destroyed;
} test_object_t;

static void
destroy_object(void *object)
{
    test_object_t *value = object;
    ++*value->destroyed;
    free(value);
}

static void *
new_object(int *destroyed)
{
    test_object_t *value = malloc(sizeof(*value));
    assert(value != NULL);
    ss_ref_init(value, destroy_object);
    value->destroyed = destroyed;
    return value;
}

int
main(void)
{
    int destroyed = 0;
    void *table = new_object(&destroyed);
    void *relay = NULL;
    ss_ref_assign(&relay, table);
    ss_ref_assign(&relay, relay); /* Self-assignment must preserve ownership. */
    ss_ptr_reset(&table, ss_ref_release); /* Simulate eviction. */
    assert(table == NULL && destroyed == 0);
    ss_ptr_reset(&relay, ss_ref_release);
    assert(relay == NULL && destroyed == 1);
    ss_ptr_reset(&relay, ss_ref_release); /* Repeated cleanup is harmless. */
    assert(destroyed == 1);

    void *query = new_object(&destroyed);
    relay = new_object(&destroyed);
    ss_ptr_move(&relay, &query, ss_ref_release);
    assert(query == NULL && relay != NULL && destroyed == 2);
    ss_ptr_move(&relay, &relay, ss_ref_release); /* Self-move. */
    assert(relay != NULL && destroyed == 2);
    ss_ref_assign(&query, relay);
    ss_ptr_move(&relay, &query, ss_ref_release); /* Two owners, same object. */
    assert(query == NULL && relay != NULL && destroyed == 2);
    ss_ref_assign(&relay, NULL);
    assert(relay == NULL && destroyed == 3);

    relay = new_object(&destroyed);
    ss_ptr_move(&relay, &query, ss_ref_release); /* Move an empty source. */
    assert(relay == NULL && query == NULL && destroyed == 4);
    assert(ss_ref_retain(NULL) == NULL);
    ss_ref_release(NULL);
    ss_ptr_reset(&relay, NULL); /* Legacy crypto has no session/callback. */
    return 0;
}
