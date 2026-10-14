#ifndef SS_REF_H
#define SS_REF_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Intrusive shared ownership for a single event-loop thread. Embed this as
 * the FIRST member of an object, initialize once, and never copy the object.
 * Each owning slot/table entry holds one reference; raw aliases are borrowed.
 * The destructor frees the enclosing object. Cycles and cross-thread sharing
 * require a different ownership scheme. */
typedef struct ss_ref {
    size_t count;
    void (*destroy)(void *);
} ss_ref_t;

static inline void
ss_ref_init(void *object, void (*destroy)(void *))
{
    ss_ref_t *ref = (ss_ref_t *)object;
    ref->count = 1;
    ref->destroy = destroy;
}

static inline void *
ss_ref_retain(void *object)
{
    if (object != NULL) {
        ss_ref_t *ref = (ss_ref_t *)object;
        if (ref->count == 0 || ref->count == SIZE_MAX)
            abort();
        ref->count++;
    }
    return object;
}

static inline void
ss_ref_release(void *object)
{
    if (object != NULL) {
        ss_ref_t *ref = (ss_ref_t *)object;
        if (ref->count == 0)
            abort();
        if (--ref->count == 0)
            ref->destroy(object);
    }
}

/* Reset/move also support opaque objects with their own release callback.
 * Slots must be actual void * objects, not casts from typed pointer slots.
 * Move consumes the source reference and releases the previous destination. */
static inline void
ss_ptr_reset(void **slot, void (*release)(void *))
{
    void *old = *slot;
    *slot = NULL;
    if (old != NULL)
        release(old);
}

static inline void
ss_ptr_move(void **dst, void **src, void (*release)(void *))
{
    if (dst == src)
        return;
    void *old = *dst;
    *dst = *src;
    *src = NULL;
    if (old != NULL)
        release(old);
}

/* Copy a borrowed reference into an owning slot, retaining before release. */
static inline void
ss_ref_assign(void **slot, void *object)
{
    void *owned = ss_ref_retain(object);
    ss_ptr_move(slot, &owned, ss_ref_release);
}

#endif /* SS_REF_H */
