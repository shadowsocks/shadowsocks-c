/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * alloc_counter: a preloadable shim that counts heap allocations.
 *
 * Load it into a program with LD_PRELOAD (glibc) or DYLD_INSERT_LIBRARIES
 * (macOS). Every SIGUSR2 appends one line with the running totals to the
 * file named by SS_ALLOC_AUDIT_OUT:
 *
 *     <pid> <allocations> <frees> <bytes>
 *
 * A driver takes a snapshot after warming a proxy up and another after more
 * traffic; the difference is what the steady-state data path allocates.
 * tests/alloc_audit/measure_alloc.py is that driver.
 *
 * The signal handler only uses async-signal-safe calls (open, write, close).
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint64_t allocations;
static uint64_t frees;
static uint64_t bytes;
static const char *out_path;

static void
count_alloc(size_t size)
{
    __atomic_add_fetch(&allocations, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&bytes, (uint64_t)size, __ATOMIC_RELAXED);
}

static void
count_free(void *ptr)
{
    if (ptr != NULL) {
        __atomic_add_fetch(&frees, 1, __ATOMIC_RELAXED);
    }
}

static char *
format_u64(char *end, uint64_t value)
{
    do {
        *--end = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    return end;
}

static void
snapshot(int signo)
{
    (void)signo;
    int saved_errno = errno;
    if (out_path != NULL) {
        uint64_t fields[4] = {
            (uint64_t)getpid(),
            __atomic_load_n(&allocations, __ATOMIC_RELAXED),
            __atomic_load_n(&frees, __ATOMIC_RELAXED),
            __atomic_load_n(&bytes, __ATOMIC_RELAXED),
        };
        char line[128];
        char *end = line + sizeof(line);
        char *p   = end;
        *--p = '\n';
        for (int i = 3; i >= 0; i--) {
            p = format_u64(p, fields[i]);
            if (i != 0) {
                *--p = ' ';
            }
        }
        int fd = open(out_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) {
            ssize_t ignored = write(fd, p, (size_t)(end - p));
            (void)ignored;
            close(fd);
        }
    }
    errno = saved_errno;
}

__attribute__((constructor)) static void
install(void)
{
    out_path = getenv("SS_ALLOC_AUDIT_OUT");
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = snapshot;
    action.sa_flags   = SA_RESTART;
    sigemptyset(&action.sa_mask);
    sigaction(SIGUSR2, &action, NULL);
}

#if defined(__APPLE__)

#include <malloc/malloc.h>

static void *
audit_malloc(size_t size)
{
    count_alloc(size);
    return malloc(size);
}

static void *
audit_calloc(size_t count, size_t size)
{
    count_alloc(count * size);
    return calloc(count, size);
}

static void *
audit_realloc(void *ptr, size_t size)
{
    count_alloc(size);
    return realloc(ptr, size);
}

static int
audit_posix_memalign(void **out, size_t align, size_t size)
{
    count_alloc(size);
    return posix_memalign(out, align, size);
}

static void
audit_free(void *ptr)
{
    count_free(ptr);
    free(ptr);
}

#define SS_INTERPOSE(replacement, original)                                   \
    __attribute__((used)) static const struct {                               \
        const void *replacement_fn;                                           \
        const void *original_fn;                                              \
    } interpose_##original __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)(uintptr_t)&replacement, (const void *)(uintptr_t)&original }

SS_INTERPOSE(audit_malloc, malloc);
SS_INTERPOSE(audit_calloc, calloc);
SS_INTERPOSE(audit_realloc, realloc);
SS_INTERPOSE(audit_posix_memalign, posix_memalign);
SS_INTERPOSE(audit_free, free);

#elif defined(__GLIBC__)

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
extern void *__libc_memalign(size_t, size_t);
extern void __libc_free(void *);

void *
malloc(size_t size)
{
    count_alloc(size);
    return __libc_malloc(size);
}

void *
calloc(size_t count, size_t size)
{
    count_alloc(count * size);
    return __libc_calloc(count, size);
}

void *
realloc(void *ptr, size_t size)
{
    count_alloc(size);
    return __libc_realloc(ptr, size);
}

void *
memalign(size_t align, size_t size)
{
    count_alloc(size);
    return __libc_memalign(align, size);
}

void *
aligned_alloc(size_t align, size_t size)
{
    return memalign(align, size);
}

int
posix_memalign(void **out, size_t align, size_t size)
{
    void *p = memalign(align, size);
    if (p == NULL) {
        return ENOMEM;
    }
    *out = p;
    return 0;
}

void
free(void *ptr)
{
    count_free(ptr);
    __libc_free(ptr);
}

#else
#error "alloc_counter supports glibc and macOS only"
#endif
