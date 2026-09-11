#include "ss_event.h"
#include <uv.h>
#include "uthash.h"
#include <assert.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

struct poll_state {
    uv_poll_t handle;
    struct ss_loop *loop;
    ss_io *watchers;
    int fd, events;
    UT_hash_handle hh;
};
struct timer_state {
    uv_timer_t handle;
    struct ss_loop *loop;
    ss_timer *watcher;
};
struct signal_state {
    uv_signal_t handle;
    struct ss_loop *loop;
    ss_signal *watcher;
};
struct ss_loop {
    uv_loop_t native;
    struct poll_state *polls;
    uint64_t generation;
};
static struct ss_loop *default_loop;
static void checked(int status)
{
    if (status < 0) {
        fprintf(stderr, "event loop: %s\n", uv_strerror(status));
        abort();
    }
}
static void *allocate(size_t size)
{
    void *p = calloc(1, size);
    if (!p) abort();
    return p;
}
static void closed(uv_handle_t *handle) { free(handle); }
uv_loop_t *ss_native_loop(struct ss_loop *loop) { return &loop->native; }
const char *ss_backend_name(void)
{
#ifdef _WIN32
    return "iocp";
#elif defined(__APPLE__) || defined(__FreeBSD__)
    return "kqueue";
#elif defined(__linux__)
    return "epoll";
#else
    return "libuv";
#endif
}
struct ss_loop *ss_loop_new(unsigned flags)
{
    (void)flags;
    struct ss_loop *loop = allocate(sizeof(*loop));
    if (uv_loop_init(&loop->native)) { free(loop); return NULL; }
    return loop;
}
struct ss_loop *ss_default_loop(void)
{
    if (!default_loop) {
        default_loop = ss_loop_new(0);
        if (!default_loop) abort();
    }
    return default_loop;
}
static void close_walk(uv_handle_t *handle, void *arg)
{
    (void)arg;
    if (!uv_is_closing(handle)) uv_close(handle, closed);
}
void ss_loop_destroy(struct ss_loop *loop)
{
    HASH_CLEAR(hh, loop->polls);
    uv_walk(&loop->native, close_walk, NULL);
    uv_run(&loop->native, UV_RUN_DEFAULT);
    checked(uv_loop_close(&loop->native));
    if (loop == default_loop) default_loop = NULL;
    free(loop);
}
int ss_run(struct ss_loop *loop, int flags)
{
    return uv_run(&loop->native, flags & SS_RUN_NOWAIT ? UV_RUN_NOWAIT : UV_RUN_DEFAULT);
}
void ss_unloop(struct ss_loop *loop, int how)
{
    (void)how;
    uv_stop(&loop->native);
}
double ss_now(struct ss_loop *loop) { return uv_now(&loop->native) / 1000.0; }
double ss_time(void)
{
    uv_timeval64_t now;
    checked(uv_gettimeofday(&now));
    return (double)now.tv_sec + now.tv_usec / 1000000.0;
}
struct pending { ss_io *watcher; uint64_t generation; };
static void polled(uv_poll_t *handle, int status, int events)
{
    struct poll_state *state = (struct poll_state *)handle;
    int ready = (events & UV_READABLE ? SS_READ : 0) |
                (events & UV_WRITABLE ? SS_WRITE : 0);
    if (status < 0) ready = SS_READ | SS_WRITE | SS_ERROR;
    size_t count = 0;
    for (ss_io *w = state->watchers; w; w = w->next) count++;
    struct pending local[8];
    struct pending *pending = count > 8 ? allocate(count * sizeof(*pending)) : local;
    size_t n = 0;
    for (ss_io *w = state->watchers; w; w = w->next)
        pending[n++] = (struct pending){w, w->generation};
    /* A callback can stop/free itself or another watcher, or reuse its memory.
     * Revalidate both membership and generation before dereferencing it. */
    for (size_t i = 0; i < count; i++) {
        for (ss_io *w = state->watchers; w; w = w->next) {
            if (w == pending[i].watcher && w->generation == pending[i].generation) {
                int deliver = ready & (w->events | SS_ERROR);
                if (deliver) w->cb(state->loop, w, deliver);
                break;
            }
        }
    }
    if (pending != local) free(pending);
}
static void update_poll(struct poll_state *state)
{
    int events = 0;
    for (ss_io *w = state->watchers; w; w = w->next) events |= w->events;
    if (events == state->events) return;
    state->events = events;
    checked(uv_poll_start(&state->handle,
        (events & SS_READ ? UV_READABLE : 0) | (events & SS_WRITE ? UV_WRITABLE : 0), polled));
}
void ss_io_init(ss_io *w, void (*cb)(struct ss_loop *, ss_io *, int), int fd, int events)
{
    *w = (ss_io){.fd = fd, .events = events, .cb = cb};
}
void ss_io_set(ss_io *w, int fd, int events)
{
    assert(!w->backend);
    w->fd = fd; w->events = events;
}
void ss_io_start(struct ss_loop *loop, ss_io *w)
{
    if (w->backend) return;
    struct poll_state *state;
    HASH_FIND_INT(loop->polls, &w->fd, state);
    if (!state) {
        state = allocate(sizeof(*state));
        state->fd = w->fd; state->loop = loop;
#ifdef _WIN32
        checked(uv_poll_init_socket(&loop->native, &state->handle, (SOCKET)(unsigned int)w->fd));
#else
        checked(uv_poll_init(&loop->native, &state->handle, w->fd));
#endif
        // NOLINTNEXTLINE(clang-analyzer-core.DivideZero): uthash expands a nonempty table, so ceil(num_items / num_buckets) is positive.
        HASH_ADD_INT(loop->polls, fd, state);
    }
    w->backend = state;
    w->generation = ++loop->generation;
    w->next = state->watchers;
    state->watchers = w;
    update_poll(state);
}
void ss_io_stop(struct ss_loop *loop, ss_io *w)
{
    struct poll_state *state = w->backend;
    if (!state) return;
    assert(state->loop == loop);
    ss_io **item = &state->watchers;
    while (*item != w) item = &(*item)->next;
    *item = w->next;
    w->backend = NULL; w->next = NULL;
    if (!state->watchers) {
        checked(uv_poll_stop(&state->handle));
        HASH_DEL(loop->polls, state);
        uv_close((uv_handle_t *)&state->handle, closed);
    } else update_poll(state);
}
static uint64_t milliseconds(double seconds)
{
    return seconds > 0 ? (uint64_t)ceil(seconds * 1000.0) : 0;
}
static void timed(uv_timer_t *handle)
{
    struct timer_state *state = (struct timer_state *)handle;
    ss_timer *w = state->watcher;
    struct ss_loop *loop = state->loop;
    if (!w->repeat) ss_timer_stop(loop, w);
    w->cb(loop, w, SS_TIMER);
}
void ss_timer_init(ss_timer *w, void (*cb)(struct ss_loop *, ss_timer *, int), double after, double repeat)
{
    *w = (ss_timer){.after = after, .repeat = repeat, .cb = cb};
}
void ss_timer_set(ss_timer *w, double after, double repeat)
{
    w->after = after; w->repeat = repeat;
}
void ss_timer_start(struct ss_loop *loop, ss_timer *w)
{
    if (w->backend) return;
    struct timer_state *state = allocate(sizeof(*state));
    state->loop = loop; state->watcher = w;
    checked(uv_timer_init(&loop->native, &state->handle));
    w->backend = state;
    uv_update_time(&loop->native);
    checked(uv_timer_start(&state->handle, timed, milliseconds(w->after), milliseconds(w->repeat)));
}
void ss_timer_stop(struct ss_loop *loop, ss_timer *w)
{
    (void)loop;
    struct timer_state *state = w->backend;
    if (!state) return;
    w->backend = NULL;
    checked(uv_timer_stop(&state->handle));
    uv_close((uv_handle_t *)&state->handle, closed);
}
void ss_timer_again(struct ss_loop *loop, ss_timer *w)
{
    ss_timer_stop(loop, w);
    if (w->repeat > 0) {
        w->after = w->repeat;
        ss_timer_start(loop, w);
    }
}
static void signaled(uv_signal_t *handle, int signum)
{
    (void)signum;
    struct signal_state *state = (struct signal_state *)handle;
    ss_signal *w = state->watcher;
    w->cb(state->loop, w, SS_SIGNAL);
}
void ss_signal_init(ss_signal *w, void (*cb)(struct ss_loop *, ss_signal *, int), int signum)
{
    *w = (ss_signal){.signum = signum, .cb = cb};
}
void ss_signal_start(struct ss_loop *loop, ss_signal *w)
{
    if (w->backend) return;
#ifdef _WIN32
    /* Windows has no SIGTERM delivery; process termination is an OS operation. */
    if (w->signum == SIGTERM) return;
#endif
    struct signal_state *state = allocate(sizeof(*state));
    state->loop = loop; state->watcher = w;
    checked(uv_signal_init(&loop->native, &state->handle));
    checked(uv_signal_start(&state->handle, signaled, w->signum));
    w->backend = state;
}
void ss_signal_stop(struct ss_loop *loop, ss_signal *w)
{
    (void)loop;
    struct signal_state *state = w->backend;
    if (!state) return;
    w->backend = NULL;
    checked(uv_signal_stop(&state->handle));
    uv_close((uv_handle_t *)&state->handle, closed);
}
