/* Project event API backed by bundled/system libuv. Watchers may be freed
 * immediately after stop; libuv handle storage has a separate lifetime. */
#ifndef SS_EVENT_H
#define SS_EVENT_H
#include <stdint.h>
/* Keep platform headers private: Linux TCP headers differ from libc headers. */
struct uv_loop_s;
struct ss_loop;
typedef double ss_tstamp;
#define SS_READ 1
#define SS_WRITE 2
#define SS_TIMER 4
#define SS_SIGNAL 8
#define SS_ERROR 16
#define SS_RUN_NOWAIT 1
#define SS_UNLOOP_ALL 2
#define SS_P_ struct ss_loop *loop,
#define SS_A_ loop,
#define SS_DEFAULT ss_default_loop()
typedef struct ss_io {
    void *backend;
    struct ss_io *next;
    uint64_t generation;
    int fd, events;
    void (*cb)(struct ss_loop *, struct ss_io *, int);
} ss_io;
typedef struct ss_timer {
    void *backend;
    double after, repeat;
    void (*cb)(struct ss_loop *, struct ss_timer *, int);
} ss_timer;
typedef struct ss_signal {
    void *backend;
    int signum;
    void (*cb)(struct ss_loop *, struct ss_signal *, int);
} ss_signal;
struct ss_loop *ss_default_loop(void);
struct ss_loop *ss_loop_new(unsigned flags);
void ss_loop_destroy(struct ss_loop *loop);
struct uv_loop_s *ss_native_loop(struct ss_loop *loop);
const char *ss_backend_name(void);
int ss_run(struct ss_loop *loop, int flags);
void ss_unloop(struct ss_loop *loop, int how);
double ss_now(struct ss_loop *loop);
double ss_time(void);
void ss_io_init(ss_io *, void (*)(struct ss_loop *, ss_io *, int), int, int);
void ss_io_set(ss_io *, int, int);
void ss_io_start(struct ss_loop *, ss_io *);
void ss_io_stop(struct ss_loop *, ss_io *);
void ss_timer_init(ss_timer *, void (*)(struct ss_loop *, ss_timer *, int), double, double);
void ss_timer_set(ss_timer *, double, double);
void ss_timer_start(struct ss_loop *, ss_timer *);
void ss_timer_stop(struct ss_loop *, ss_timer *);
void ss_timer_again(struct ss_loop *, ss_timer *);
void ss_signal_init(ss_signal *, void (*)(struct ss_loop *, ss_signal *, int), int);
void ss_signal_start(struct ss_loop *, ss_signal *);
void ss_signal_stop(struct ss_loop *, ss_signal *);
#endif
