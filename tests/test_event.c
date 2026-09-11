#include "test_helpers.h"
#include <string.h>
#include "ss_event.h"
#include <uv.h>
#ifdef __APPLE__
#include <sys/event.h>
#endif
int verbose = 0;
struct receiver { ss_io io; int count; };
static void receive(struct ss_loop *loop, ss_io *io, int events)
{
    struct receiver *r = (struct receiver *)io;
    char byte;
    assert(events & SS_READ);
    assert(recv(io->fd, &byte, 1, 0) == 1 && byte == 'x');
    r->count++;
    ss_io_stop(loop, io);
}
struct shared { ss_io io; ss_io *other; int *calls; };
static void destroy_peer(struct ss_loop *loop, ss_io *io, int events)
{
    (void)events;
    struct shared *s = (struct shared *)io;
    (*s->calls)++;
    ss_io_stop(loop, s->other);
    free(s->other);
    ss_io_stop(loop, io);
    free(s);
}
static void must_not_run(struct ss_loop *loop, ss_io *io, int events)
{
    (void)loop; (void)io; (void)events;
    assert(!"stopped watcher was invoked");
}
int main(void)
{
    test_network_init();
    struct ss_loop *loop = ss_loop_new(0);
    assert(loop);
#ifdef _WIN32
    assert(strcmp(ss_backend_name(), "iocp") == 0);
    assert(ss_native_loop(loop)->iocp != NULL);
#elif defined(__APPLE__)
    assert(strcmp(ss_backend_name(), "kqueue") == 0);
    struct timespec zero = {0};
    assert(kevent(uv_backend_fd(ss_native_loop(loop)), NULL, 0, NULL, 0, &zero) == 0);
#endif
    /* Exceed Winsock select's default 64 descriptors. */
    struct receiver receivers[256] = {0};
    ss_socket_t sender = socket(AF_INET, SOCK_DGRAM, 0);
    for (unsigned i = 0; i < 256; i++) {
        int fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
        socklen_t length = sizeof(address);
        assert(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
        ss_io_init(&receivers[i].io, receive, fd, SS_READ);
        ss_io_start(loop, &receivers[i].io);
        assert(sendto(sender, "x", 1, 0, (struct sockaddr *)&address, length) == 1);
    }
    ss_run(loop, 0);
    for (unsigned i = 0; i < 256; i++) {
        assert(receivers[i].count == 1);
        ss_socket_close(receivers[i].io.fd);
    }
    /* Both directions share one poll handle; freeing a pending peer is safe. */
    int calls = 0;
    ss_io *other = calloc(1, sizeof(*other));
    struct shared *owner = calloc(1, sizeof(*owner));
    assert(other && owner);
    ss_io_init(other, must_not_run, (int)sender, SS_WRITE);
    ss_io_init(&owner->io, destroy_peer, (int)sender, SS_WRITE);
    owner->other = other; owner->calls = &calls;
    ss_io_start(loop, other);
    ss_io_start(loop, &owner->io);
    ss_run(loop, 0);
    assert(calls == 1);
    ss_socket_close(sender);
    assert(ss_run(loop, SS_RUN_NOWAIT) == 0);
    ss_loop_destroy(loop);
    return 0;
}
