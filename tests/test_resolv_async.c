/* Local delayed DNS server proves A/AAAA/NXDOMAIN completion without blocking. */
#include "test_helpers.h"
#include <string.h>
#include "ss_event.h"
#include "resolv.h"
int verbose = 0;
struct packet {
    struct packet *next;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    unsigned char bytes[512];
    size_t length;
};
static struct packet *packets;
static ss_io dns_io;
static ss_timer reply_timer, ticker, deadline;
static unsigned ticks, completed;
static int family;
struct result { unsigned called, freed; int missing; };
static void reply(struct ss_loop *loop, ss_timer *timer, int events)
{
    (void)loop; (void)timer; (void)events;
    while (packets) {
        struct packet *p = packets;
        packets = p->next;
        assert(sendto(dns_io.fd, (const char *)p->bytes, (int)p->length, 0,
                      (struct sockaddr *)&p->peer, p->peer_len) == (int)p->length);
        free(p);
    }
}
static void question(struct ss_loop *loop, ss_io *io, int events)
{
    (void)events;
    struct packet *p = calloc(1, sizeof(*p));
    assert(p);
    p->peer_len = sizeof(p->peer);
    int count = (int)recvfrom(io->fd, (char *)p->bytes, sizeof(p->bytes), 0,
                              (struct sockaddr *)&p->peer, &p->peer_len);
    assert(count > 16 && p->bytes[4] == 0 && p->bytes[5] == 1);
    size_t end = 12;
    while (end < (size_t)count && p->bytes[end]) end += p->bytes[end] + 1;
    end += 5; /* terminating zero, QTYPE, QCLASS */
    assert(end <= (size_t)count && end + 28 <= sizeof(p->bytes));
    unsigned type = p->bytes[end - 3];
    int missing = p->bytes[13] == 'm';
    p->bytes[2] = 0x81; p->bytes[3] = missing ? 0x83 : 0x80;
    p->bytes[6] = 0; p->bytes[7] = missing ? 0 : 1;
    memset(p->bytes + 8, 0, 4);
    p->length = end;
    if (!missing) {
        unsigned char answer[] = {0xc0,0x0c,0,0,0,1,0,0,0,1,0,0};
        assert(type == 1 || type == 28);
        answer[3] = (unsigned char)type;
        answer[11] = type == 1 ? 4 : 16;
        memcpy(p->bytes + end, answer, sizeof(answer));
        p->length += sizeof(answer);
        memset(p->bytes + p->length, 0, 16);
        if (type == 1) { p->bytes[p->length] = 127; p->bytes[p->length+3] = 1; }
        else p->bytes[p->length+15] = 1;
        p->length += answer[11];
    }
    p->next = packets; packets = p;
    ss_timer_start(loop, &reply_timer);
}
static void tick(struct ss_loop *loop, ss_timer *timer, int events)
{
    (void)loop; (void)timer; (void)events; ticks++;
}
static void timed_out(struct ss_loop *loop, ss_timer *timer, int events)
{
    (void)loop; (void)timer; (void)events;
    assert(!"asynchronous DNS did not complete");
}
static struct ss_loop *test_loop;
static void resolved(struct sockaddr *address, void *data)
{
    struct result *r = data;
    assert(!r->called && !r->freed && ticks > 2);
    r->called++;
    if (r->missing) assert(address == NULL);
    else {
        assert(address && address->sa_family == family);
        if (family == AF_INET) assert(((struct sockaddr_in *)address)->sin_port == htons(443));
        else assert(((struct sockaddr_in6 *)address)->sin6_port == htons(443));
    }
    if (++completed == 33) ss_unloop(test_loop, SS_UNLOOP_ALL);
}
static void released(void *data)
{
    struct result *r = data;
    assert(r->called == 1 && !r->freed);
    r->freed++;
}
int main(void)
{
    test_network_init();
    test_loop = ss_loop_new(0);
    int fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(fd, (struct sockaddr *)&address, &length) == 0);
    char nameserver[64];
    snprintf(nameserver, sizeof(nameserver), "127.0.0.1:%u", ntohs(address.sin_port));
    ss_io_init(&dns_io, question, fd, SS_READ);
    ss_timer_init(&reply_timer, reply, .05, 0);
    ss_timer_init(&ticker, tick, .001, .001);
    ss_timer_init(&deadline, timed_out, 10, 0);
    for (int ipv6 = 0; ipv6 < 2; ipv6++) {
        struct result results[33] = {{0}};
        results[32].missing = 1;
        family = ipv6 ? AF_INET6 : AF_INET;
        ticks = completed = 0;
        assert(resolv_init(test_loop, nameserver, ipv6) == 0);
        ss_io_start(test_loop, &dns_io);
        ss_timer_start(test_loop, &ticker);
        ss_timer_start(test_loop, &deadline);
        for (unsigned i = 0; i < 33; i++) {
            char host[64];
            snprintf(host, sizeof(host), "%s-%u.invalid", i == 32 ? "missing" : "resolved", i);
            resolv_start(host, htons(443), resolved, released, &results[i]);
        }
        assert(completed == 0);
        ss_run(test_loop, 0);
        assert(completed == 33);
        for (unsigned i = 0; i < 33; i++) assert(results[i].called == 1 && results[i].freed == 1);
        resolv_shutdown(test_loop);
        ss_io_stop(test_loop, &dns_io);
        ss_timer_stop(test_loop, &ticker);
        ss_timer_stop(test_loop, &deadline);
        ss_timer_stop(test_loop, &reply_timer);
        assert(!packets);
        assert(ss_run(test_loop, SS_RUN_NOWAIT) == 0);
    }
    ss_socket_close(fd);
    ss_loop_destroy(test_loop);
    return 0;
}
