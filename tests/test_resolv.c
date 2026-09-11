/* Exercise real c-ares cancellation with outstanding A and AAAA requests. */
#include "test_helpers.h"
#include "ss_event.h"
#include "resolv.h"

int verbose = 0;
struct result { unsigned called, freed; };
static void resolved(struct sockaddr *address, void *data)
{
    struct result *result = data;
    assert(address == NULL);
    assert(result->freed == 0);
    result->called++;
}
static void released(void *data)
{
    struct result *result = data;
    assert(result->called == 1);
    result->freed++;
}
int main(void)
{
    test_network_init();
    /* A bound but unread UDP socket prevents DNS responses or ICMP rejection;
     * the test needs no external DNS server or connectivity. */
    ss_socket_t sink = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(sink, (struct sockaddr *)&address, sizeof(address)) == 0);
    socklen_t size = sizeof(address);
    assert(getsockname(sink, (struct sockaddr *)&address, &size) == 0);
    char nameserver[64];
    snprintf(nameserver, sizeof(nameserver), "127.0.0.1:%u", ntohs(address.sin_port));
    struct ss_loop *loop = ss_loop_new(0);
    assert(loop != NULL);
    for (unsigned round = 0; round < 3; round++) {
        struct result results[64] = {{0}};
        assert(resolv_init(loop, nameserver, 0) == 0);
        for (unsigned i = 0; i < 64; i++) {
            char hostname[64];
            snprintf(hostname, sizeof(hostname), "pending-%u.invalid", i);
            resolv_start(hostname, htons(443), resolved, released, &results[i]);
        }
        ss_run(loop, SS_RUN_NOWAIT);
        resolv_shutdown(loop);
        for (unsigned i = 0; i < 64; i++) {
            assert(results[i].called == 1);
            assert(results[i].freed == 1);
        }
        assert(ss_run(loop, SS_RUN_NOWAIT) == 0);
    }
    ss_loop_destroy(loop);
    ss_socket_close(sink);
    return 0;
}
