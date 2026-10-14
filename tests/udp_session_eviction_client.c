/* Live UDP relay regression based on Akhil Koul (@akoul)'s private report.
 * Two source sockets preserve one relay while replacing the other's session.
 * Receive each forwarded packet before sending the next: no racing counters,
 * sleeps, or unbounded waits are needed to hit the exact cache boundary. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sodium.h>
#include "aead.h"
#include "crypto.h"
#include "ppbloom.h"
#include "utils.h"

int verbose = 0;
struct cache *nonce_cache = NULL;

static int
udp_socket(void)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(fd >= 0);
    struct timeval timeout = { 5, 0 };
    assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
    return fd;
}

static void
check_reply(int upstream, int client, const struct sockaddr_in *peer,
            crypto_t *crypto, void **session, buffer_t *packet)
{
    const unsigned char reply = 0x42;
    assert(sendto(upstream, &reply, 1, 0, (const struct sockaddr *)peer,
                  sizeof(*peer)) == 1);
    ssize_t n = recv(client, packet->data, packet->capacity, 0);
    assert(n > 0);
    packet->len = (size_t)n;
    assert(crypto->decrypt_udp(packet, crypto->cipher, 2048, session) == CRYPTO_OK);
    assert(packet->len == 8 && (unsigned char)packet->data[0] == 1);
    assert((unsigned char)packet->data[7] == reply);
}

int
main(int argc, char **argv)
{
    assert(argc == 5);
    int port = atoi(argv[1]);
    int count = atoi(argv[2]);
    assert(port > 0 && port <= 65535 && count > 1);
    assert(sodium_init() >= 0);
    crypto_t *crypto = crypto_init(argv[4], NULL, argv[3]);
    assert(crypto != NULL);
    aead_set_role(CRYPTO_ROLE_CLIENT);

    int upstream = udp_socket(), first = udp_socket(), flood = udp_socket();
    struct sockaddr_in origin = { 0 }, server = { 0 };
    origin.sin_family = server.sin_family = AF_INET;
    origin.sin_addr.s_addr = server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server.sin_port = htons((uint16_t)port);
    assert(bind(upstream, (struct sockaddr *)&origin, sizeof(origin)) == 0);
    socklen_t length = sizeof(origin);
    assert(getsockname(upstream, (struct sockaddr *)&origin, &length) == 0);
    uint16_t upstream_port = ntohs(origin.sin_port);
    const unsigned char plaintext[] = {
        1, 127, 0, 0, 1, (unsigned char)(upstream_port >> 8),
        (unsigned char)upstream_port, 0x41
    };
    buffer_t packet = { 0 };
    balloc(&packet, 2048);
    void *first_session = NULL, *last_session = NULL;
    struct sockaddr_in first_peer = { 0 }, last_peer = { 0 };
    for (int i = 0; i < count; ++i) {
        void *session = NULL;
        memcpy(packet.data, plaintext, sizeof(plaintext));
        packet.len = sizeof(plaintext);
        assert(crypto->encrypt_udp(&packet, crypto->cipher, 2048, &session) == CRYPTO_OK);
        assert(sendto(i == 0 ? first : flood, packet.data, packet.len, 0,
                      (struct sockaddr *)&server, sizeof(server)) == (ssize_t)packet.len);
        unsigned char payload[2];
        length = sizeof(last_peer);
        assert(recvfrom(upstream, payload, sizeof(payload), 0,
                        (struct sockaddr *)&last_peer, &length) == 1);
        assert(payload[0] == 0x41);
        if (i == 0) {
            first_peer = last_peer;
            first_session = session;
        } else if (i == count - 1) {
            last_session = session;
        } else {
            crypto->udp_session_release(session);
        }
    }
    /* The first relay must survive eviction; the reused relay must use its
     * latest session, not a leaked or stale previous owner. */
    check_reply(upstream, first, &first_peer, crypto, &first_session, &packet);
    check_reply(upstream, flood, &last_peer, crypto, &last_session, &packet);
    crypto->udp_session_release(first_session);
    crypto->udp_session_release(last_session);
    bfree(&packet);
    close(upstream);
    close(first);
    close(flood);
    ppbloom_free();
    ss_free(crypto->cipher);
    ss_free(crypto);
    return 0;
}
