/* SPDX-License-Identifier: GPL-3.0-or-later */
// The embedding API (<shadowsocks/control.h>, <shadowsocks/shadowsocks.hpp>):
// start ss-local on the library's thread, talk SOCKS5 to it, refuse a second
// instance, stop it from this thread, and start it again.
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <shadowsocks/shadowsocks.hpp>

#include "test_helpers.hpp"

namespace {

std::atomic<int> ready_fd{ -1 };

void on_ready(int socks_fd, int, void *) { ready_fd = socks_fd; }

int free_port()
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    SS_CHECK(fd >= 0);
    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    SS_CHECK(bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0);
    socklen_t len = sizeof(a);
    SS_CHECK(getsockname(fd, reinterpret_cast<sockaddr *>(&a), &len) == 0);
    close(fd);
    return ntohs(a.sin_port);
}

bool socks_greeting(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    sockaddr_in a{};
    a.sin_family      = AF_INET;
    a.sin_port        = htons(static_cast<uint16_t>(port));
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bool ok           = false;
    if (connect(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0) {
        const unsigned char hello[3] = { 5, 1, 0 };
        unsigned char reply[2]       = {};
        ok = send(fd, hello, sizeof(hello), 0) == 3 && recv(fd, reply, 2, MSG_WAITALL) == 2 && reply[0] == 5
             && reply[1] == 0;
    }
    close(fd);
    return ok;
}

void wait_ready()
{
    for (int i = 0; i < 500 && ready_fd < 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    SS_CHECK(ready_fd >= 0);
}

void test_lifecycle()
{
    int port = free_port();
    char host[] = "127.0.0.1", method[] = "aes-256-gcm", password[] = "secret";
    profile_t profile{};
    profile.remote_host = host;
    profile.local_addr  = host;
    profile.method      = method;
    profile.password    = password;
    profile.remote_port = 1; // nothing listens there; only the SOCKS side is exercised
    profile.local_port  = port;
    profile.timeout     = 10;

    for (int round = 0; round < 2; ++round) {
        ready_fd = -1;
        shadowsocks::LocalServer server;
        SS_CHECK(server.start(profile, &on_ready, nullptr) == 0);
        wait_ready();
        SS_CHECK(socks_greeting(port));

        shadowsocks::LocalServer second;
        SS_CHECK(second.start(profile) == EBUSY);

        server.stop();
        SS_CHECK(server.wait() == 0);
        SS_CHECK(!server.running());
    }

    // A stop before the loop runs is honoured too.
    ss_local_handle *h = nullptr;
    ready_fd           = -1;
    SS_CHECK(ss_local_start(&profile, &on_ready, nullptr, &h) == 0);
    ss_local_stop(h);
    SS_CHECK(ss_local_wait(h) == 0);
    ss_local_destroy(h);
    SS_CHECK(ss_local_start(nullptr, nullptr, nullptr, &h) == EINVAL);
}

} // namespace

int main()
{
    SS_RUN(test_lifecycle);
    return 0;
}
