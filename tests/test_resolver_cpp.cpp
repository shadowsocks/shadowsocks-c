/* SPDX-License-Identifier: GPL-3.0-or-later */
// ss::relay::Resolver against a local DNS server that answers after a delay:
// A/AAAA/NXDOMAIN complete without blocking the loop, the query pool bounds
// the number in flight, and shutdown reports pending queries as failed.
#include <cstring>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "event/loop.hpp"
#include "relay/resolver.hpp"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

using namespace ss;

namespace {

struct Answered {
    unsigned called = 0;
    int family      = 0;
    bool missing    = false;
    bool ok         = false;
};

int expected_family = AF_INET;
unsigned completed  = 0;
event::Loop *test_loop = nullptr;
unsigned stop_after = 0;

void on_answer(const relay::ResolveCallback &cb, const sockaddr *address) noexcept
{
    auto *r = static_cast<Answered *>(cb.ctx);
    ++r->called;
    if (address != nullptr) {
        r->family = address->sa_family;
        r->ok     = address->sa_family == AF_INET
                    ? reinterpret_cast<const sockaddr_in *>(address)->sin_port == htons(443)
                    : reinterpret_cast<const sockaddr_in6 *>(address)->sin6_port == htons(443);
    }
    if (++completed == stop_after) {
        test_loop->stop();
    }
}

// Answers every question 50 ms later: names starting with 'm' do not exist.
class FakeDns {
public:
    void on_tick() noexcept
    {
        for (auto &p : pending_) {
            (void)sendto(poll_.fd(), p.bytes, p.length, 0, reinterpret_cast<sockaddr *>(&p.peer), p.peer_len);
        }
        pending_.clear();
    }
    event::Flow on_question(int) noexcept
    {
        Packet p{};
        p.peer_len = sizeof(p.peer);
        ssize_t n  = recvfrom(poll_.fd(), p.bytes, sizeof(p.bytes), 0, reinterpret_cast<sockaddr *>(&p.peer),
                              &p.peer_len);
        if (n < 17) {
            return event::Flow::proceed;
        }
        std::size_t end = 12;
        while (end < static_cast<std::size_t>(n) && p.bytes[end] != 0) {
            end += p.bytes[end] + 1;
        }
        end += 5;
        unsigned type = p.bytes[end - 3];
        bool missing  = p.bytes[13] == 'm';
        p.bytes[2]    = 0x81;
        p.bytes[3]    = missing ? 0x83 : 0x80;
        p.bytes[6]    = 0;
        p.bytes[7]    = missing ? 0 : 1;
        std::memset(p.bytes + 8, 0, 4);
        p.length = end;
        if (!missing) {
            unsigned char answer[] = { 0xc0, 0x0c, 0, static_cast<unsigned char>(type), 0, 1, 0, 0, 0, 1, 0,
                                       static_cast<unsigned char>(type == 1 ? 4 : 16) };
            std::memcpy(p.bytes + end, answer, sizeof(answer));
            p.length += sizeof(answer);
            std::memset(p.bytes + p.length, 0, 16);
            if (type == 1) {
                p.bytes[p.length]     = 127;
                p.bytes[p.length + 3] = 1;
            } else {
                p.bytes[p.length + 15] = 1;
            }
            p.length += type == 1 ? 4 : 16;
        }
        pending_.push_back(p);
        timer_.start(50);
        return event::Flow::proceed;
    }

    void open(event::Loop &loop, int fd)
    {
        SS_CHECK(poll_.open(loop, *this, fd));
        SS_CHECK(poll_.want(event::readable));
        SS_CHECK(timer_.open(loop, *this));
    }
    void close(event::CloseGroup &g)
    {
        poll_.close(g);
        timer_.close(g);
    }

private:
    struct Packet {
        sockaddr_storage peer;
        socklen_t peer_len;
        unsigned char bytes[512];
        std::size_t length;
    };
    std::vector<Packet> pending_;
    event::Poll<FakeDns, &FakeDns::on_question> poll_;
    event::Timer<FakeDns, &FakeDns::on_tick> timer_;
};

void drain(event::Loop &loop, bool &flag)
{
    while (!flag) {
        loop.run_nowait();
    }
}

void test_answers_and_limits()
{
    for (int ipv6 = 0; ipv6 < 2; ++ipv6) {
        event::Loop loop;
        SS_CHECK(loop.init());
        test_loop = &loop;
        int fd    = socket(AF_INET, SOCK_DGRAM, 0);
        SS_CHECK(fd >= 0);
        sockaddr_in a{};
        a.sin_family      = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        SS_CHECK(bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) == 0);
        socklen_t len = sizeof(a);
        SS_CHECK(getsockname(fd, reinterpret_cast<sockaddr *>(&a), &len) == 0);
        char nameserver[64];
        std::snprintf(nameserver, sizeof(nameserver), "127.0.0.1:%u", ntohs(a.sin_port));
        FakeDns dns;
        dns.open(loop, fd);

        relay::Resolver resolver;
        SS_CHECK(resolver.init(loop, nameserver, ipv6 != 0, 33));
        expected_family = ipv6 ? AF_INET6 : AF_INET;
        completed       = 0;
        stop_after      = 33;
        Answered results[34];
        results[32].missing = true;
        for (unsigned i = 0; i < 34; ++i) {
            char host[64];
            std::snprintf(host, sizeof(host), "%s-%u.invalid", i == 32 ? "missing" : "resolved", i);
            relay::ResolveCallback cb;
            cb.fn  = &on_answer;
            cb.ctx = &results[i];
            auto st = resolver.resolve(host, htons(443), cb);
            // The pool holds 33 queries; the 34th is refused up front.
            SS_CHECK(i < 33 ? static_cast<bool>(st) : (!st && st.error().code == Errc::exhausted));
        }
        SS_CHECK(completed == 0 && resolver.in_flight() == 33);
        loop.run();
        SS_CHECK(completed == 33 && resolver.in_flight() == 0);
        for (unsigned i = 0; i < 33; ++i) {
            SS_CHECK(results[i].called == 1);
            if (results[i].missing) {
                SS_CHECK(!results[i].ok && results[i].family == 0);
            } else {
                SS_CHECK(results[i].ok && results[i].family == expected_family);
            }
        }
        SS_CHECK(results[33].called == 0);

        // Shutting down with queries in flight reports them as failed.
        Answered late;
        relay::ResolveCallback cb;
        cb.fn  = &on_answer;
        cb.ctx = &late;
        SS_CHECK(resolver.resolve("resolved-late.invalid", htons(443), cb));
        static bool closed;
        closed = false;
        resolver.shutdown(CloseCompletion([](void *, std::uint32_t) { closed = true; }, nullptr, 0));
        drain(loop, closed);
        SS_CHECK(late.called == 1 && !late.ok);

        event::CloseGroup g;
        static bool dns_closed;
        dns_closed = false;
        g.arm(CloseCompletion([](void *, std::uint32_t) { dns_closed = true; }, nullptr, 0));
        dns.close(g);
        g.seal();
        drain(loop, dns_closed);
        SS_CHECK(loop.shutdown());
    }
}

} // namespace

int main()
{
    SS_RUN(test_answers_and_limits);
    return 0;
}
