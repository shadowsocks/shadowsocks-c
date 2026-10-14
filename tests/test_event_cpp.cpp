/* SPDX-License-Identifier: GPL-3.0-or-later */
// C++ event layer (src/event/loop.hpp): polling, close ordering, pooled
// owners, timers, deadlines and cross-thread wakeups.
#include <cstdint>
#include <cstring>
#include <optional>

#include "event/loop.hpp"
#include "test_helpers.h"
#include "test_helpers.hpp"

namespace ev = ss::event;

namespace {

ss_socket_t udp_socket(sockaddr_in &bound)
{
    ss_socket_t fd = socket(AF_INET, SOCK_DGRAM, 0);
    SS_CHECK(fd != (ss_socket_t)-1);
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    SS_CHECK(bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    socklen_t len = sizeof(bound);
    SS_CHECK(getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &len) == 0);
    return fd;
}

void send_byte(const sockaddr_in &to)
{
    sockaddr_in unused{};
    ss_socket_t s = udp_socket(unused);
    char byte     = 'x';
    SS_CHECK(sendto(s, &byte, 1, 0, reinterpret_cast<const sockaddr *>(&to), sizeof(to)) == 1);
    ss_socket_close(s);
}

void drain(ss_socket_t fd)
{
    char buf[16];
    (void)recv(fd, buf, sizeof(buf), 0);
}

// Closes its handles into a group and records when the group completes.
struct Finished {
    bool done = false;
    static void complete(void *self, std::uint32_t) noexcept { static_cast<Finished *>(self)->done = true; }
    ss::CloseCompletion completion() noexcept { return ss::CloseCompletion(&Finished::complete, this, 0); }
};

struct Reader {
    ev::Flow on_ready(int ready);

    ev::Loop *loop = nullptr;
    ev::Poll<Reader, &Reader::on_ready> poll;
    ev::CloseGroup closer;
    Reader *victim = nullptr; // closed from inside our callback
    Finished victim_closed;
    int events = 0;
};

ev::Flow Reader::on_ready(int ready)
{
    ++events;
    SS_CHECK(ready & ev::readable);
    drain(poll.fd());
    if (victim != nullptr) {
        victim->closer.arm(victim_closed.completion());
        victim->poll.close(victim->closer);
        victim->closer.seal();
        victim = nullptr;
    }
    loop->stop();
    return ev::Flow::proceed;
}

void close_reader(ev::Loop &loop, Reader &r)
{
    Finished finished;
    r.closer.arm(finished.completion());
    r.poll.close(r.closer);
    r.closer.seal();
    while (!finished.done) {
        loop.run_once();
    }
}

void test_poll_readable()
{
    ev::Loop loop;
    SS_CHECK(loop.init());
    sockaddr_in addr{};
    Reader r;
    r.loop = &loop;
    SS_CHECK(r.poll.open(loop, r, udp_socket(addr)));
    SS_CHECK(r.poll.want(ev::readable));
    send_byte(addr);
    loop.run();
    SS_CHECK(r.events == 1);
    // Interest can be dropped without closing.
    SS_CHECK(r.poll.want(0));
    SS_CHECK(r.poll.interest() == 0);
    // The loop refuses to shut down while a handle is still open.
    SS_CHECK(!loop.shutdown());
    close_reader(loop, r);
    SS_CHECK(!r.poll.is_open());
    SS_CHECK(loop.shutdown());
}

void test_close_peer_inside_callback()
{
    ev::Loop loop;
    SS_CHECK(loop.init());
    sockaddr_in a_addr{}, b_addr{};
    Reader a, b;
    a.loop = b.loop = &loop;
    SS_CHECK(a.poll.open(loop, a, udp_socket(a_addr)));
    SS_CHECK(b.poll.open(loop, b, udp_socket(b_addr)));
    SS_CHECK(a.poll.want(ev::readable));
    SS_CHECK(b.poll.want(ev::readable));
    // Whichever fires first closes the other; the other must stay silent.
    a.victim = &b;
    b.victim = &a;
    send_byte(a_addr);
    send_byte(b_addr);
    loop.run();
    SS_CHECK(a.events + b.events == 1);
    Reader &survivor = a.events == 1 ? a : b;
    Reader &closed   = a.events == 1 ? b : a;
    while (!survivor.victim_closed.done) {
        loop.run_once();
    }
    SS_CHECK(!closed.poll.is_open());
    loop.run_nowait();
    SS_CHECK(closed.events == 0);
    close_reader(loop, survivor);
    SS_CHECK(loop.shutdown());
}

// A pooled connection-like owner: dropping its PoolPtr closes its handles,
// and the slot only returns to the pool afterwards.
struct Conn {
    ev::Flow on_ready(int) { return ev::Flow::proceed; }
    void on_timer() {}

    ev::Poll<Conn, &Conn::on_ready> poll;
    ev::Timer<Conn, &Conn::on_timer> timer;
    ev::CloseGroup closer;

    void begin_close(ss::CloseCompletion done) noexcept
    {
        closer.arm(done);
        poll.close(closer);
        timer.close(closer);
        closer.seal();
    }
};

void test_pooled_owner_close()
{
    static_assert(ss::AsyncClosable<Conn>);
    ev::Loop loop;
    SS_CHECK(loop.init());
    ss::ObjectPool<Conn> pool;
    SS_CHECK(pool.reserve(1));
    sockaddr_in addr{};
    ss_socket_t fd;
    {
        auto conn = pool.acquire();
        SS_CHECK(conn);
        fd = udp_socket(addr);
        SS_CHECK((*conn)->poll.open(loop, **conn, fd));
        SS_CHECK((*conn)->timer.open(loop, **conn));
        (*conn)->timer.start(60000);
        SS_CHECK((*conn)->poll.want(ev::readable));
    }
    // Ownership is gone; libuv still holds the handles.
    SS_CHECK(pool.closing() == 1 && pool.available() == 0);
    loop.run_nowait();
    SS_CHECK(pool.closing() == 0 && pool.available() == 1);
#ifndef _WIN32
    // The socket was closed with the poll handle.
    SS_CHECK(fcntl(fd, F_GETFD) == -1);
#endif
    (void)fd;
    // An owner that never opened a handle completes synchronously.
    {
        auto idle = pool.acquire();
        SS_CHECK(idle);
    }
    SS_CHECK(pool.available() == 1);
    SS_CHECK(loop.shutdown());
}

struct Ticker {
    void on_timer();

    ev::Loop *loop = nullptr;
    ev::Timer<Ticker, &Ticker::on_timer> timer;
    ev::CloseGroup closer;
    int fired = 0;
};

void Ticker::on_timer()
{
    if (++fired == 3) {
        timer.stop();
        loop->stop();
    }
}

void test_timer_repeat()
{
    ev::Loop loop;
    SS_CHECK(loop.init());
    Ticker t;
    t.loop = &loop;
    SS_CHECK(t.timer.open(loop, t));
    t.timer.start(1, 1);
    SS_CHECK(t.timer.active());
    loop.run();
    SS_CHECK(t.fired == 3 && !t.timer.active());
    Finished finished;
    t.closer.arm(finished.completion());
    t.timer.close(t.closer);
    t.closer.seal();
    loop.run();
    SS_CHECK(finished.done && loop.shutdown());
}

struct Idle : ev::Deadline {
    explicit Idle(int v) noexcept : id(v) {}
    int id;
};

void test_deadlines()
{
    ev::DeadlineList<Idle> idle(100);
    Idle a(1), b(2), c(3);
    SS_CHECK(!idle.next_due());
    idle.touch(a, 0);
    idle.touch(b, 10);
    idle.touch(c, 20);
    SS_CHECK(idle.next_due() == std::optional<std::uint64_t>(100));
    // Activity on `a` pushes it behind the others.
    idle.touch(a, 50);
    SS_CHECK(idle.next_due() == std::optional<std::uint64_t>(110) && a.deadline() == 150);
    int order[3] = {};
    int n        = 0;
    SS_CHECK(idle.expire(120, [&](Idle &x) { order[n++] = x.id; }) == 2);
    SS_CHECK(order[0] == 2 && order[1] == 3);
    SS_CHECK(!b.linked() && a.linked());
    ev::DeadlineList<Idle>::remove(a);
    SS_CHECK(idle.empty());
}

struct Waker {
    void on_wake()
    {
        ++woken;
        loop->stop();
    }

    ev::Loop *loop = nullptr;
    ev::Async<Waker, &Waker::on_wake> async;
    ev::CloseGroup closer;
    int woken = 0;
};

void wake_from_thread(void *arg)
{
    static_cast<Waker *>(arg)->async.send();
}

void test_async_cross_thread()
{
    ev::Loop loop;
    SS_CHECK(loop.init());
    Waker w;
    w.loop = &loop;
    SS_CHECK(w.async.open(loop, w));
    uv_thread_t thread;
    SS_CHECK(uv_thread_create(&thread, &wake_from_thread, &w) == 0);
    loop.run();
    SS_CHECK(uv_thread_join(&thread) == 0);
    SS_CHECK(w.woken == 1);
    Finished finished;
    w.closer.arm(finished.completion());
    w.async.close(w.closer);
    w.closer.seal();
    loop.run();
    SS_CHECK(finished.done && loop.shutdown());
}

} // namespace

int main()
{
    test_network_init();
    SS_RUN(test_poll_readable);
    SS_RUN(test_close_peer_inside_callback);
    SS_RUN(test_pooled_owner_close);
    SS_RUN(test_timer_repeat);
    SS_RUN(test_deadlines);
    SS_RUN(test_async_cross_thread);
    return 0;
}
