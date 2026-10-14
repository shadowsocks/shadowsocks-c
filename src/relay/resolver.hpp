/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_RELAY_RESOLVER_HPP
#define SS_RELAY_RESOLVER_HPP

// Asynchronous DNS over c-ares with a fixed number of queries in flight.
//
// Replaces resolv.cpp's per-query state, per-answer sockaddr allocations
// and per-socket watcher nodes. A query lives in a pool slot; its answers are
// kept inline (the first A and the first AAAA record are all that is ever
// used); c-ares sockets are watched from a fixed table. A query never points
// at the object waiting for it: it carries a callback plus opaque words, and
// the relay resolves its own generation-checked handle when the answer comes
// back, so a connection that closed in the meantime is simply not found.

#include <array>
#include <cstdint>

#include <ares.h>

#include "core/pool.hpp"
#include "core/result.hpp"
#include "event/loop.hpp"
#include "netutils.h"

namespace ss::relay {

class Resolver;

// Called once per query with the chosen address, or nullptr when the name
// did not resolve (or the resolver is shutting down).
struct ResolveCallback {
    void (*fn)(const ResolveCallback &self, const sockaddr *address) noexcept = nullptr;
    void *ctx              = nullptr;
    void *aux              = nullptr;
    std::uint64_t token    = 0;
};

class Resolver {
public:
    static constexpr std::uint32_t kMaxSockets = 32;

    Resolver() noexcept = default;
    Resolver(const Resolver &)            = delete;
    Resolver &operator=(const Resolver &) = delete;
    ~Resolver();

    // `nameservers` is a c-ares CSV list (host[:port],...) or nullptr for the
    // system configuration.
    Status init(event::Loop &loop, const char *nameservers, bool ipv6_first, std::uint32_t max_queries) noexcept;

    // `port` is in network byte order and copied into the answer. Fails with
    // Errc::exhausted when max_queries are already in flight; the callback
    // is then never called.
    Status resolve(const char *host, std::uint16_t port, const ResolveCallback &cb) noexcept;

    std::uint32_t in_flight() const noexcept { return queries_.live(); }
    bool ready() const noexcept { return channel_ != nullptr; }

    // Cancel everything (callbacks get nullptr) and close the watchers; the
    // closes finish on the next loop iterations, then `done` runs.
    void shutdown(CloseCompletion done) noexcept;

private:
    struct Query {
        Resolver *owner = nullptr;
        ResolveCallback cb;
        std::uint16_t port = 0;
        std::uint8_t pending = 2; // A and AAAA
        bool has4 = false, has6 = false;
        sockaddr_in v4{};
        sockaddr_in6 v6{};
    };

    struct Watch {
        Resolver *owner = nullptr;
        ares_socket_t socket = ARES_SOCKET_BAD;
        event::Flow on_ready(int events) noexcept;
        event::Poll<Watch, &Watch::on_ready> poll;
    };

    static void sock_state(void *data, ares_socket_t s, int readable, int writable) noexcept;
    static void on_host(void *arg, int status, int timeouts, hostent *he) noexcept;
    void on_timer() noexcept;
    void rearm() noexcept;
    void finish(Query *q, int status) noexcept;
    void on_closed_all() noexcept;

    event::Loop *loop_ = nullptr;
    ares_channel channel_ = nullptr;
    bool ipv6_first_      = false;
    ObjectPool<Query> queries_;
    std::array<Watch, kMaxSockets> watches_{};
    event::Timer<Resolver, &Resolver::on_timer> timer_;
    event::CloseGroup closer_;
    CloseCompletion done_;
};

} // namespace ss::relay

#endif
