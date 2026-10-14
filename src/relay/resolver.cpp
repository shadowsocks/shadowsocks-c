/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "relay/resolver.hpp"

#include <cstring>

#include "utils.h"

extern "C" int verbose;

namespace ss::relay {

Resolver::~Resolver()
{
    if (channel_ != nullptr) {
        std::abort(); // shutdown() first
    }
}

Status Resolver::init(event::Loop &loop, const char *nameservers, bool ipv6_first, std::uint32_t max_queries) noexcept
{
    if (channel_ != nullptr) {
        return fail(Errc::invalid);
    }
    SS_TRY(queries_.reserve(max_queries));
    int status = ares_library_init(ARES_LIB_INIT_ALL);
    if (status != ARES_SUCCESS) {
        LOGE("c-ares error: %s", ares_strerror(status));
        return fail(Errc::config);
    }
    ares_options options{};
    options.sock_state_cb      = &Resolver::sock_state;
    options.sock_state_cb_data = this;
    options.timeout            = 3000;
    options.tries              = 2;
    status = ares_init_options(&channel_, &options,
                               ARES_OPT_NOROTATE | ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES | ARES_OPT_SOCK_STATE_CB);
    if (status != ARES_SUCCESS) {
        LOGE("c-ares error: %s", ares_strerror(status));
        channel_ = nullptr;
        return fail(Errc::config);
    }
    if (nameservers != nullptr && ares_set_servers_ports_csv(channel_, nameservers) != ARES_SUCCESS) {
        LOGE("failed to set nameservers %s", nameservers);
        ares_destroy(channel_);
        channel_ = nullptr;
        return fail(Errc::config);
    }
    loop_       = &loop;
    ipv6_first_ = ipv6_first;
    for (Watch &w : watches_) {
        w.owner = this;
    }
    SS_TRY(timer_.open(loop, *this));
    return {};
}

Status Resolver::resolve(const char *host, std::uint16_t port, const ResolveCallback &cb) noexcept
{
    if (channel_ == nullptr) {
        return fail(Errc::closed);
    }
    SS_TRY_ASSIGN(query, queries_.acquire());
    query->owner = this;
    query->cb    = cb;
    query->port  = port;
    // c-ares holds the query until both lookups have reported back.
    Query *raw = query.release();
    ares_gethostbyname(channel_, host, AF_INET, &Resolver::on_host, raw);
    ares_gethostbyname(channel_, host, AF_INET6, &Resolver::on_host, raw);
    rearm();
    return {};
}

void Resolver::on_host(void *arg, int status, int, hostent *he) noexcept
{
    auto *q = static_cast<Query *>(arg);
    if (status == ARES_SUCCESS && he != nullptr && he->h_addr_list[0] != nullptr) {
        if (he->h_addrtype == AF_INET && !q->has4 && he->h_length == sizeof(in_addr)) {
            q->v4.sin_family = AF_INET;
            q->v4.sin_port   = q->port;
            std::memcpy(&q->v4.sin_addr, he->h_addr_list[0], sizeof(in_addr));
            q->has4 = true;
        } else if (he->h_addrtype == AF_INET6 && !q->has6 && he->h_length == sizeof(in6_addr)) {
            q->v6.sin6_family = AF_INET6;
            q->v6.sin6_port   = q->port;
            std::memcpy(&q->v6.sin6_addr, he->h_addr_list[0], sizeof(in6_addr));
            q->has6 = true;
        }
    } else if (verbose && status != ARES_EDESTRUCTION) {
        LOGI("failed to lookup address: %s", ares_strerror(status));
    }
    q->owner->finish(q, status);
}

void Resolver::finish(Query *q, int status) noexcept
{
    if (--q->pending != 0) {
        return;
    }
    PoolPtr<Query> owned = queries_.adopt(q);
    const sockaddr *best = nullptr;
    if (status != ARES_EDESTRUCTION) {
        if (ipv6_first_) {
            best = q->has6 ? reinterpret_cast<const sockaddr *>(&q->v6)
                           : (q->has4 ? reinterpret_cast<const sockaddr *>(&q->v4) : nullptr);
        } else {
            best = q->has4 ? reinterpret_cast<const sockaddr *>(&q->v4)
                           : (q->has6 ? reinterpret_cast<const sockaddr *>(&q->v6) : nullptr);
        }
    }
    ResolveCallback cb = q->cb;
    sockaddr_storage copy{};
    if (best != nullptr) {
        std::memcpy(&copy, best, best->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
    }
    owned.reset(); // the slot is free before the callback can start another query
    cb.fn(cb, best != nullptr ? reinterpret_cast<const sockaddr *>(&copy) : nullptr);
}

event::Flow Resolver::Watch::on_ready(int events) noexcept
{
    ares_socket_t rfd = (events & (event::readable | event::failed)) ? socket : ARES_SOCKET_BAD;
    ares_socket_t wfd = (events & (event::writable | event::failed)) ? socket : ARES_SOCKET_BAD;
    ares_process_fd(owner->channel_, rfd, wfd);
    owner->rearm();
    return event::Flow::proceed;
}

void Resolver::sock_state(void *data, ares_socket_t s, int readable, int writable) noexcept
{
    auto *self = static_cast<Resolver *>(data);
    Watch *slot = nullptr, *free_slot = nullptr;
    for (Watch &w : self->watches_) {
        if (w.poll.is_open() && !w.poll.is_closing() && w.socket == s) {
            slot = &w;
            break;
        }
        if (free_slot == nullptr && !w.poll.is_open()) {
            free_slot = &w;
        }
    }
    int events = (readable ? event::readable : 0) | (writable ? event::writable : 0);
    if (events == 0) {
        if (slot != nullptr) {
            // c-ares closes the socket itself right after this.
            slot->poll.close(self->closer_, false);
        }
        return;
    }
    if (slot == nullptr) {
        if (free_slot == nullptr) {
            LOGE("resolver: too many DNS sockets");
            return;
        }
        slot = free_slot;
        if (!slot->poll.open(*self->loop_, *slot, static_cast<ss_socket_t>(s))) {
            LOGE("resolver: cannot watch DNS socket");
            return;
        }
        slot->socket = s;
    }
    (void)slot->poll.want(events);
}

void Resolver::rearm() noexcept
{
    if (channel_ == nullptr) {
        return;
    }
    timeval tv{};
    if (ares_timeout(channel_, nullptr, &tv) == nullptr) {
        timer_.stop();
        return;
    }
    std::uint64_t ms = static_cast<std::uint64_t>(tv.tv_sec) * 1000 + static_cast<std::uint64_t>(tv.tv_usec) / 1000;
    timer_.start(ms == 0 ? 1 : ms);
}

void Resolver::on_timer() noexcept
{
    ares_process_fd(channel_, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
    rearm();
}

void Resolver::shutdown(CloseCompletion done) noexcept
{
    if (channel_ == nullptr) {
        done();
        return;
    }
    done_ = done;
    closer_.arm(CloseCompletion(
        [](void *self, std::uint32_t) { static_cast<Resolver *>(self)->on_closed_all(); }, this, 0));
    // Cancelled queries report nullptr; destroying the channel then reports
    // ARES_EDESTRUCTION for anything left and closes the sockets.
    ares_cancel(channel_);
    ares_channel channel = channel_;
    channel_             = nullptr;
    ares_destroy(channel);
    ares_library_cleanup();
    for (Watch &w : watches_) {
        w.poll.close(closer_, false);
    }
    timer_.close(closer_);
    closer_.seal();
}

void Resolver::on_closed_all() noexcept
{
    CloseCompletion done = done_;
    done();
}

} // namespace ss::relay
