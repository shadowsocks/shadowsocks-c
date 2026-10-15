/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "relay/tcp.hpp"

#include <algorithm>
#include <cinttypes>
#include <cstring>
#include <memory>

#include <sodium.h>

#ifdef __linux__
#include <linux/netfilter_ipv4.h>
#endif

#include "acl.h" // BLACK_LIST, WHITE_LIST
#include "jconf.h"
#include "utils.h"

extern "C" int verbose;

#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif
#ifndef IP6T_SO_ORIGINAL_DST
#define IP6T_SO_ORIGINAL_DST 80
#endif

namespace ss::relay {

using event::Flow;

namespace {

constexpr std::uint64_t kDelayMs     = 50;  // wait for a first payload before connecting
constexpr int kAcceptBurst           = 64;  // connections accepted per wakeup
constexpr int kPumpRounds            = 16;  // receives per direction per wakeup
constexpr std::uint8_t kSocksVersion = 5;

std::uint64_t pack(Handle<Connection> h) noexcept
{
    return (static_cast<std::uint64_t>(h.index) << 32) | h.gen;
}

Handle<Connection> unpack(std::uint64_t v) noexcept
{
    return Handle<Connection>{ static_cast<std::uint32_t>(v >> 32), static_cast<std::uint32_t>(v) };
}

std::span<std::uint8_t> bytes_of(std::span<std::byte> b) noexcept
{
    return { reinterpret_cast<std::uint8_t *>(b.data()), b.size() };
}

std::span<const std::uint8_t> bytes_of(std::span<const std::byte> b) noexcept
{
    return { reinterpret_cast<const std::uint8_t *>(b.data()), b.size() };
}

bool loopback_v4(const sockaddr *addr) noexcept
{
    return addr->sa_family == AF_INET
           && reinterpret_cast<const sockaddr_in *>(addr)->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
}

void send_reply(ss_socket_t fd, const std::uint8_t *data, std::size_t len) noexcept
{
    // Handshake replies are tiny; like the C relays, a short send is fatal.
    (void)send_some(fd, { data, len });
}

#ifdef __linux__
bool original_destination(ss_socket_t fd, bool tproxy, sockaddr_storage &out) noexcept
{
    socklen_t len = sizeof(out);
    if (tproxy) {
        return getsockname(fd, reinterpret_cast<sockaddr *>(&out), &len) == 0;
    }
    if (getsockopt(fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &out, &len) == 0) {
        return true;
    }
    len = sizeof(out);
    return getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &out, &len) == 0;
}
#else
bool original_destination(ss_socket_t, bool, sockaddr_storage &) noexcept
{
    return false;
}
#endif

void peer_name(ss_socket_t fd, char *out, std::size_t size) noexcept
{
    out[0] = '\0';
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    if (getpeername(fd, reinterpret_cast<sockaddr *>(&addr), &len) != 0) {
        return;
    }
    if (addr.ss_family == AF_INET) {
        ss_inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(&addr)->sin_addr, out, static_cast<socklen_t>(size));
    } else if (addr.ss_family == AF_INET6) {
        ss_inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(&addr)->sin6_addr, out,
                     static_cast<socklen_t>(size));
    }
}

} // namespace

// ------------------------------------------------------------------ relay

TcpRelay::~TcpRelay()
{
    for (auto &owner : owners_) {
        std::destroy_at(&owner);
    }
}

Status TcpRelay::init(event::Loop &loop, Method &method, const TcpConfig &config, Resolver *resolver) noexcept
{
    if (loop_ != nullptr || config.max_connections == 0) {
        return fail(Errc::invalid);
    }
    if (config.kind != Kind::server && config.remotes.empty()) {
        return fail(Errc::config);
    }
    loop_     = &loop;
    method_   = &method;
    resolver_ = resolver;
    config_   = config;
    const AclHooks &acl = config_.acl_hooks;
    if (acl.match_host == nullptr || acl.mode == nullptr || acl.outbound_blocked == nullptr) {
        config_.acl = false;
    }
    SS_TRY(buffers_.reserve(2 * config.max_connections));
    SS_TRY(pool_.reserve(config.max_connections));
    using Owner = PoolPtr<Connection>;
    SS_TRY_ASSIGN(region, Region::reserve(config.max_connections * sizeof(Owner), alignof(Owner)));
    owners_region_ = std::move(region);
    auto *first    = reinterpret_cast<Owner *>(owners_region_.data());
    for (std::uint32_t i = 0; i < config.max_connections; ++i) {
        std::construct_at(first + i);
    }
    owners_ = { first, config.max_connections };

    const std::uint64_t timeout = static_cast<std::uint64_t>(std::max(config.timeout_secs, 1));
    delay_list_.set_timeout(kDelayMs);
    connect_list_.set_timeout(std::min<std::uint64_t>(MAX_CONNECT_TIMEOUT, timeout) * 1000);
    idle_list_.set_timeout(std::max<std::uint64_t>(MIN_TCP_IDLE_TIMEOUT, timeout) * 1000);
    SS_TRY(timer_.open(loop, *this));
    own_closed_ = false;
    LOGI("tcp: up to %u connections (%zu KiB each, plus two %zu KiB buffers leased while data is in flight)",
         config.max_connections, sizeof(Connection) / 1024, sizeof(RelayBuffer) / 1024);
    return {};
}

Status TcpRelay::listen(ss_socket_t fd, int tos) noexcept
{
    if (listener_count_ == kMaxListeners || loop_ == nullptr) {
        return fail(Errc::exhausted);
    }
    SS_TRY(set_nonblocking(fd));
    Listener &l = listeners_[listener_count_];
    l.relay     = this;
    l.tos       = tos;
    SS_TRY(l.poll.open(*loop_, l, fd));
    ++listener_count_;
    return l.poll.want(event::readable);
}

Flow TcpRelay::Listener::on_ready(int) noexcept
{
    relay->accept_from(*this);
    return Flow::proceed;
}

void TcpRelay::accept_from(Listener &listener) noexcept
{
    for (int i = 0; i < kAcceptBurst && !shutting_down_; ++i) {
        ss_socket_t fd = ss_accept(listener.poll.fd(), nullptr, nullptr);
#ifdef _WIN32
        if (fd == INVALID_SOCKET) {
#else
        if (fd < 0) {
#endif
            int err = ss_socket_error();
            if (err != EAGAIN && err != EWOULDBLOCK && err != EINTR) {
                ERROR("accept");
            }
            return;
        }
        if (pool_.full()) {
            ss_socket_close(fd);
            ++refused_;
            std::uint64_t now = loop_->now();
            if (now - last_refusal_log_ >= 1000 || last_refusal_log_ == 0) {
                LOGE("connection limit of %u reached, %" PRIu64 " connection(s) refused so far",
                     pool_.capacity(), refused_);
                last_refusal_log_ = now;
            }
            pause_accept();
            return;
        }
        if (config_.kind == Kind::server && config_.acl) {
            char peer[INET6_ADDRSTRLEN];
            peer_name(fd, peer, sizeof(peer));
            if (peer[0] != '\0'
                && ((config_.acl_hooks.mode() == BLACK_LIST && config_.acl_hooks.match_host(peer) == 1)
                    || (config_.acl_hooks.mode() == WHITE_LIST && config_.acl_hooks.match_host(peer) >= 0))) {
                LOGE("Access denied from %s", peer);
                ss_socket_close(fd);
                continue;
            }
        }
        auto conn = pool_.acquire(*this);
        if (!conn) {
            ss_socket_close(fd);
            return;
        }
        Connection &c   = **conn;
        std::uint32_t at = pool_.handle_of(&c).index;
        owners_[at]     = std::move(*conn);
        c.tos_          = listener.tos;
        (void)c.start(fd);
    }
}

void TcpRelay::pause_accept() noexcept
{
    if (accept_paused_) {
        return;
    }
    accept_paused_ = true;
    for (std::size_t i = 0; i < listener_count_; ++i) {
        (void)listeners_[i].poll.want(0);
    }
}

void TcpRelay::resume_accept() noexcept
{
    accept_paused_ = false;
    for (std::size_t i = 0; i < listener_count_; ++i) {
        (void)listeners_[i].poll.want(event::readable);
    }
}

void TcpRelay::slot_freed() noexcept
{
    if (accept_paused_ && !shutting_down_ && !pool_.full()) {
        resume_accept();
    }
}

void TcpRelay::close(Connection &conn) noexcept
{
    clear_deadline(conn);
    std::uint32_t at = pool_.handle_of(&conn).index;
    owners_[at].reset(); // begins the asynchronous close
}

const sockaddr_storage &TcpRelay::pick_remote() noexcept
{
    auto n = static_cast<std::uint32_t>(config_.remotes.size());
    return config_.remotes[n > 1 ? randombytes_uniform(n) : 0];
}

void TcpRelay::set_deadline(Connection &conn, Connection::Timed which) noexcept
{
    if (conn.timed_ != which) {
        clear_deadline(conn);
    }
    event::DeadlineList<Connection> *list = which == Connection::Timed::delay     ? &delay_list_
                                            : which == Connection::Timed::connect ? &connect_list_
                                                                                  : &idle_list_;
    std::uint64_t now = loop_->now();
    list->touch(conn, now);
    conn.timed_ = which;
    std::uint64_t due = conn.deadline();
    if (timer_due_ == 0 || due < timer_due_) {
        timer_due_ = due;
        timer_.start(due > now ? due - now : 1);
    }
}

void TcpRelay::clear_deadline(Connection &conn) noexcept
{
    if (conn.timed_ != Connection::Timed::none) {
        event::DeadlineList<Connection>::remove(conn);
        conn.timed_ = Connection::Timed::none;
    }
}

void TcpRelay::on_timer() noexcept
{
    timer_due_        = 0;
    std::uint64_t now = loop_->now();
    auto fire         = [](Connection::Timed which) {
        return [which](Connection &c) {
            c.timed_ = Connection::Timed::none;
            if (which == Connection::Timed::delay) {
                c.on_deadline();
            } else {
                if (verbose) {
                    LOGI("TCP connection timeout");
                }
                (void)c.close();
            }
        };
    };
    delay_list_.expire(now, fire(Connection::Timed::delay));
    connect_list_.expire(now, fire(Connection::Timed::connect));
    idle_list_.expire(now, fire(Connection::Timed::idle));
    schedule();
}

void TcpRelay::schedule() noexcept
{
    std::uint64_t due = 0;
    for (auto *list : { &delay_list_, &connect_list_, &idle_list_ }) {
        if (auto next = list->next_due()) {
            due = due == 0 ? *next : std::min(due, *next);
        }
    }
    if (due == 0) {
        timer_.stop();
        timer_due_ = 0;
        return;
    }
    std::uint64_t now = loop_->now();
    timer_due_        = due;
    timer_.start(due > now ? due - now : 1);
}

Status TcpRelay::resolve(Connection &conn, const char *host, std::uint16_t port_be) noexcept
{
    if (resolver_ == nullptr) {
        return fail(Errc::invalid);
    }
    ResolveCallback cb;
    cb.fn    = &TcpRelay::resolved;
    cb.ctx   = this;
    cb.token = pack(pool_.handle_of(&conn));
    return resolver_->resolve(host, port_be, cb);
}

void TcpRelay::resolved(const ResolveCallback &cb, const sockaddr *address) noexcept
{
    auto *self = static_cast<TcpRelay *>(cb.ctx);
    if (Connection *conn = self->pool_.resolve(unpack(cb.token))) {
        conn->on_resolved(address);
    }
}

void TcpRelay::shutdown() noexcept
{
    if (shutting_down_ || loop_ == nullptr) {
        return;
    }
    shutting_down_ = true;
    for (auto &owner : owners_) {
        if (owner) {
            close(*owner);
        }
    }
    closer_.arm(CloseCompletion([](void *self, std::uint32_t) { static_cast<TcpRelay *>(self)->own_closed_ = true; },
                                this, 0));
    for (std::size_t i = 0; i < listener_count_; ++i) {
        listeners_[i].poll.close(closer_);
    }
    timer_.close(closer_);
    closer_.seal();
}

bool TcpRelay::closed() const noexcept
{
    return own_closed_ && pool_.live() == 0 && pool_.closing() == 0;
}

// ------------------------------------------------------------- connection

bool Connection::client_kind() const noexcept
{
    return relay_->config_.kind != Kind::server;
}

void Connection::begin_close(CloseCompletion done) noexcept
{
    if (hook_state_ != nullptr && relay_->config_.release != nullptr) {
        relay_->config_.release(hook_state_);
        hook_state_ = nullptr;
    }
    done_ = done;
    closer_.arm(CloseCompletion(
        [](void *self, std::uint32_t) {
            auto *c            = static_cast<Connection *>(self);
            TcpRelay *relay    = c->relay_;
            CloseCompletion d  = c->done_;
            d(); // destroys *c
            relay->slot_freed();
        },
        this, 0));
    client_.close(closer_);
    upstream_.close(closer_);
    closer_.seal();
}

Connection::Connection(TcpRelay &relay) noexcept
    : relay_(&relay)
    , to_upstream_(relay.buffers_)
    , to_client_(relay.buffers_)
{
}

Flow Connection::close() noexcept
{
    relay_->close(*this);
    return Flow::closed;
}

Flow Connection::start(ss_socket_t fd) noexcept
{
    (void)set_nonblocking(fd);
    set_nodelay(fd, true);
    set_nosigpipe(fd);
    if (!client_.open(*relay_->loop_, *this, fd)) {
        ss_socket_close(fd);
        return close();
    }
    const TcpConfig &cfg = relay_->config_;
    // Every connection is timed from the start, so a client that never
    // finishes its handshake cannot hold a pool slot forever. Later stages
    // replace this with their own deadline.
    relay_->set_deadline(*this, Timed::idle);
    switch (cfg.kind) {
    case Kind::local:
        if (verbose) {
            char peer[INET6_ADDRSTRLEN];
            peer_name(fd, peer, sizeof(peer));
            LOGI("connection from %s", peer);
        }
        stage_ = Stage::socks_method;
        update_interest();
        return Flow::proceed;
    case Kind::redir: {
        sockaddr_storage dest{};
        if (!original_destination(fd, cfg.tproxy, dest)) {
            ERROR("getdestaddr");
            return close();
        }
        target_header_len_ = encode_socks_addr(reinterpret_cast<sockaddr *>(&dest), target_header_.data());
        if (target_header_len_ == 0) {
            return close();
        }
        break;
    }
    case Kind::tunnel:
        std::memcpy(target_header_.data(), cfg.tunnel_target.data(), cfg.tunnel_target_len);
        target_header_len_ = cfg.tunnel_target_len;
        break;
    case Kind::server: {
        if (!dec_.init(*relay_->method_, false, nullptr) || !enc_.init(*relay_->method_, false, &dec_)) {
            return close();
        }
        stage_ = Stage::header;
        update_interest();
        return Flow::proceed;
    }
    }
    // ss-tunnel and ss-redir: the target is known; with fast open, wait a
    // moment so the first payload can ride in the SYN.
    upstream_addr_ = relay_->pick_remote();
    if (cfg.fast_open) {
        stage_ = Stage::delay;
        relay_->set_deadline(*this, Timed::delay);
        update_interest();
        return Flow::proceed;
    }
    return start_upstream(reinterpret_cast<const sockaddr *>(&upstream_addr_), false);
}

Flow Connection::on_client(int events) noexcept
{
    switch (stage_) {
    case Stage::socks_method:
    case Stage::socks_request:
        return socks_input();
    case Stage::delay:
        return delay_input();
    case Stage::udp_assoc:
    case Stage::stopped: {
        // Read and drop until the client goes away (or the timeout).
        for (int i = 0; i < kPumpRounds; ++i) {
            auto r = recv_some(client_.fd(), relay_->scratch_);
            if (!r) {
                if (r.error().code == Errc::again) {
                    return Flow::proceed;
                }
                return close();
            }
            if (relay_->config_.tx != nullptr) {
                *relay_->config_.tx += *r;
            }
        }
        return Flow::proceed;
    }
    case Stage::header: {
        Pull p = pull(client_.fd(), true, to_upstream_, relay_->config_.tx);
        switch (p) {
        case Pull::data:
            return server_header();
        case Pull::nothing:
        case Pull::again:
            return Flow::proceed;
        case Pull::eof:
        case Pull::error:
            return close();
        }
        return Flow::proceed;
    }
    case Stage::stream:
        if ((events & event::writable) && pump_to_client() == Flow::closed) {
            return Flow::closed;
        }
        if ((events & (event::readable | event::failed)) && pump_to_upstream() == Flow::closed) {
            return Flow::closed;
        }
        update_interest();
        return Flow::proceed;
    case Stage::acl_resolve:
    case Stage::resolving:
    case Stage::connecting:
        return Flow::proceed; // not reading the client meanwhile
    }
    return Flow::proceed;
}

Flow Connection::on_upstream(int events) noexcept
{
    if (stage_ == Stage::connecting) {
        if (!is_connected(upstream_.fd())) {
            if (verbose || client_kind()) {
                ERROR("getpeername");
            }
            return close();
        }
        return connected();
    }
    if (stage_ != Stage::stream) {
        return Flow::proceed;
    }
    if ((events & event::writable) && pump_to_upstream() == Flow::closed) {
        return Flow::closed;
    }
    if ((events & (event::readable | event::failed)) && pump_to_client() == Flow::closed) {
        return Flow::closed;
    }
    update_interest();
    return Flow::proceed;
}

void Connection::on_deadline() noexcept
{
    // Only the first-payload delay ends anywhere but in a close.
    if (stage_ == Stage::delay) {
        (void)start_upstream(reinterpret_cast<const sockaddr *>(&upstream_addr_), direct_);
    }
}

void Connection::on_resolved(const sockaddr *address) noexcept
{
    if (stage_ == Stage::acl_resolve) {
        dns_done_ = true;
        dns_ok_   = address != nullptr;
        if (address != nullptr) {
            std::memcpy(&dns_answer_, address, sockaddr_size(address));
        }
        (void)socks_route();
        return;
    }
    if (stage_ == Stage::resolving) {
        if (address == nullptr) {
            LOGE("unable to resolve %s", target_.host);
            (void)close();
            return;
        }
        if (verbose) {
            LOGI("successfully resolved %s", target_.host);
        }
        (void)server_connect(address);
    }
}

// ----------------------------------------------------------- ss-local

Flow Connection::socks_input() noexcept
{
    auto room = bytes_of(handshake_.writable());
    if (room.empty()) {
        return close(); // no SOCKS5 message is this long
    }
    auto r = recv_some(client_.fd(), room);
    if (!r) {
        return r.error().code == Errc::again ? Flow::proceed : close();
    }
    (void)handshake_.commit(*r);

    if (stage_ == Stage::socks_method) {
        auto in = bytes_of(handshake_.readable());
        if (in[0] != kSocksVersion) {
            return close();
        }
        if (in.size() < 2 || in.size() < 2U + in[1]) {
            return Flow::proceed;
        }
        std::uint8_t reply[2] = { kSocksVersion, 0xFF };
        for (std::size_t i = 0; i < in[1]; ++i) {
            if (in[2 + i] == 0x00) {
                reply[1] = 0x00; // no authentication
                break;
            }
        }
        send_reply(client_.fd(), reply, sizeof(reply));
        if (reply[1] != 0x00) {
            return close();
        }
        (void)handshake_.consume(2U + in[1]);
        stage_ = Stage::socks_request;
        if (handshake_.empty()) {
            return Flow::proceed;
        }
    }
    return socks_request();
}

Flow Connection::socks_request() noexcept
{
    auto in = bytes_of(handshake_.readable());
    if (in.size() < 4) {
        return Flow::proceed;
    }
    constexpr std::uint8_t kCmdConnect = 1, kCmdUdp = 3;
    if (in[1] == kCmdUdp) {
        if (verbose) {
            LOGI("udp assc request accepted");
        }
        sockaddr_storage local{};
        socklen_t len = sizeof(local);
        std::uint8_t reply[3 + kMaxSocksAddr] = { kSocksVersion, 0, 0 };
        std::size_t n = 0;
        if (getsockname(client_.fd(), reinterpret_cast<sockaddr *>(&local), &len) == 0) {
            n = encode_socks_addr(reinterpret_cast<sockaddr *>(&local), reply + 3);
        }
        if (n == 0) {
            reply[1] = 5; // connection refused
            send_reply(client_.fd(), reply, 3);
            return close();
        }
        send_reply(client_.fd(), reply, 3 + n);
        handshake_.clear();
        stage_ = Stage::udp_assoc;
        update_interest();
        return Flow::proceed;
    }
    if (in[1] != kCmdConnect) {
        LOGE("unsupported command: %d", in[1]);
        std::uint8_t reply[4] = { kSocksVersion, 7, 0, 1 }; // command not supported
        send_reply(client_.fd(), reply, sizeof(reply));
        return close();
    }
    std::uint8_t atyp = in[3];
    if (atyp != 1 && atyp != 3 && atyp != 4) {
        LOGE("unsupported addrtype: %d", atyp);
        std::uint8_t reply[4] = { kSocksVersion, 8, 0, 1 }; // address type not supported
        send_reply(client_.fd(), reply, sizeof(reply));
        return close();
    }
    ParseResult pr = parse_socks_addr(in.subspan(3), target_);
    if (pr == ParseResult::need_more) {
        return Flow::proceed;
    }
    if (pr == ParseResult::invalid) {
        return close();
    }
    std::memcpy(target_header_.data(), in.data() + 3, target_.length);
    target_header_len_ = target_.length;
    (void)handshake_.consume(3 + target_.length); // what remains is the first payload
    if (verbose) {
        if (target_.type == 4) {
            LOGI("connect to [%s]:%u", target_.host, target_.port);
        } else {
            LOGI("connect to %s:%u", target_.host, target_.port);
        }
    }
    return socks_route();
}

Flow Connection::socks_route() noexcept
{
    const TcpConfig &cfg = relay_->config_;
    // An ACL on host names may need the address before deciding.
    if (cfg.acl && target_.type == 3 && !dns_done_ && !cfg.vpn && cfg.acl_hooks.match_host(target_.host) >= 0) {
        stage_ = Stage::acl_resolve;
        update_interest();
        if (relay_->resolve(*this, target_.host, htons(target_.port))) {
            return Flow::proceed;
        }
        dns_done_ = true; // cannot ask: decide without the address
    }

    // The reply goes out before the upstream is connected, as in the C
    // implementation (clients send their first bytes sooner).
    std::uint8_t reply[10] = { kSocksVersion, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    send_reply(client_.fd(), reply, sizeof(reply));

    bool bypass = false;
    sockaddr_storage direct{};
    bool have_direct = false;
    if (cfg.acl && !(cfg.vpn && target_.port == 53)) {
        int host_match = target_.type == 3 ? cfg.acl_hooks.match_host(target_.host) : 0;
        if (host_match > 0) {
            bypass = true;
        } else if (host_match == 0) {
            char ip[INET6_ADDRSTRLEN] = {};
            bool known = false;
            if (target_.type == 3) {
                if (dns_ok_ && !cfg.vpn) {
                    direct      = dns_answer_;
                    have_direct = true;
                    const void *raw = direct.ss_family == AF_INET
                                          ? static_cast<const void *>(&reinterpret_cast<sockaddr_in *>(&direct)->sin_addr)
                                          : static_cast<const void *>(&reinterpret_cast<sockaddr_in6 *>(&direct)->sin6_addr);
                    known = ss_inet_ntop(direct.ss_family, raw, ip, sizeof(ip)) != nullptr;
                }
            } else {
                // A literal address: it fits, but copy at most sizeof(ip) - 1 bytes.
                std::size_t n = strnlen(target_.host, sizeof(ip) - 1);
                std::memcpy(ip, target_.host, n);
                ip[n] = '\0';
                direct      = target_.ip;
                have_direct = true;
                known       = true;
            }
            if (known) {
                int ip_match = cfg.acl_hooks.match_host(ip);
                if (cfg.acl_hooks.mode() == BLACK_LIST) {
                    bypass = ip_match > 0;
                } else {
                    bypass = ip_match >= 0;
                }
            }
        }
        if (bypass && !have_direct) {
            if (target_.type == 3 && dns_ok_ && !cfg.vpn) {
                direct      = dns_answer_;
                have_direct = true;
            } else {
                bypass = false; // nowhere to go directly
            }
        }
        if (bypass && verbose) {
            LOGI("bypass %s:%u", target_.host, target_.port);
        }
    }

    if (bypass && have_direct) {
        upstream_addr_ = direct;
        direct_        = true;
    } else {
        upstream_addr_ = relay_->pick_remote();
        direct_        = false;
    }
    if (!handshake_.empty()) {
        return start_upstream(reinterpret_cast<const sockaddr *>(&upstream_addr_), direct_);
    }
    // No payload with the request: give the client a moment to send some,
    // so it can travel with the address (and in the SYN with fast open).
    stage_ = Stage::delay;
    relay_->set_deadline(*this, Timed::delay);
    update_interest();
    return Flow::proceed;
}

Flow Connection::delay_input() noexcept
{
    auto room = bytes_of(handshake_.writable());
    if (!room.empty()) {
        auto r = recv_some(client_.fd(), room);
        if (!r) {
            return r.error().code == Errc::again ? Flow::proceed : close();
        }
        (void)handshake_.commit(*r);
    }
    relay_->clear_deadline(*this);
    return start_upstream(reinterpret_cast<const sockaddr *>(&upstream_addr_), direct_);
}

Flow Connection::start_upstream(const sockaddr *target, bool direct) noexcept
{
    TcpConfig &cfg = relay_->config_;
    direct_        = direct;
    if (!enc_.init(*relay_->method_, direct, nullptr, cfg.printable_salt && !direct)
        || !dec_.init(*relay_->method_, direct, &enc_)) {
        LOGE("invalid password or cipher");
        return close();
    }
    // The first write carries the target address and whatever the client
    // has sent so far.
    std::size_t n = 0;
    if (!direct) {
        std::memcpy(relay_->scratch_.data(), target_header_.data(), target_header_len_);
        n = target_header_len_;
    }
    auto pending = bytes_of(handshake_.readable());
    if (!pending.empty()) {
        std::memcpy(relay_->scratch_.data() + n, pending.data(), pending.size());
        n += pending.size();
    }
    handshake_.clear();
    to_upstream_.clear();
    if (n != 0) {
        auto w = enc_.seal({ relay_->scratch_.data(), n }, bytes_of(to_upstream_.writable()));
        if (!w) {
            LOGE("invalid password or cipher");
            return close();
        }
        (void)to_upstream_.commit(*w);
    }

    bool protect        = cfg.vpn && !loopback_v4(target);
    SocketTuning tuning = cfg.upstream;
    if (tos_ >= 0) {
        tuning.tos = tos_;
    }
    auto fd             = open_upstream(target->sa_family, tuning, protect);
    cfg.upstream.mptcp  = tuning.mptcp; // remember the option that worked
    if (!fd) {
        return close();
    }
    if (!upstream_.open(*relay_->loop_, *this, *fd)) {
        ss_socket_close(*fd);
        return close();
    }
    if (verbose) {
        char host[INET6_ADDRSTRLEN] = {};
        const void *raw = target->sa_family == AF_INET
                              ? static_cast<const void *>(&reinterpret_cast<const sockaddr_in *>(target)->sin_addr)
                              : static_cast<const void *>(&reinterpret_cast<const sockaddr_in6 *>(target)->sin6_addr);
        ss_inet_ntop(target->sa_family, raw, host, sizeof(host));
        LOGI("remote: %s", host);
    }
    bool fast = cfg.fast_open && !direct;
    auto sent = start_connect(*fd, target, bytes_of(to_upstream_.readable()), fast);
    if (!sent && sent.error().code == Errc::invalid) {
        LOGE("fast open is not supported on this platform");
        cfg.fast_open = false;
        sent          = start_connect(*fd, target, {}, false);
    }
    if (!sent) {
        ERROR("connect");
        return close();
    }
    (void)to_upstream_.consume(*sent);
    stage_ = Stage::connecting;
    relay_->set_deadline(*this, Timed::connect);
    update_interest();
    return Flow::proceed;
}

// ---------------------------------------------------------- ss-server

void Connection::server_reject(const char *reason) noexcept
{
    if (relay_->config_.report_failure != nullptr) {
        relay_->config_.report_failure(client_.fd(), reason);
    }
    stage_ = Stage::stopped;
    to_upstream_.clear();
    if (upstream_.is_open()) {
        upstream_.close(closer_);
    }
    update_interest();
}

Flow Connection::server_header() noexcept
{
    const TcpConfig &cfg = relay_->config_;
    auto in              = bytes_of(to_upstream_.readable());
    ParseResult pr       = parse_socks_addr(in, target_);
    if (pr == ParseResult::need_more) {
        if (in.size() > kMaxSocksAddr) {
            server_reject("invalid request length");
        }
        return Flow::proceed;
    }
    if (pr == ParseResult::invalid) {
        server_reject("invalid address type");
        return Flow::proceed;
    }
    (void)to_upstream_.consume(target_.length); // the rest is the first payload
    bool is_name = target_.type == 3;
    if (is_name) {
        // A literal address sent as a name.
        in_addr v4{};
        in6_addr v6{};
        if (inet_pton(AF_INET, target_.host, &v4) == 1) {
            auto *sa       = reinterpret_cast<sockaddr_in *>(&target_.ip);
            sa->sin_family = AF_INET;
            sa->sin_addr   = v4;
            sa->sin_port   = htons(target_.port);
            is_name        = false;
        } else if (inet_pton(AF_INET6, target_.host, &v6) == 1) {
            auto *sa        = reinterpret_cast<sockaddr_in6 *>(&target_.ip);
            sa->sin6_family = AF_INET6;
            sa->sin6_addr   = v6;
            sa->sin6_port   = htons(target_.port);
            is_name         = false;
        } else {
            if (cfg.acl && cfg.acl_hooks.outbound_blocked(target_.host) == 1) {
                if (verbose) {
                    LOGI("outbound blocked %s", target_.host);
                }
                return close();
            }
            if (!validate_hostname(target_.host, static_cast<int>(std::strlen(target_.host)))) {
                server_reject("invalid host name");
                return Flow::proceed;
            }
        }
    }
    if (verbose) {
        if (target_.type == 4) {
            LOGI("[%s] connect to [%s]:%u", cfg.label, target_.host, target_.port);
        } else {
            LOGI("[%s] connect to %s:%u", cfg.label, target_.host, target_.port);
        }
    }
    if (!is_name) {
        return server_connect(reinterpret_cast<const sockaddr *>(&target_.ip));
    }
    stage_ = Stage::resolving;
    update_interest();
    if (!relay_->resolve(*this, target_.host, htons(target_.port))) {
        LOGE("unable to resolve %s: too many queries", target_.host);
        return close();
    }
    return Flow::proceed;
}

Flow Connection::server_connect(const sockaddr *target) noexcept
{
    TcpConfig &cfg = relay_->config_;
    if (cfg.acl) {
        char ip[INET6_ADDRSTRLEN] = {};
        const void *raw = target->sa_family == AF_INET
                              ? static_cast<const void *>(&reinterpret_cast<const sockaddr_in *>(target)->sin_addr)
                              : static_cast<const void *>(&reinterpret_cast<const sockaddr_in6 *>(target)->sin6_addr);
        ss_inet_ntop(target->sa_family, raw, ip, sizeof(ip));
        if (cfg.acl_hooks.outbound_blocked(ip) == 1) {
            if (verbose) {
                LOGI("outbound blocked %s", ip);
            }
            return close();
        }
    }
    auto fd = open_upstream(target->sa_family, cfg.upstream, false);
    if (!fd) {
        LOGE("connect error");
        return close();
    }
    if (!upstream_.open(*relay_->loop_, *this, *fd)) {
        ss_socket_close(*fd);
        return close();
    }
    auto sent = start_connect(*fd, target, bytes_of(to_upstream_.readable()), cfg.fast_open);
    if (!sent && sent.error().code == Errc::invalid) {
        LOGE("fast open is not supported on this platform");
        cfg.fast_open = false;
        sent          = start_connect(*fd, target, {}, false);
    }
    if (!sent) {
        ERROR("connect");
        return close();
    }
    (void)to_upstream_.consume(*sent);
    stage_ = Stage::connecting;
    update_interest();
    return Flow::proceed;
}

// -------------------------------------------------------------- stream

Flow Connection::connected() noexcept
{
    if (client_kind()) {
        relay_->set_deadline(*this, Timed::idle); // replaces the connect deadline
    }
    stage_ = Stage::stream;
    if (pump_to_upstream() == Flow::closed) {
        return Flow::closed;
    }
    update_interest();
    return Flow::proceed;
}

Connection::Pull Connection::flush(ss_socket_t fd, LeasedBuffer &src) noexcept
{
    auto s = send_some(fd, bytes_of(src.readable()));
    if (!s) {
        if (s.error().code == Errc::again) {
            return Pull::again;
        }
        if (verbose) {
            ERROR("send");
        }
        return Pull::error;
    }
    (void)src.consume(*s);
    return src.empty() ? Pull::data : Pull::again;
}

Connection::Pull Connection::pull(ss_socket_t fd, bool decode, LeasedBuffer &dst, std::uint64_t *counter) noexcept
{
    Pull p = pull_into(fd, decode, dst, counter);
    dst.trim(); // nothing arrived: do not hold on to the lease
    return p;
}

Connection::Pull Connection::pull_into(ss_socket_t fd, bool decode, LeasedBuffer &dst,
                                       std::uint64_t *counter) noexcept
{
    dst.compact();
    auto out = bytes_of(dst.writable());
    if (out.empty() && !dst.leased()) {
        return Pull::error; // the pool has a buffer for every direction, so this cannot happen
    }
    std::size_t limit;
    if (decode) {
        // Hand out plaintext the decoder kept back before reading more.
        auto step = dec_.decrypt({}, out);
        if (!step) {
            return Pull::error;
        }
        if (step->produced != 0) {
            (void)dst.commit(step->produced);
            return Pull::data;
        }
        limit = std::min({ static_cast<std::size_t>(SOCKET_BUF_SIZE), dec_.accept_limit(), out.size() });
    } else {
        limit = std::min<std::size_t>(SOCKET_BUF_SIZE, out.size() - Method::kMaxOverhead);
    }
    if (limit == 0) {
        return Pull::again;
    }
    auto r = recv_some(fd, { relay_->scratch_.data(), limit });
    if (!r) {
        switch (r.error().code) {
        case Errc::again:
            return Pull::again;
        case Errc::closed:
            return Pull::eof;
        default:
            if (verbose) {
                ERROR("recv");
            }
            return Pull::error;
        }
    }
    const TcpConfig &cfg = relay_->config_;
    if (counter != nullptr) {
        *counter += *r;
        if (cfg.on_traffic != nullptr) {
            cfg.on_traffic();
        }
    }
    if (stage_ == Stage::stream) {
        relay_->set_deadline(*this, Timed::idle);
    }
    std::span<const std::uint8_t> in(relay_->scratch_.data(), *r);
    if (decode) {
        auto step = dec_.decrypt(in, out);
        if (!step || step->consumed != in.size()) {
            if (cfg.kind == Kind::server) {
                server_reject("authentication error");
                return Pull::nothing;
            }
            LOGE("invalid password or cipher");
            return Pull::error;
        }
        (void)dst.commit(step->produced);
        return step->produced != 0 ? Pull::data : Pull::nothing;
    }
    auto w = enc_.seal(in, out);
    if (!w) {
        LOGE("invalid password or cipher");
        return Pull::error;
    }
    (void)dst.commit(*w);
    return Pull::data;
}

Flow Connection::pump_to_upstream() noexcept
{
    const bool decode = !client_kind();
    for (int round = 0; round < kPumpRounds; ++round) {
        if (!to_upstream_.empty()) {
            Pull f = flush(upstream_.fd(), to_upstream_);
            if (f == Pull::error) {
                return close();
            }
            if (f == Pull::again) {
                return Flow::proceed;
            }
        }
        Pull p = pull(client_.fd(), decode, to_upstream_, relay_->config_.tx);
        if (stage_ == Stage::stopped) {
            return Flow::proceed;
        }
        switch (p) {
        case Pull::data:
        case Pull::nothing:
            continue;
        case Pull::again:
            return Flow::proceed;
        case Pull::eof:
        case Pull::error:
            return close();
        }
    }
    return Flow::proceed;
}

Flow Connection::pump_to_client() noexcept
{
    const bool decode = client_kind();
    for (int round = 0; round < kPumpRounds; ++round) {
        if (!to_client_.empty()) {
            Pull f = flush(client_.fd(), to_client_);
            if (f == Pull::error) {
                return close();
            }
            if (f == Pull::again) {
                return Flow::proceed;
            }
        }
        Pull p = pull(upstream_.fd(), decode, to_client_, relay_->config_.rx);
        if (p == Pull::data && relay_->config_.downstream != nullptr) {
            relay_->config_.downstream(&hook_state_, client_.fd(), upstream_.fd());
        }
        switch (p) {
        case Pull::data:
            if (!replied_) {
                // Disable TCP_NODELAY once the first response is on its way.
                replied_ = true;
                if (!relay_->config_.no_delay) {
                    set_nodelay(client_.fd(), false);
                    set_nodelay(upstream_.fd(), false);
                }
            }
            continue;
        case Pull::nothing:
            continue;
        case Pull::again:
            return Flow::proceed;
        case Pull::eof:
        case Pull::error:
            return close();
        }
    }
    return Flow::proceed;
}

void Connection::update_interest() noexcept
{
    int c = 0, u = 0;
    switch (stage_) {
    case Stage::socks_method:
    case Stage::socks_request:
    case Stage::udp_assoc:
    case Stage::delay:
    case Stage::header:
    case Stage::stopped:
        c = event::readable;
        break;
    case Stage::acl_resolve:
    case Stage::resolving:
        break;
    case Stage::connecting:
        u = event::writable;
        break;
    case Stage::stream:
        c = (to_upstream_.empty() ? event::readable : 0) | (to_client_.empty() ? 0 : event::writable);
        u = (to_client_.empty() ? event::readable : 0) | (to_upstream_.empty() ? 0 : event::writable);
        break;
    }
    if (client_.is_open() && !client_.is_closing()) {
        (void)client_.want(c);
    }
    if (upstream_.is_open() && !upstream_.is_closing()) {
        (void)upstream_.want(u);
    }
}

} // namespace ss::relay
