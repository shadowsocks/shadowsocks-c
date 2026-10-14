/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "relay/udp.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <memory>

#include <sodium.h>

#ifndef _WIN32
#include <netdb.h>
#include <sys/uio.h>
#endif

#include "jconf.h"
#include "utils.h"

extern "C" int verbose;

#ifndef SOL_IP
#define SOL_IP IPPROTO_IP
#endif
#ifndef SOL_IPV6
#define SOL_IPV6 IPPROTO_IPV6
#endif
#ifdef __linux__
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75
#endif
#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif
#ifndef IPV6_RECVORIGDSTADDR
#define IPV6_RECVORIGDSTADDR 74
#endif
#endif

namespace ss::relay {

using event::Flow;

namespace {

#ifdef __linux__
// musl's CMSG_NXTHDR compares a size_t with a ptrdiff_t.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
cmsghdr *next_cmsg(msghdr *msg, cmsghdr *c) noexcept
{
    return CMSG_NXTHDR(msg, c);
}
#pragma GCC diagnostic pop
#endif

constexpr int kQosTos             = 46 << 2; // DSCP EF, as udprelay.cpp
constexpr int kReceiveBurst       = 64;
constexpr std::uint64_t kTtl2022  = 600; // seconds an idle AEAD-2022 client session is kept
constexpr std::size_t kPacketHeader = 1 + 28 + 2 + 64; // as udprelay.h

void set_qos(ss_socket_t fd) noexcept
{
    int tos = kQosTos;
    if (ss_setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0 && ss_socket_error() != ENOPROTOOPT) {
        LOGE("setting ipv4 dscp failed: %d", ss_socket_error());
    }
#ifdef IPV6_TCLASS
    if (ss_setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos)) < 0 && ss_socket_error() != ENOPROTOOPT) {
        LOGE("setting ipv6 dscp failed: %d", ss_socket_error());
    }
#endif
}

void no_fragment(ss_socket_t fd) noexcept
{
#if defined(__linux__) && defined(IP_MTU_DISCOVER)
    int val = IP_PMTUDISC_DO;
    (void)ss_setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(val));
#else
    (void)fd;
#endif
}

bool valid_socket(ss_socket_t fd) noexcept
{
#ifdef _WIN32
    return fd != INVALID_SOCKET;
#else
    return fd >= 0;
#endif
}

std::uint64_t pack_ptr(void *p) noexcept
{
    return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(p));
}

void *unpack_ptr(std::uint64_t v) noexcept
{
    return reinterpret_cast<void *>(static_cast<std::uintptr_t>(v));
}

// ss-redir replies come from the original destination: a transparent
// socket bound to it, one per datagram as in the C relay.
void send_as(const sockaddr_storage &from, const sockaddr_storage &to, std::span<const std::uint8_t> data,
             bool reuse_port) noexcept
{
#ifdef __linux__
    sockaddr_storage src = from, dst = to;
    auto map = [](sockaddr_storage &a) {
        if (a.ss_family != AF_INET) {
            return;
        }
        sockaddr_in v4;
        std::memcpy(&v4, &a, sizeof(v4));
        sockaddr_in6 v6{};
        v6.sin6_family            = AF_INET6;
        v6.sin6_port              = v4.sin_port;
        v6.sin6_addr.s6_addr[10]  = 0xff;
        v6.sin6_addr.s6_addr[11]  = 0xff;
        std::memcpy(&v6.sin6_addr.s6_addr[12], &v4.sin_addr, 4);
        a = {};
        std::memcpy(&a, &v6, sizeof(v6));
    };
    map(src);
    map(dst);
    ss_socket_t fd = ss_socket(AF_INET6, SOCK_DGRAM, 0);
    if (!valid_socket(fd)) {
        ERROR("[udp] remote_recv_socket");
        return;
    }
    int opt = 1;
    if (ss_setsockopt(fd, SOL_IPV6, IPV6_TRANSPARENT, &opt, sizeof(opt))
        || ss_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        ERROR("[udp] remote_recv_setsockopt");
        ss_socket_close(fd);
        return;
    }
    if (reuse_port && set_reuseport(fd) != 0) {
        ERROR("[udp] remote_recv port_reuse");
    }
    set_qos(fd);
    if (bind(fd, reinterpret_cast<sockaddr *>(&src), sizeof(sockaddr_in6)) != 0) {
        ERROR("[udp] remote_recv_bind");
        ss_socket_close(fd);
        return;
    }
    if (sendto(fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr *>(&dst), sizeof(sockaddr_in6)) == -1
        && ss_socket_error() != EAGAIN && ss_socket_error() != EWOULDBLOCK) {
        ERROR("[udp] remote_recv_sendto");
    }
    ss_socket_close(fd);
#else
    (void)from;
    (void)to;
    (void)data;
    (void)reuse_port;
#endif
}

} // namespace

Result<ss_socket_t> open_udp_listener(const char *host, const char *port, bool transparent, bool reuse_port) noexcept
{
    addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG;
    hints.ai_protocol = IPPROTO_UDP;
    addrinfo *result  = nullptr;
    int s             = getaddrinfo(host, port, &hints, &result);
    if (s != 0 || result == nullptr) {
        LOGE("[udp] getaddrinfo: %s", gai_strerror(s));
        return fail(Errc::config);
    }
    // getaddrinfo(NULL, AI_PASSIVE) gives 0.0.0.0 then ::; the dual-stack
    // :: covers both, so prefer it.
    addrinfo *rp = result;
    if (host == nullptr) {
        for (addrinfo *p = result; p != nullptr; p = p->ai_next) {
            if (p->ai_family == AF_INET6) {
                rp = p;
                break;
            }
        }
    }
    ss_socket_t fd = static_cast<ss_socket_t>(-1);
    for (; rp != nullptr; rp = rp->ai_next) {
        fd = ss_socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (!valid_socket(fd)) {
            continue;
        }
        if (rp->ai_family == AF_INET6) {
            int v6only = host != nullptr ? 1 : 0;
            (void)ss_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
        }
        int opt = 1;
        (void)ss_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        set_nosigpipe(fd);
        if (reuse_port && set_reuseport(static_cast<int>(fd)) == 0) {
            LOGI("udp port reuse enabled");
        }
        set_qos(fd);
#ifdef __linux__
        if (transparent) {
            int sol    = rp->ai_family == AF_INET ? SOL_IP : SOL_IPV6;
            int flag_t = rp->ai_family == AF_INET ? IP_TRANSPARENT : IPV6_TRANSPARENT;
            int flag_r = rp->ai_family == AF_INET ? IP_RECVORIGDSTADDR : IPV6_RECVORIGDSTADDR;
            if (ss_setsockopt(fd, sol, flag_t, &opt, sizeof(opt))) {
                ERROR("[udp] setsockopt IP_TRANSPARENT");
                exit(EXIT_FAILURE);
            }
            if (ss_setsockopt(fd, sol, flag_r, &opt, sizeof(opt))) {
                FATAL("[udp] setsockopt IP_RECVORIGDSTADDR");
            }
        }
#else
        (void)transparent;
#endif
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
            break;
        }
        ERROR("[udp] bind");
        ss_socket_close(fd);
        fd = static_cast<ss_socket_t>(-1);
    }
    freeaddrinfo(result);
    if (!valid_socket(fd)) {
        return fail(Errc::io);
    }
    no_fragment(fd);
    return fd;
}

// ------------------------------------------------------------- sessions

void Shared2022::destroy(Shared2022 *self) noexcept
{
    UdpRelay *relay = self->relay_;
    relay->shared_pool_.adopt(self).reset();
}

void UdpSession::begin_close(CloseCompletion done) noexcept
{
    if (static_cast<ListNode<event::DeadlineTag> &>(*this).linked()) {
        event::DeadlineList<UdpSession>::remove(*this);
    }
    server2022_.reset();
    done_ = done;
    closer_.arm(CloseCompletion(
        [](void *self, std::uint32_t) {
            auto *s           = static_cast<UdpSession *>(self);
            CloseCompletion d = s->done_;
            d();
        },
        this, 0));
    socket_.close(closer_);
    closer_.seal();
}

Flow UdpSession::on_readable(int) noexcept
{
    relay_->reply(*this);
    return Flow::proceed;
}

// ---------------------------------------------------------------- relay

UdpRelay::~UdpRelay()
{
    sessions_.clear();
    shared_.clear();
}

Status UdpRelay::init(event::Loop &loop, Method &method, const UdpConfig &config, Resolver *resolver) noexcept
{
    if (loop_ != nullptr || config.max_sessions == 0) {
        return fail(Errc::invalid);
    }
    if (config.mtu > 0 && config.mtu <= static_cast<int>(kPacketHeader)) {
        LOGE("MTU must be greater than %d", static_cast<int>(kPacketHeader));
        return fail(Errc::config);
    }
    loop_     = &loop;
    method_   = &method;
    resolver_ = resolver;
    config_   = config;
    std::uint64_t seed = 0;
    randombytes_buf(&seed, sizeof(seed));
    // An evicted session keeps its pool slot until its socket's close
    // callback runs on a later loop iteration, so the pool needs room for
    // a table's worth of closing sessions next to the live ones.
    SS_TRY(pool_.reserve(2 * config.max_sessions));
    SS_TRY(sessions_.reserve(config.max_sessions, seed));
    if (config.kind == Kind::server) {
        if (method.psk() != nullptr) {
            // An entry evicted from shared_ stays alive while a relay
            // session still references it (at most one per session).
            SS_TRY(shared_pool_.reserve(config.max_sessions_2022 + config.max_sessions));
            SS_TRY(shared_.reserve(config.max_sessions_2022, seed ^ 0x9E3779B97F4A7C15ULL));
        }
        SS_TRY(pending_.reserve(config.max_pending_dns));
    }
    idle_.set_timeout(static_cast<std::uint64_t>(std::max(config.timeout_secs, MIN_UDP_TIMEOUT)) * 1000);
    SS_TRY(timer_.open(loop, *this));
    own_closed_ = false;
    return {};
}

Status UdpRelay::listen(ss_socket_t fd) noexcept
{
    if (listener_count_ == kMaxListeners || loop_ == nullptr) {
        return fail(Errc::exhausted);
    }
    SS_TRY(set_nonblocking(fd));
    Listener &l = listeners_[listener_count_];
    l.relay     = this;
    l.index     = static_cast<std::uint8_t>(listener_count_);
    SS_TRY(l.poll.open(*loop_, l, fd));
    ++listener_count_;
    return l.poll.want(event::readable);
}

Flow UdpRelay::Listener::on_ready(int) noexcept
{
    relay->receive(*this);
    return Flow::proceed;
}

std::uint64_t UdpRelay::now_secs() const noexcept
{
    return loop_->now() / 1000;
}

void UdpRelay::receive(Listener &listener) noexcept
{
    for (int i = 0; i < kReceiveBurst && !shutting_down_; ++i) {
        sockaddr_storage from{};
        sockaddr_storage original{};
        bool have_original = false;
        ssize_t r          = -1;
#ifdef __linux__
        if (config_.kind == Kind::redir) {
            char control[64] = {};
            iovec iov{ in_.data(), in_.size() };
            msghdr msg{};
            msg.msg_name       = &from;
            msg.msg_namelen    = sizeof(from);
            msg.msg_control    = control;
            msg.msg_controllen = sizeof(control);
            msg.msg_iov        = &iov;
            msg.msg_iovlen     = 1;
            r                  = recvmsg(listener.poll.fd(), &msg, 0);
            if (r >= 0) {
                for (cmsghdr *c = CMSG_FIRSTHDR(&msg); c != nullptr; c = next_cmsg(&msg, c)) {
                    if (c->cmsg_level == SOL_IP && c->cmsg_type == IP_RECVORIGDSTADDR) {
                        std::memcpy(&original, CMSG_DATA(c), sizeof(sockaddr_in));
                        original.ss_family = AF_INET;
                        have_original      = true;
                    } else if (c->cmsg_level == SOL_IPV6 && c->cmsg_type == IPV6_RECVORIGDSTADDR) {
                        std::memcpy(&original, CMSG_DATA(c), sizeof(sockaddr_in6));
                        original.ss_family = AF_INET6;
                        have_original      = true;
                    }
                }
            }
        } else
#endif
        {
            socklen_t len = sizeof(from);
            r = recvfrom(listener.poll.fd(), reinterpret_cast<char *>(in_.data()), in_.size(), 0,
                         reinterpret_cast<sockaddr *>(&from), &len);
        }
        if (r < 0) {
            int err = ss_socket_error();
            if (err != EAGAIN && err != EWOULDBLOCK && err != EINTR) {
                ERROR("[udp] server_recv_recvfrom");
            }
            return;
        }
        if (verbose) {
            LOGI("[udp] server receive a packet");
        }
        std::span<std::uint8_t> packet(in_.data(), static_cast<std::size_t>(r));
        if (config_.kind == Kind::server) {
            server_packet(listener, from, packet);
        } else if (config_.kind == Kind::redir) {
            if (!have_original) {
                LOGE("[udp] unable to get dest addr");
                continue;
            }
            client_packet(listener, from, packet, &original);
        } else {
            client_packet(listener, from, packet, nullptr);
        }
    }
}

Result<ss_socket_t> UdpRelay::open_upstream_socket(int family) noexcept
{
    ss_socket_t fd = ss_socket(family, SOCK_DGRAM, 0);
    if (!valid_socket(fd)) {
        ERROR("[udp] cannot create socket");
        return fail(Errc::io);
    }
    const sockaddr_storage *source = family == AF_INET ? config_.bind_v4 : config_.bind_v6;
    if (source != nullptr && source->ss_family == family) {
        if (bind_to_addr(const_cast<sockaddr_storage *>(source), static_cast<int>(fd)) == -1) {
            ERROR("bind_to_addr");
            ss_socket_close(fd);
            return fail(Errc::io);
        }
    } else {
        sockaddr_storage any{};
        any.ss_family = static_cast<decltype(any.ss_family)>(family);
        socklen_t len = family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
        if (bind(fd, reinterpret_cast<sockaddr *>(&any), len) != 0) {
            ERROR("[udp] cannot bind socket");
            ss_socket_close(fd);
            return fail(Errc::io);
        }
    }
    no_fragment(fd);
    (void)set_nonblocking(fd);
#ifdef SO_BROADCAST
    if (config_.kind == Kind::server) {
        int opt = 1;
        (void)ss_setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &opt, sizeof(opt));
    }
#endif
    set_nosigpipe(fd);
    set_qos(fd);
#ifdef SET_INTERFACE
    if (config_.iface != nullptr && setinterface(static_cast<int>(fd), config_.iface) == -1) {
        ERROR("setinterface");
    }
#endif
    if (config_.vpn && config_.protect != nullptr && config_.protect(static_cast<int>(fd)) == -1) {
        ERROR("protect_socket");
        ss_socket_close(fd);
        return fail(Errc::io);
    }
    return fd;
}

UdpSession *UdpRelay::session_for(std::uint8_t listener, const sockaddr_storage &client, int family) noexcept
{
    std::array<std::byte, sizeof(int) + sizeof(sockaddr_storage)> raw{};
    std::memcpy(raw.data(), &family, sizeof(int));
    std::memcpy(raw.data() + sizeof(int), &client, sizeof(sockaddr_storage));
    auto key = Key::from(raw);
    if (!key) {
        return nullptr;
    }
    if (PoolPtr<UdpSession> *found = sessions_.find(*key)) {
        return found->get();
    }
    if (verbose) {
        LOGI("[%s] [udp] cache miss", config_.label);
    }
    if (sessions_.full()) {
        (void)sessions_.pop_oldest(); // closes the least recently used session
    }
    auto fd = open_upstream_socket(family);
    if (!fd) {
        return nullptr;
    }
    auto session = pool_.acquire(*this, listener);
    if (!session) {
        ss_socket_close(*fd);
        return nullptr;
    }
    UdpSession &s = **session;
    if (!s.socket_.open(*loop_, s, *fd)) {
        ss_socket_close(*fd);
        return nullptr;
    }
    s.client_  = client;
    s.key_     = raw;
    s.key_len_ = static_cast<std::uint8_t>(raw.size());
    (void)s.socket_.want(event::readable);
    auto inserted = sessions_.emplace(*key, std::move(*session));
    if (!inserted) {
        return nullptr; // the PoolPtr went out of scope: closed again
    }
    return &s;
}

void UdpRelay::expire(UdpSession &session) noexcept
{
    if (verbose) {
        LOGI("[udp] connection timeout");
    }
    if (auto key = Key::from(session.key_)) {
        (void)sessions_.take(*key); // the PoolPtr dies here and closes the session
    }
}

void UdpRelay::client_packet(Listener &listener, const sockaddr_storage &from, std::span<std::uint8_t> packet,
                             const sockaddr_storage *original_dst) noexcept
{
    // Build [target address][payload] in out_.
    std::size_t n = 0;
    if (config_.kind == Kind::local) {
#ifdef __ANDROID__
        if (config_.tx != nullptr) {
            *config_.tx += packet.size();
        }
#endif
        if (packet.size() < 3) {
            LOGE("[udp] invalid SOCKS5 UDP header");
            return;
        }
        if (packet[2] != 0) {
            LOGE("[udp] drop a message since frag is not 0, but %d", packet[2]);
            return;
        }
        SocksTarget target;
        if (parse_socks_addr(packet.subspan(3), target) != ParseResult::complete) {
            LOGE("[udp] invalid header");
            return;
        }
        n = packet.size() - 3;
        std::memcpy(out_.data(), packet.data() + 3, n);
    } else {
        std::size_t header = 0;
        if (config_.kind == Kind::tunnel) {
            std::memcpy(out_.data(), config_.tunnel_target.data(), config_.tunnel_target_len);
            header = config_.tunnel_target_len;
        } else {
            header = encode_socks_addr(reinterpret_cast<const sockaddr *>(original_dst), out_.data());
            if (header == 0) {
                LOGE("[udp] failed to parse tproxy addr");
                return;
            }
        }
        std::memcpy(out_.data() + header, packet.data(), packet.size());
        n = header + packet.size();
    }
    UdpSession *session = session_for(listener.index, from, config_.remote.ss_family);
    if (session == nullptr) {
        return;
    }
    idle_.touch(*session, loop_->now());
    schedule();

    // Seal into in_ (the received packet is no longer needed).
    std::span<const std::uint8_t> plain(out_.data(), n);
    Result<std::size_t> sealed = fail(Errc::config);
    if (const crypto::MasterKey *master = method_->aead()) {
        sealed = crypto::aead_udp_seal(*master, plain, in_, crypto::ReplayFilter::ppbloom());
    } else if (const crypto::Psk *psk = method_->psk()) {
        if (n + crypto::udp2022_overhead(*psk, Role::client) <= in_.size()) {
            sealed = crypto::udp2022_seal(*psk, Role::client, session->client2022_, plain, in_);
        }
    }
    if (!sealed) {
        return; // drop the packet silently
    }
    const sockaddr *remote = reinterpret_cast<const sockaddr *>(&config_.remote);
    if (sendto(session->socket_.fd(), reinterpret_cast<const char *>(in_.data()), *sealed, 0, remote,
               sockaddr_size(remote))
        == -1) {
        ERROR("[udp] server_recv_sendto");
    }
}

RefPtr<Shared2022> UdpRelay::shared_for(const std::array<std::uint8_t, crypto::kSessionIdLen> &id) noexcept
{
    auto key = FixedKey<crypto::kSessionIdLen>::from(std::as_bytes(std::span(id)));
    if (!key) {
        return nullptr;
    }
    std::uint64_t now = now_secs();
    if (RefPtr<Shared2022> *found = shared_.find(*key)) {
        (*found)->last_used = now;
        return *found;
    }
    // Forget client sessions idle for longer than the TTL (oldest first).
    while (RefPtr<Shared2022> *oldest = shared_.oldest()) {
        if ((*oldest)->last_used + kTtl2022 > now) {
            break;
        }
        (void)shared_.pop_oldest();
    }
    if (shared_.full()) {
        (void)shared_.pop_oldest(); // relay sessions still using it keep it alive
    }
    auto slot = shared_pool_.acquire(*this);
    if (!slot) {
        return nullptr;
    }
    Shared2022 *raw = slot->release(); // the references own it from here
    raw->last_used  = now;
    RefPtr<Shared2022> ref(raw);
    if (!shared_.emplace(*key, ref)) {
        return nullptr;
    }
    return ref;
}

void UdpRelay::server_packet(Listener &listener, const sockaddr_storage &from, std::span<std::uint8_t> packet) noexcept
{
    if (config_.tx != nullptr) {
        *config_.tx += packet.size();
    }
    Result<std::size_t> opened = fail(Errc::config);
    RefPtr<Shared2022> shared;
    if (const crypto::MasterKey *master = method_->aead()) {
        opened = crypto::aead_udp_open(*master, packet, out_, crypto::ReplayFilter::ppbloom());
    } else if (const crypto::Psk *psk = method_->psk()) {
        auto pkt = crypto::udp2022_decrypt(*psk, packet, out_);
        if (pkt) {
            shared = shared_for(pkt->session_id);
            if (shared) {
                opened = crypto::udp2022_accept(Role::server, shared->state, *pkt, out_,
                                                static_cast<std::uint64_t>(std::time(nullptr)));
            }
        }
    }
    if (!opened) {
        char peer[INET6_ADDRSTRLEN] = {};
        const void *raw = from.ss_family == AF_INET
                              ? static_cast<const void *>(&reinterpret_cast<const sockaddr_in *>(&from)->sin_addr)
                              : static_cast<const void *>(&reinterpret_cast<const sockaddr_in6 *>(&from)->sin6_addr);
        ss_inet_ntop(from.ss_family, raw, peer, sizeof(peer));
        LOGE("failed to handshake with %s: %s", peer, "suspicious UDP packet");
        return;
    }
    std::span<const std::uint8_t> plain(out_.data(), *opened);
    SocksTarget target;
    if (parse_socks_addr(plain, target) != ParseResult::complete) {
        LOGE("[udp] error in parse header");
        return;
    }
    auto payload = plain.subspan(target.length);
    if (target.type == 3) {
        in_addr v4{};
        in6_addr v6{};
        if (inet_pton(AF_INET, target.host, &v4) == 1) {
            auto *sa       = reinterpret_cast<sockaddr_in *>(&target.ip);
            sa->sin_family = AF_INET;
            sa->sin_addr   = v4;
            sa->sin_port   = htons(target.port);
        } else if (inet_pton(AF_INET6, target.host, &v6) == 1) {
            auto *sa        = reinterpret_cast<sockaddr_in6 *>(&target.ip);
            sa->sin6_family = AF_INET6;
            sa->sin6_addr   = v6;
            sa->sin6_port   = htons(target.port);
        } else {
            if (!validate_hostname(target.host, static_cast<int>(std::strlen(target.host)))) {
                LOGE("[udp] invalid host name");
                return;
            }
            // Hold the payload until the name resolves.
            auto pending = pending_.acquire();
            if (!pending || resolver_ == nullptr) {
                LOGE("[udp] too many pending DNS queries");
                return;
            }
            Pending &p = **pending;
            p.listener = listener.index;
            p.client   = from;
            p.session  = std::move(shared);
            p.len      = payload.size();
            std::memcpy(p.payload.data(), payload.data(), payload.size());
            ResolveCallback cb;
            cb.fn    = &UdpRelay::resolved;
            cb.ctx   = this;
            cb.token = pack_ptr(pending->get());
            Pending *raw = pending->release();
            if (!resolver_->resolve(target.host, htons(target.port), cb)) {
                (void)pending_.adopt(raw); // dropped again
                LOGE("[udp] unable to resolve %s", target.host);
            }
            return;
        }
    }
    server_forward(listener.index, from, reinterpret_cast<const sockaddr *>(&target.ip), std::move(shared), payload);
}

void UdpRelay::resolved(const ResolveCallback &cb, const sockaddr *address) noexcept
{
    auto *self = static_cast<UdpRelay *>(cb.ctx);
    PoolPtr<Pending> p = self->pending_.adopt(static_cast<Pending *>(unpack_ptr(cb.token)));
    if (address == nullptr) {
        LOGE("[udp] unable to resolve");
        return;
    }
    if (self->shutting_down_) {
        return;
    }
    self->server_forward(p->listener, p->client, address, std::move(p->session), { p->payload.data(), p->len });
}

void UdpRelay::server_forward(std::uint8_t listener, const sockaddr_storage &client, const sockaddr *target,
                              RefPtr<Shared2022> shared, std::span<const std::uint8_t> payload) noexcept
{
    UdpSession *session = session_for(listener, client, target->sa_family);
    if (session == nullptr) {
        return;
    }
    if (shared) {
        session->server2022_ = std::move(shared); // replies use the latest validated session
    }
    idle_.touch(*session, loop_->now());
    schedule();
    if (sendto(session->socket_.fd(), reinterpret_cast<const char *>(payload.data()), payload.size(), 0, target,
               sockaddr_size(target))
        == -1) {
        ERROR("[udp] sendto_remote");
    }
}

void UdpRelay::reply(UdpSession &session) noexcept
{
    for (int i = 0; i < kReceiveBurst; ++i) {
        sockaddr_storage from{};
        socklen_t len = sizeof(from);
        ssize_t r     = recvfrom(session.socket_.fd(), reinterpret_cast<char *>(in_.data()), in_.size(), 0,
                                 reinterpret_cast<sockaddr *>(&from), &len);
        if (r < 0) {
            int err = ss_socket_error();
            if (err != EAGAIN && err != EWOULDBLOCK && err != EINTR) {
                ERROR("[udp] remote_recv_recvfrom");
            }
            return;
        }
        if (verbose) {
            LOGI("[udp] remote receive a packet");
        }
        std::span<std::uint8_t> packet(in_.data(), static_cast<std::size_t>(r));
        const Listener &listener = listeners_[session.listener_];
        std::span<const std::uint8_t> datagram;
        sockaddr_storage reply_from{};

        if (config_.kind == Kind::server) {
            if (config_.rx != nullptr) {
                *config_.rx += packet.size();
            }
            // [source address][payload], sealed back to the client.
            std::size_t header = encode_socks_addr(reinterpret_cast<const sockaddr *>(&from), out_.data());
            if (header == 0) {
                continue;
            }
            std::memcpy(out_.data() + header, packet.data(), packet.size());
            std::span<const std::uint8_t> plain(out_.data(), header + packet.size());
            Result<std::size_t> sealed = fail(Errc::config);
            if (const crypto::MasterKey *master = method_->aead()) {
                sealed = crypto::aead_udp_seal(*master, plain, in_, crypto::ReplayFilter::ppbloom());
            } else if (const crypto::Psk *psk = method_->psk()) {
                if (session.server2022_ && plain.size() + crypto::udp2022_overhead(*psk, Role::server) <= in_.size()) {
                    sealed = crypto::udp2022_seal(*psk, Role::server, session.server2022_->state, plain, in_);
                }
            }
            if (!sealed) {
                continue;
            }
            datagram = { in_.data(), *sealed };
        } else {
            Result<std::size_t> opened = fail(Errc::config);
            if (const crypto::MasterKey *master = method_->aead()) {
                opened = crypto::aead_udp_open(*master, packet, out_, crypto::ReplayFilter::ppbloom());
            } else if (const crypto::Psk *psk = method_->psk()) {
                auto pkt = crypto::udp2022_decrypt(*psk, packet, out_);
                if (pkt) {
                    opened = crypto::udp2022_accept(Role::client, session.client2022_, *pkt, out_,
                                                    static_cast<std::uint64_t>(std::time(nullptr)));
                }
            }
            if (!opened) {
                LOGE("failed to handshake with the server: %s", "suspicious UDP packet");
                continue;
            }
            SocksTarget target;
            if (parse_socks_addr({ out_.data(), *opened }, target) != ParseResult::complete) {
                LOGE("[udp] error in parse header");
                continue;
            }
            if (config_.kind == Kind::local) {
#ifdef __ANDROID__
                if (config_.rx != nullptr) {
                    *config_.rx += *opened;
                }
                if (config_.on_traffic != nullptr) {
                    config_.on_traffic();
                }
#endif
                // SOCKS5 UDP reply: RSV(2) FRAG(1) then address and payload.
                std::memmove(out_.data() + 3, out_.data(), *opened);
                out_[0] = out_[1] = out_[2] = 0;
                datagram                    = { out_.data(), *opened + 3 };
            } else {
                datagram = { out_.data() + target.length, *opened - target.length };
                if (config_.kind == Kind::redir) {
                    if (target.type == 3) {
                        LOGI("[udp] ss-redir does not support domain name");
                        continue;
                    }
                    reply_from = target.ip;
                }
            }
        }

        if (config_.kind == Kind::redir) {
            send_as(reply_from, session.client_, datagram, config_.reuse_port);
        } else if (sendto(listener.poll.fd(), reinterpret_cast<const char *>(datagram.data()), datagram.size(), 0,
                          reinterpret_cast<const sockaddr *>(&session.client_),
                          sockaddr_size(reinterpret_cast<const sockaddr *>(&session.client_)))
                       == -1
                   && ss_socket_error() != EAGAIN && ss_socket_error() != EWOULDBLOCK) {
            ERROR("[udp] remote_recv_sendto");
            continue;
        }
        idle_.touch(session, loop_->now());
        schedule();
    }
}

void UdpRelay::on_timer() noexcept
{
    timer_due_ = 0;
    idle_.expire(loop_->now(), [this](UdpSession &s) { expire(s); });
    schedule();
}

void UdpRelay::schedule() noexcept
{
    auto next = idle_.next_due();
    if (!next) {
        if (timer_due_ != 0) {
            timer_.stop();
            timer_due_ = 0;
        }
        return;
    }
    // Touches only push deadlines later, so an armed timer can stay.
    if (timer_due_ != 0 && timer_due_ <= *next) {
        return;
    }
    std::uint64_t now = loop_->now();
    timer_due_        = *next;
    timer_.start(*next > now ? *next - now : 1);
}

void UdpRelay::shutdown() noexcept
{
    if (shutting_down_ || loop_ == nullptr) {
        return;
    }
    shutting_down_ = true;
    sessions_.clear(); // closes every session
    shared_.clear();
    closer_.arm(CloseCompletion([](void *self, std::uint32_t) { static_cast<UdpRelay *>(self)->own_closed_ = true; },
                                this, 0));
    for (std::size_t i = 0; i < listener_count_; ++i) {
        listeners_[i].poll.close(closer_);
    }
    timer_.close(closer_);
    closer_.seal();
}

bool UdpRelay::closed() const noexcept
{
    return own_closed_ && pool_.live() == 0 && pool_.closing() == 0 && pending_.live() == 0;
}

} // namespace ss::relay
