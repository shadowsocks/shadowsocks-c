/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "relay/socket.hpp"

#include <cstring>

#ifndef _WIN32
#include <netinet/tcp.h>
#endif

#include "utils.h"

#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

namespace ss::relay {

namespace {

bool would_block(int err) noexcept
{
    return err == EAGAIN || err == EWOULDBLOCK;
}

} // namespace

Status set_nonblocking(ss_socket_t fd) noexcept
{
#ifdef _WIN32
    if (setnonblocking(fd) != 0) {
        return fail(Errc::io, ss_socket_error());
    }
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        flags = 0;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        return fail(Errc::io, errno);
    }
#endif
    return {};
}

void set_nodelay(ss_socket_t fd, bool on) noexcept
{
    int opt = on ? 1 : 0;
    (void)ss_setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

void set_nosigpipe(ss_socket_t fd) noexcept
{
#ifdef SO_NOSIGPIPE
    int opt = 1;
    (void)ss_setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#else
    (void)fd;
#endif
}

socklen_t sockaddr_size(const sockaddr *addr) noexcept
{
    if (addr->sa_family == AF_INET) {
        return sizeof(sockaddr_in);
    }
    if (addr->sa_family == AF_INET6) {
        return sizeof(sockaddr_in6);
    }
    return 0;
}

Result<ss_socket_t> open_upstream(int family, SocketTuning &t, bool protect) noexcept
{
    int protocol = t.mptcp < 0 ? IPPROTO_MPTCP : IPPROTO_TCP;
    ss_socket_t fd = ss_socket(family, SOCK_STREAM, protocol);
#ifdef _WIN32
    if (fd == INVALID_SOCKET) {
#else
    if (fd < 0) {
#endif
        int err = ss_socket_error();
        ERROR("socket");
        return fail(Errc::io, err);
    }
    if (protect && t.protect != nullptr && t.protect(static_cast<int>(fd)) == -1) {
        ERROR("protect_socket");
        ss_socket_close(fd);
        return fail(Errc::io);
    }
    int opt = 1;
    set_nodelay(fd, true);
    set_nosigpipe(fd);
    if (t.keepalive || t.keepalive_tuned) {
        (void)ss_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
    }
#if defined(TCP_KEEPIDLE) && defined(TCP_KEEPINTVL) && defined(TCP_KEEPCNT)
    if (t.keepalive_tuned) {
        int idle = 40, interval = 20, count = 5;
        (void)ss_setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
        (void)ss_setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
        (void)ss_setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &count, sizeof(count));
    }
#endif
    if (t.tos >= 0) {
        if (ss_setsockopt(fd, IPPROTO_IP, IP_TOS, &t.tos, sizeof(t.tos)) < 0 && ss_socket_error() != ENOPROTOOPT) {
            LOGE("setting ipv4 dscp failed: %d", ss_socket_error());
        }
#ifdef IPV6_TCLASS
        if (ss_setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &t.tos, sizeof(t.tos)) < 0
            && ss_socket_error() != ENOPROTOOPT) {
            LOGE("setting ipv6 dscp failed: %d", ss_socket_error());
        }
#endif
    }
    if (t.mptcp > 1) {
        if (ss_setsockopt(fd, SOL_TCP, t.mptcp, &opt, sizeof(opt)) == -1) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    } else if (t.mptcp == 1) {
        int i = 0;
        while ((t.mptcp = mptcp_enabled_values[i]) > 0) {
            if (ss_setsockopt(fd, SOL_TCP, t.mptcp, &opt, sizeof(opt)) != -1) {
                break;
            }
            ++i;
        }
        if (t.mptcp == 0) {
            ERROR("failed to enable out-of-tree multipath TCP");
        }
    }
    if (t.sndbuf > 0) {
        (void)ss_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &t.sndbuf, sizeof(int));
    }
    if (t.rcvbuf > 0) {
        (void)ss_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &t.rcvbuf, sizeof(int));
    }
    if (!set_nonblocking(fd)) {
        ERROR("setnonblocking");
    }
    const sockaddr_storage *source = family == AF_INET ? t.bind_v4 : t.bind_v6;
    if (source != nullptr && source->ss_family == family
        && bind_to_addr(const_cast<sockaddr_storage *>(source), static_cast<int>(fd)) == -1) {
        ERROR("bind_to_addr");
        ss_socket_close(fd);
        return fail(Errc::io);
    }
#ifdef SET_INTERFACE
    if (t.iface != nullptr && setinterface(static_cast<int>(fd), t.iface) == -1) {
        ERROR("setinterface");
    }
#endif
    return fd;
}

Result<std::size_t> start_connect(ss_socket_t fd, const sockaddr *addr, std::span<const std::uint8_t> data,
                                  bool fast_open) noexcept
{
    socklen_t len = sockaddr_size(addr);
    if (!fast_open || data.empty()) {
        if (connect(fd, addr, len) == -1 && ss_socket_error() != CONNECT_IN_PROGRESS) {
            return fail(Errc::io, ss_socket_error());
        }
        return std::size_t{ 0 };
    }
    ssize_t s = -1;
#if defined(MSG_FASTOPEN) && !defined(TCP_FASTOPEN_CONNECT)
    s = sendto(fd, reinterpret_cast<const char *>(data.data()), data.size(), MSG_FASTOPEN, addr, len);
#elif defined(CONNECT_DATA_IDEMPOTENT)
    sockaddr_storage copy{};
    std::memcpy(&copy, addr, len);
    if (copy.ss_family == AF_INET) {
        reinterpret_cast<sockaddr_in *>(&copy)->sin_len = sizeof(sockaddr_in);
    }
    sa_endpoints_t endpoints{};
    endpoints.sae_dstaddr    = reinterpret_cast<sockaddr *>(&copy);
    endpoints.sae_dstaddrlen = len;
    s = connectx(fd, &endpoints, SAE_ASSOCID_ANY, CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT, nullptr,
                 0, nullptr, nullptr);
    if (s == 0) {
        s = send(fd, data.data(), data.size(), 0);
    }
#elif defined(TCP_FASTOPEN_CONNECT)
    int optval = 1;
    if (ss_setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &optval, sizeof(optval)) < 0) {
        return fail(Errc::invalid, ss_socket_error());
    }
    s = connect(fd, addr, len);
    if (s == 0) {
        s = send(fd, data.data(), data.size(), 0);
    }
#else
    return fail(Errc::invalid, ENOPROTOOPT); // not on this platform
#endif
    if (s >= 0) {
        return static_cast<std::size_t>(s);
    }
    int err = ss_socket_error();
    if (err == CONNECT_IN_PROGRESS || would_block(err)) {
        return std::size_t{ 0 };
    }
    if (err == EOPNOTSUPP || err == EPROTONOSUPPORT || err == ENOPROTOOPT) {
        return fail(Errc::invalid, err);
    }
    return fail(Errc::io, err);
}

bool is_connected(ss_socket_t fd) noexcept
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    return getpeername(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0;
}

Result<std::size_t> recv_some(ss_socket_t fd, std::span<std::uint8_t> buf) noexcept
{
    ssize_t r = recv(fd, reinterpret_cast<char *>(buf.data()), buf.size(), 0);
    if (r > 0) {
        return static_cast<std::size_t>(r);
    }
    if (r == 0) {
        return fail(Errc::closed);
    }
    int err = ss_socket_error();
    if (would_block(err) || err == EINTR) {
        return fail(Errc::again);
    }
    return fail(Errc::io, err);
}

Result<std::size_t> send_some(ss_socket_t fd, std::span<const std::uint8_t> buf) noexcept
{
    ssize_t s = send(fd, reinterpret_cast<const char *>(buf.data()), buf.size(), 0);
    if (s >= 0) {
        return static_cast<std::size_t>(s);
    }
    int err = ss_socket_error();
    if (would_block(err) || err == EINTR) {
        return fail(Errc::again);
    }
    return fail(Errc::io, err);
}

std::size_t encode_socks_addr(const sockaddr *addr, std::uint8_t *out) noexcept
{
    if (addr->sa_family == AF_INET) {
        const auto *in = reinterpret_cast<const sockaddr_in *>(addr);
        out[0]         = 1;
        std::memcpy(out + 1, &in->sin_addr, 4);
        std::memcpy(out + 5, &in->sin_port, 2);
        return 7;
    }
    if (addr->sa_family == AF_INET6) {
        const auto *in = reinterpret_cast<const sockaddr_in6 *>(addr);
        out[0]         = 4;
        std::memcpy(out + 1, &in->sin6_addr, 16);
        std::memcpy(out + 17, &in->sin6_port, 2);
        return 19;
    }
    return 0;
}

std::size_t encode_socks_host(const char *host, std::uint16_t port, std::uint8_t *out) noexcept
{
    std::uint16_t be = htons(port);
    in_addr v4{};
    in6_addr v6{};
    std::size_t at = 0;
    if (inet_pton(AF_INET, host, &v4) == 1) {
        out[at++] = 1;
        std::memcpy(out + at, &v4, 4);
        at += 4;
    } else if (inet_pton(AF_INET6, host, &v6) == 1) {
        out[at++] = 4;
        std::memcpy(out + at, &v6, 16);
        at += 16;
    } else {
        std::size_t n = std::strlen(host);
        if (n == 0 || n > 255) {
            return 0;
        }
        out[at++] = 3;
        out[at++] = static_cast<std::uint8_t>(n);
        std::memcpy(out + at, host, n); // NOLINT(bugprone-not-null-terminated-result): binary, length-prefixed
        at += n;
    }
    std::memcpy(out + at, &be, 2);
    return at + 2;
}

ParseResult parse_socks_addr(std::span<const std::uint8_t> in, SocksTarget &out) noexcept
{
    if (in.empty()) {
        return ParseResult::need_more;
    }
    out.type = in[0] & 0x0F;
    out.ip   = {};
    std::size_t at = 1;
    switch (out.type) {
    case 1: {
        if (in.size() < 1 + 4 + 2) {
            return ParseResult::need_more;
        }
        auto *sa       = reinterpret_cast<sockaddr_in *>(&out.ip);
        sa->sin_family = AF_INET;
        std::memcpy(&sa->sin_addr, in.data() + 1, 4);
        std::memcpy(&sa->sin_port, in.data() + 5, 2);
        ss_inet_ntop(AF_INET, &sa->sin_addr, out.host, sizeof(out.host));
        at += 4;
        break;
    }
    case 4: {
        if (in.size() < 1 + 16 + 2) {
            return ParseResult::need_more;
        }
        auto *sa        = reinterpret_cast<sockaddr_in6 *>(&out.ip);
        sa->sin6_family = AF_INET6;
        std::memcpy(&sa->sin6_addr, in.data() + 1, 16);
        std::memcpy(&sa->sin6_port, in.data() + 17, 2);
        ss_inet_ntop(AF_INET6, &sa->sin6_addr, out.host, sizeof(out.host));
        at += 16;
        break;
    }
    case 3: {
        if (in.size() < 2) {
            return ParseResult::need_more;
        }
        std::size_t n = in[1];
        if (n == 0) {
            return ParseResult::invalid;
        }
        if (in.size() < 2 + n + 2) {
            return ParseResult::need_more;
        }
        std::memcpy(out.host, in.data() + 2, n);
        out.host[n] = '\0';
        at += 1 + n;
        break;
    }
    default:
        return ParseResult::invalid;
    }
    out.port   = static_cast<std::uint16_t>((in[at] << 8) | in[at + 1]);
    out.length = at + 2;
    return ParseResult::complete;
}

} // namespace ss::relay
