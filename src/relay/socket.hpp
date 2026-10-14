/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_RELAY_SOCKET_HPP
#define SS_RELAY_SOCKET_HPP

// Socket plumbing shared by the relays: option tuning, non-blocking I/O
// with Result errors, TCP Fast Open and SOCKS5 address encoding.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "core/result.hpp"
#include "netutils.h"
#include "platform.h"

namespace ss::relay {

// Options applied to every outgoing (upstream) socket.
struct SocketTuning {
    int sndbuf = 0;
    int rcvbuf = 0;
    // As the C relays: < 0 opens IPPROTO_MPTCP sockets, 1 probes the
    // out-of-tree option (and remembers the one that worked), > 1 is that
    // option.
    int mptcp            = 0;
    const char *iface    = nullptr;
    bool keepalive       = false;
    bool keepalive_tuned = false; // ss-redir: idle 40 s, interval 20 s, 5 probes
    int tos              = -1;
    // ss-server --bind-address: source addresses for each family.
    const sockaddr_storage *bind_v4 = nullptr;
    const sockaddr_storage *bind_v6 = nullptr;
    int (*protect)(int fd)          = nullptr; // Android VpnService
};

Status set_nonblocking(ss_socket_t fd) noexcept;
void set_nodelay(ss_socket_t fd, bool on) noexcept;
void set_nosigpipe(ss_socket_t fd) noexcept;
socklen_t sockaddr_size(const sockaddr *addr) noexcept;

// A non-blocking stream socket for `family`, tuned for upstream use.
Result<ss_socket_t> open_upstream(int family, SocketTuning &tuning, bool protect) noexcept;

// Start connecting. With `fast_open` the first bytes of `data` travel in the
// SYN; returns how many were accepted (0 when nothing was sent yet). Fails
// with Errc::invalid when the platform turned fast open down; the caller then
// falls back to a plain connect.
Result<std::size_t> start_connect(ss_socket_t fd, const sockaddr *addr, std::span<const std::uint8_t> data,
                                  bool fast_open) noexcept;
// After the socket became writable: did the connect succeed?
bool is_connected(ss_socket_t fd) noexcept;

// recv/send with EAGAIN as Errc::again and an orderly EOF as Errc::closed.
Result<std::size_t> recv_some(ss_socket_t fd, std::span<std::uint8_t> buf) noexcept;
Result<std::size_t> send_some(ss_socket_t fd, std::span<const std::uint8_t> buf) noexcept;

// SOCKS5 address (type, address, port) for an IP endpoint; returns its length.
inline constexpr std::size_t kMaxSocksAddr = 1 + 1 + 255 + 2;
std::size_t encode_socks_addr(const sockaddr *addr, std::uint8_t *out) noexcept;
// For a host name or a literal IP plus a port in host byte order. Returns 0
// when the name does not fit.
std::size_t encode_socks_host(const char *host, std::uint16_t port, std::uint8_t *out) noexcept;

struct SocksTarget {
    std::size_t length = 0;  // bytes of the encoded address
    std::uint8_t type  = 0;  // 1, 3 or 4
    char host[256]     = {}; // dotted/colon form for IPs, the name for domains
    std::uint16_t port = 0;  // host byte order
    sockaddr_storage ip{};   // filled for IP addresses
};
enum class ParseResult : std::uint8_t { complete, need_more, invalid };
// Parse a SOCKS5 address at the head of `in` (the shadowsocks request
// header). The address type's upper bits are ignored, as ss-server does.
ParseResult parse_socks_addr(std::span<const std::uint8_t> in, SocksTarget &out) noexcept;

} // namespace ss::relay

#endif
