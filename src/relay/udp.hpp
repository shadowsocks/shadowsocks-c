/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_RELAY_UDP_HPP
#define SS_RELAY_UDP_HPP

// The UDP relay shared by the four programs, replacing udprelay.cpp and its
// per-module conditionals.
//
// Ownership
//   * A Session (one per client address and target family, with its own
//     upstream socket) is owned by the relay's LRU table through a PoolPtr;
//     evicting or expiring an entry is what closes the session.
//   * AEAD-2022 server sessions are shared: the table keyed by client
//     session ID holds one reference and every relay session talking to
//     that client holds another (RefPtr), so evicting a busy table entry
//     never frees state still in use.
//   * Datagrams waiting for DNS are pool slots handed to the resolver and
//     taken back by its callback.
//   * Packets are received into, and built in, two buffers owned by the
//     relay; nothing is allocated per datagram.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "core/buffer.hpp"
#include "core/fixed_map.hpp"
#include "core/pool.hpp"
#include "core/ref.hpp"
#include "core/result.hpp"
#include "event/loop.hpp"
#include "relay/codec.hpp"
#include "relay/resolver.hpp"
#include "relay/socket.hpp"
#include "relay/tcp.hpp" // Kind

namespace ss::relay {

inline constexpr std::size_t kMaxDatagram = 65536;

struct UdpConfig {
    Kind kind = Kind::local;
    sockaddr_storage remote{}; // client kinds: the ss-server
    std::array<std::uint8_t, kMaxSocksAddr> tunnel_target{};
    std::size_t tunnel_target_len = 0;
    int timeout_secs              = 60;
    std::uint32_t max_sessions    = 512;
    std::uint32_t max_sessions_2022 = 4096; // server: AEAD-2022 client sessions
    std::uint32_t max_pending_dns = 64;
    int mtu                       = 0;
    const char *iface             = nullptr;
    const sockaddr_storage *bind_v4 = nullptr;
    const sockaddr_storage *bind_v6 = nullptr;
    bool vpn                      = false;
    int (*protect)(int fd)        = nullptr;
    bool reuse_port               = false;
    const char *label             = "";
    std::uint64_t *tx             = nullptr;
    std::uint64_t *rx             = nullptr;
    void (*on_traffic)()          = nullptr;
};

// Bind the UDP socket clients send to (ss-redir: transparent, with the
// original destination reported). Returns the socket or an error.
Result<ss_socket_t> open_udp_listener(const char *host, const char *port, bool transparent, bool reuse_port) noexcept;

class UdpRelay;

// Shared AEAD-2022 server session (see above).
class Shared2022 : public RefCounted<Shared2022> {
public:
    explicit Shared2022(UdpRelay &relay) noexcept : relay_(&relay) {}
    static void destroy(Shared2022 *self) noexcept;

    crypto::UdpSession2022 state;
    std::uint64_t last_used = 0;

private:
    UdpRelay *relay_;
};

class UdpSession : public event::Deadline {
public:
    UdpSession(UdpRelay &relay, std::uint8_t listener) noexcept : relay_(&relay), listener_(listener) {}
    UdpSession(const UdpSession &)            = delete;
    UdpSession &operator=(const UdpSession &) = delete;

    void begin_close(CloseCompletion done) noexcept;
    event::Flow on_readable(int events) noexcept;

private:
    friend class UdpRelay;

    UdpRelay *relay_;
    std::uint8_t listener_;
    CloseCompletion done_;
    event::Poll<UdpSession, &UdpSession::on_readable> socket_;
    event::CloseGroup closer_;
    sockaddr_storage client_{};          // where replies go
    std::array<std::byte, sizeof(int) + sizeof(sockaddr_storage)> key_{};
    std::uint8_t key_len_ = 0;
    crypto::UdpSession2022 client2022_;  // client kinds
    RefPtr<Shared2022> server2022_;      // server
};

class UdpRelay {
public:
    UdpRelay() noexcept = default;
    UdpRelay(const UdpRelay &)            = delete;
    UdpRelay &operator=(const UdpRelay &) = delete;
    ~UdpRelay();

    // `resolver` is needed by ss-server (targets given by name).
    Status init(event::Loop &loop, Method &method, const UdpConfig &config, Resolver *resolver) noexcept;
    Status listen(ss_socket_t fd) noexcept;

    void shutdown() noexcept;
    bool closed() const noexcept;

    std::uint32_t sessions() const noexcept { return sessions_.size(); }

private:
    friend class UdpSession;
    friend class Shared2022;

    using Key = FixedKey<sizeof(int) + sizeof(sockaddr_storage)>;

    struct Listener {
        UdpRelay *relay   = nullptr;
        std::uint8_t index = 0;
        event::Flow on_ready(int events) noexcept;
        event::Poll<Listener, &Listener::on_ready> poll;
    };
    static constexpr std::size_t kMaxListeners = 16;

    struct Pending {
        std::uint8_t listener = 0;
        sockaddr_storage client{};
        RefPtr<Shared2022> session;
        std::size_t len = 0;
        std::array<std::uint8_t, kMaxDatagram> payload; // target payload only
    };

    void receive(Listener &listener) noexcept;
    void client_packet(Listener &listener, const sockaddr_storage &from, std::span<std::uint8_t> packet,
                       const sockaddr_storage *original_dst) noexcept;
    void server_packet(Listener &listener, const sockaddr_storage &from, std::span<std::uint8_t> packet) noexcept;
    void server_forward(std::uint8_t listener, const sockaddr_storage &client, const sockaddr *target,
                        RefPtr<Shared2022> shared, std::span<const std::uint8_t> payload) noexcept;
    void reply(UdpSession &session) noexcept;
    UdpSession *session_for(std::uint8_t listener, const sockaddr_storage &client, int family) noexcept;
    RefPtr<Shared2022> shared_for(const std::array<std::uint8_t, crypto::kSessionIdLen> &id) noexcept;
    void expire(UdpSession &session) noexcept;
    Result<ss_socket_t> open_upstream_socket(int family) noexcept;
    static void resolved(const ResolveCallback &cb, const sockaddr *address) noexcept;
    void on_timer() noexcept;
    void schedule() noexcept;
    std::uint64_t now_secs() const noexcept;

    event::Loop *loop_  = nullptr;
    Method *method_     = nullptr;
    Resolver *resolver_ = nullptr;
    UdpConfig config_{};

    std::array<Listener, kMaxListeners> listeners_{};
    std::size_t listener_count_ = 0;

    ObjectPool<UdpSession> pool_;
    FixedLru<Key, PoolPtr<UdpSession> > sessions_;
    ObjectPool<Shared2022> shared_pool_;
    FixedLru<FixedKey<crypto::kSessionIdLen>, RefPtr<Shared2022> > shared_;
    ObjectPool<Pending> pending_;

    event::DeadlineList<UdpSession> idle_;
    event::Timer<UdpRelay, &UdpRelay::on_timer> timer_;
    std::uint64_t timer_due_ = 0;
    event::CloseGroup closer_;
    bool shutting_down_ = false;
    bool own_closed_    = true;

    // Received datagram and the one built from it.
    std::array<std::uint8_t, kMaxDatagram> in_{};
    std::array<std::uint8_t, kMaxDatagram + 3 + kMaxSocksAddr + 256> out_{};
};

} // namespace ss::relay

#endif
