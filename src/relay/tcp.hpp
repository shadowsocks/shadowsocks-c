/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_RELAY_TCP_HPP
#define SS_RELAY_TCP_HPP

// The TCP relay shared by ss-local, ss-tunnel, ss-redir and ss-server,
// replacing the four hand-copied sets of accept/recv/send/close callbacks.
//
// Ownership
//   * TcpRelay owns every Connection through a PoolPtr kept in a table
//     indexed by pool slot; closing a connection is resetting that pointer.
//     The pool then closes the connection's two sockets (begin_close) and
//     recycles the slot once libuv has let go of them.
//   * Nothing points at a Connection from outside: DNS answers come back
//     with a generation-checked Handle, timeouts are intrusive list links
//     the connection removes itself from when it closes.
//   * Buffers, cipher state and the handshake state live inside the
//     connection, so accepting a connection allocates nothing; when the pool
//     is full the new connection is refused.
//
// Data moves in lock step, as in the C relays: one direction reads its
// source only while its buffer towards the other side is empty.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>

#include "core/buffer.hpp"
#include "core/pool.hpp"
#include "core/region.hpp"
#include "core/result.hpp"
#include "event/loop.hpp"
#include "relay/codec.hpp"
#include "relay/resolver.hpp"
#include "relay/socket.hpp"

namespace ss::relay {

enum class Kind : std::uint8_t { local, tunnel, redir, server };

// The ACL module (acl.cpp), for the binaries that link it.
struct AclHooks {
    int (*match_host)(const char *host) = nullptr; // > 0 listed as bypass/block, < 0 as proxy, 0 neither
    int (*mode)()                       = nullptr; // BLACK_LIST or WHITE_LIST
    int (*outbound_blocked)(const char *host) = nullptr;

    // ss-server: is a client at `peer` (an address) refused?
    bool peer_denied(const char *peer) const noexcept
    {
        constexpr int kWhiteList = 1; // acl.h WHITE_LIST
        int listed = match_host(peer);
        return mode() == kWhiteList ? listed >= 0 : listed == 1;
    }

    // ss-server: may a client reach `target`?
    bool target_blocked(const sockaddr *target) const noexcept
    {
        char ip[INET6_ADDRSTRLEN] = {};
        const void *raw = target->sa_family == AF_INET
                              ? static_cast<const void *>(&reinterpret_cast<const sockaddr_in *>(target)->sin_addr)
                              : static_cast<const void *>(&reinterpret_cast<const sockaddr_in6 *>(target)->sin6_addr);
        ss_inet_ntop(target->sa_family, raw, ip, sizeof(ip));
        return outbound_blocked(ip) == 1;
    }
};

struct TcpConfig {
    Kind kind = Kind::local;
    // Client kinds: the ss-server endpoints (or the plugin's local port).
    std::span<const sockaddr_storage> remotes;
    // ss-tunnel: the encoded target address.
    std::array<std::uint8_t, kMaxSocksAddr> tunnel_target{};
    std::size_t tunnel_target_len = 0;
    int timeout_secs              = 60;
    std::uint32_t max_connections = 1024;
    bool fast_open                = false;
    bool no_delay                 = false;
    bool printable_salt           = false; // ss-local experiment
    bool acl                      = false; // with `acl_hooks` set
    AclHooks acl_hooks;
    bool tproxy                   = false; // ss-redir: the target is the local address
    bool vpn                      = false; // Android: protect sockets, no local DNS for ACL
    const char *label             = "";    // ss-server: the port, for logs
    SocketTuning upstream;
    std::uint64_t *tx = nullptr; // bytes received from clients
    std::uint64_t *rx = nullptr; // bytes received from upstreams
    void (*on_traffic)() = nullptr;
    // ss-server: a client failed the handshake (logging, nftables).
    void (*report_failure)(ss_socket_t client, const char *reason) = nullptr;
    // ss-server --connmark-to-TOS: runs before each write to the client
    // with per-connection state the hook owns, released when it closes.
    void (*downstream)(void **state, ss_socket_t client, ss_socket_t upstream) = nullptr;
    void (*release)(void *state) = nullptr;
};

class TcpRelay;

// Buffers towards each side hold one received chunk plus cipher overhead.
inline constexpr std::size_t kRelayBuffer = SOCKET_BUF_SIZE + Method::kMaxOverhead;
inline constexpr std::size_t kHandshakeBuffer = 1024;

using RelayBuffer = FixedBuffer<kRelayBuffer>;

// A relay buffer leased from the relay's shared pool only while it holds
// bytes. An idle connection holds none, so the pages of its buffers are not
// kept resident; a drained buffer goes back to the LIFO pool and the next
// connection reuses the same warm pages. The pool has two buffers for every
// connection slot, so a lease cannot fail.
class LeasedBuffer {
public:
    explicit LeasedBuffer(ObjectPool<RelayBuffer> &pool) noexcept : pool_(&pool) {}

    bool empty() const noexcept { return !buf_ || buf_->empty(); }
    ConstBytes readable() const noexcept { return buf_ ? std::as_const(*buf_).readable() : ConstBytes{}; }
    Bytes writable() noexcept { return lease() ? buf_->writable() : Bytes{}; }
    bool commit(std::size_t n) noexcept { return n == 0 || (buf_ && buf_->commit(n)); }
    bool consume(std::size_t n) noexcept
    {
        if (!buf_) {
            return n == 0;
        }
        bool ok = buf_->consume(n);
        trim();
        return ok;
    }
    void compact() noexcept
    {
        if (buf_) {
            buf_->compact();
        }
    }
    void clear() noexcept { buf_.reset(); }
    // Give the buffer back if it is empty.
    void trim() noexcept
    {
        if (buf_ && buf_->empty()) {
            buf_.reset();
        }
    }
    bool leased() const noexcept { return static_cast<bool>(buf_); }

private:
    bool lease() noexcept
    {
        if (!buf_) {
            auto b = pool_->acquire();
            if (!b) {
                return false;
            }
            buf_ = std::move(*b);
        }
        return true;
    }

    ObjectPool<RelayBuffer> *pool_;
    PoolPtr<RelayBuffer> buf_;
};

class Connection : public event::Deadline {
public:
    explicit Connection(TcpRelay &relay) noexcept;
    Connection(const Connection &)            = delete;
    Connection &operator=(const Connection &) = delete;

    void begin_close(CloseCompletion done) noexcept;

    event::Flow on_client(int events) noexcept;
    event::Flow on_upstream(int events) noexcept;
    void on_deadline() noexcept;
    void on_resolved(const sockaddr *address) noexcept;

private:
    friend class TcpRelay;

    enum class Stage : std::uint8_t {
        socks_method,  // local: waiting for the method selection
        socks_request, // local: waiting for the CONNECT request
        acl_resolve,   // local: resolving a name for the ACL
        udp_assoc,     // local: UDP ASSOCIATE held open until the client leaves
        delay,         // client kinds: waiting briefly for the first payload
        header,        // server: waiting for the request header
        resolving,     // server: resolving the target
        connecting,
        stream,
        stopped, // server: failed the handshake; drain until timeout
    };
    enum class Timed : std::uint8_t { none, delay, handshake, connect, idle };

    event::Flow start(ss_socket_t fd) noexcept;
    event::Flow close() noexcept;

    // Client side handshakes.
    event::Flow socks_input() noexcept;
    event::Flow socks_request() noexcept;
    event::Flow socks_route() noexcept;
    event::Flow delay_input() noexcept;
    event::Flow start_upstream(const sockaddr *target, bool direct) noexcept;
    // Server side.
    event::Flow server_header() noexcept;
    event::Flow server_connect(const sockaddr *target) noexcept;
    void server_reject(const char *reason) noexcept;

    event::Flow connected() noexcept;
    event::Flow pump_to_upstream() noexcept;
    event::Flow pump_to_client() noexcept;
    event::Flow half_close(ss_socket_t peer) noexcept;
    void update_interest() noexcept;

    enum class Pull : std::uint8_t { data, nothing, again, eof, error };
    Pull pull(ss_socket_t fd, bool decode, LeasedBuffer &dst, std::uint64_t *counter) noexcept;
    Pull pull_into(ss_socket_t fd, bool decode, LeasedBuffer &dst, std::uint64_t *counter) noexcept;
    Pull flush(ss_socket_t fd, LeasedBuffer &src) noexcept;

    bool client_kind() const noexcept;

    TcpRelay *relay_;
    CloseCompletion done_;
    event::Poll<Connection, &Connection::on_client> client_;
    event::Poll<Connection, &Connection::on_upstream> upstream_;
    event::CloseGroup closer_;

    LeasedBuffer to_upstream_;
    LeasedBuffer to_client_;
    FixedBuffer<kHandshakeBuffer> handshake_;
    Encoder enc_;
    Decoder dec_;

    std::array<std::uint8_t, kMaxSocksAddr> target_header_{};
    std::size_t target_header_len_ = 0;
    SocksTarget target_{};
    sockaddr_storage upstream_addr_{};

    Stage stage_       = Stage::socks_method;
    Timed timed_       = Timed::none;
    bool direct_       = false;
    bool dns_done_     = false;
    bool dns_ok_       = false;
    bool replied_      = false; // first upstream bytes reached the client
    // Half-close: one side has sent EOF, which went on to the other side as
    // a shutdown(SHUT_WR); the other direction keeps flowing until its EOF.
    bool client_eof_   = false;
    bool upstream_eof_ = false;
    void *hook_state_  = nullptr;
    int tos_           = -1; // from the listener that accepted it
    sockaddr_storage dns_answer_{};
};

class TcpRelay {
public:
    TcpRelay() noexcept = default;
    TcpRelay(const TcpRelay &)            = delete;
    TcpRelay &operator=(const TcpRelay &) = delete;
    ~TcpRelay();

    // `resolver` is needed by ss-server and by ss-local with an ACL.
    Status init(event::Loop &loop, Method &method, const TcpConfig &config, Resolver *resolver) noexcept;
    // Start accepting on a bound, listening socket; the relay owns it now.
    // Upstream connections of its clients get IP TOS `tos` when >= 0.
    Status listen(ss_socket_t fd, int tos = -1) noexcept;

    // Close every connection and listener. Run the loop until closed().
    void shutdown() noexcept;
    bool closed() const noexcept;
    // Listening sockets the relay owns (and closes on shutdown).
    std::size_t listeners() const noexcept { return listener_count_; }

    std::uint32_t live() const noexcept { return pool_.live(); }
    std::uint64_t refused() const noexcept { return refused_; }

private:
    friend class Connection;

    struct Listener {
        TcpRelay *relay = nullptr;
        int tos         = -1;
        event::Flow on_ready(int events) noexcept;
        event::Poll<Listener, &Listener::on_ready> poll;
    };
    static constexpr std::size_t kMaxListeners = 16;

    void accept_from(Listener &listener) noexcept;
    void close(Connection &conn) noexcept;
    void slot_freed() noexcept;
    void set_deadline(Connection &conn, Connection::Timed which) noexcept;
    void clear_deadline(Connection &conn) noexcept;
    void on_timer() noexcept;
    void schedule() noexcept;
    Status resolve(Connection &conn, const char *host, std::uint16_t port_be) noexcept;
    static void resolved(const ResolveCallback &cb, const sockaddr *address) noexcept;
    const sockaddr_storage &pick_remote() noexcept;
    void pause_accept() noexcept;
    void resume_accept() noexcept;

    event::Loop *loop_ = nullptr;
    Method *method_    = nullptr;
    Resolver *resolver_ = nullptr;
    TcpConfig config_{};

    // Declared before pool_ so that it outlives every connection's lease.
    ObjectPool<RelayBuffer> buffers_;
    ObjectPool<Connection> pool_;
    Region owners_region_;
    std::span<PoolPtr<Connection> > owners_;

    std::array<Listener, kMaxListeners> listeners_{};
    std::size_t listener_count_ = 0;
    bool accept_paused_         = false;
    std::uint64_t refused_      = 0;
    std::uint64_t last_refusal_log_ = 0;
    std::uint64_t accept_retry_at_  = 0; // accept() failed hard (e.g. EMFILE): retry then

    event::DeadlineList<Connection> delay_list_;
    event::DeadlineList<Connection> handshake_list_;
    event::DeadlineList<Connection> connect_list_;
    event::DeadlineList<Connection> idle_list_;
    event::Timer<TcpRelay, &TcpRelay::on_timer> timer_;
    std::uint64_t timer_due_ = 0; // 0 when the timer is idle
    event::CloseGroup closer_;
    bool shutting_down_ = false;
    bool own_closed_    = true;

    // One receive at a time, shared by every connection.
    std::array<std::uint8_t, SOCKET_BUF_SIZE + kMaxSocksAddr + kHandshakeBuffer> scratch_{};
};

} // namespace ss::relay

#endif
