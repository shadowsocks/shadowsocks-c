/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_EVENT_LOOP_HPP
#define SS_EVENT_LOOP_HPP

// C++ event layer over libuv, replacing the ss_event C API module by module.
//
// Ownership rules
//   * Every handle wrapper (Poll, Timer, Signal, Async) is embedded by value
//     in the object that reacts to it, its Owner. Callbacks go straight to
//     a member function of the Owner chosen at compile time; there is no
//     container_of arithmetic and no per-handle heap state. The Owner must
//     declare that member function before the handle member that names it.
//   * A Poll owns its socket. The descriptor is closed in libuv's close
//     callback, once libuv no longer polls it.
//   * libuv closes handles asynchronously, so an Owner cannot be destroyed
//     the moment it is done. It closes its handles into a CloseGroup, and
//     the group reports completion once the last close callback has run.
//     Owners kept in an ObjectPool model AsyncClosable by doing exactly
//     that in begin_close(), so their slot is recycled only afterwards.
//   * One poll handle per socket carries both read and write interest. A
//     handle stopped or closed inside another callback gets no further
//     events (libuv guarantees this), which is what the old ss_event
//     generation snapshot emulated for shared per-fd watchers.

#include <cstdint>
#include <cstdlib>
#include <optional>
#include <type_traits>

#include <uv.h>

#include "core/intrusive_list.hpp"
#include "core/pool.hpp"
#include "core/result.hpp"
#include "platform.h"

namespace ss::event {

// Readiness bits delivered to Poll owners.
enum Events : int {
    readable = 1,
    writable = 2,
    failed   = 4, // the socket reported an error; reading or writing will tell which
};

// What a callback did with its owner. Returning Flow::closed promises the
// caller that the owner has started closing and must not be touched again.
enum class [[nodiscard]] Flow : std::uint8_t { proceed, closed };

class Loop {
public:
    Loop() noexcept = default;
    Loop(const Loop &)            = delete;
    Loop &operator=(const Loop &) = delete;

    ~Loop()
    {
        if (initialised_ && !shutdown()) {
            std::abort(); // a handle outlived the loop it belongs to
        }
    }

    Status init() noexcept
    {
        if (initialised_ || native_ != &loop_) {
            return fail(Errc::invalid);
        }
        int rc = uv_loop_init(&loop_);
        if (rc != 0) {
            return fail(Errc::io, -rc);
        }
        initialised_ = true;
        return {};
    }

    // Use a loop owned by someone else (the ss_event default loop while C
    // modules still run on it). The loop is neither run nor closed here.
    Status adopt(uv_loop_t *loop) noexcept
    {
        if (initialised_ || loop == nullptr) {
            return fail(Errc::invalid);
        }
        native_ = loop;
        return {};
    }

    // Run until stop() or until nothing is left to do.
    void run() noexcept { uv_run(native_, UV_RUN_DEFAULT); }
    // Poll once without blocking.
    void run_nowait() noexcept { uv_run(native_, UV_RUN_NOWAIT); }
    // Block for one round of events.
    void run_once() noexcept { uv_run(native_, UV_RUN_ONCE); }
    void stop() noexcept { uv_stop(native_); }

    // Cached loop time in milliseconds.
    std::uint64_t now() const noexcept { return uv_now(native_); }
    void update_time() noexcept { uv_update_time(native_); }

    uv_loop_t *native() noexcept { return native_; }

    // Let pending close callbacks run and release the loop. Fails, leaving
    // the loop usable, while handles are still open.
    bool shutdown() noexcept
    {
        if (!initialised_) {
            return true;
        }
        uv_run(&loop_, UV_RUN_NOWAIT);
        if (uv_loop_close(&loop_) != 0) {
            return false;
        }
        initialised_ = false;
        return true;
    }

private:
    uv_loop_t loop_{};
    uv_loop_t *native_ = &loop_;
    bool initialised_  = false;
};

// Collects the asynchronous closes of one owner's handles and invokes a
// CloseCompletion after the last one. Usage inside begin_close():
//
//     closer_.arm(done);
//     client_.close(closer_);
//     timer_.close(closer_);
//     closer_.seal();
//
// seal() completes immediately when nothing needed closing.
class CloseGroup {
public:
    void arm(CloseCompletion done) noexcept
    {
        if (armed_) {
            std::abort();
        }
        done_  = done;
        armed_ = true;
    }

    void seal() noexcept
    {
        sealed_ = true;
        maybe_finish();
    }

    // Called by handle wrappers.
    void enter() noexcept { ++pending_; }
    void leave() noexcept
    {
        if (pending_ == 0) {
            std::abort();
        }
        --pending_;
        maybe_finish();
    }

    bool closing() const noexcept { return armed_; }

private:
    void maybe_finish() noexcept
    {
        if (sealed_ && pending_ == 0 && armed_) {
            armed_                = false;
            CloseCompletion done = done_;
            done(); // may destroy the owner, and with it this group
        }
    }

    CloseCompletion done_;
    std::uint32_t pending_ = 0;
    bool armed_            = false;
    bool sealed_           = false;
};

namespace detail {

// State shared by the handle wrappers: the owner, the group to report a
// finished close to, and whether the handle is live.
template <class Handle>
struct HandleBase {
    HandleBase() noexcept = default;
    HandleBase(const HandleBase &)            = delete;
    HandleBase &operator=(const HandleBase &) = delete;

    ~HandleBase()
    {
        if (live) {
            std::abort(); // close() the handle and wait for it first
        }
    }

    uv_handle_t *as_handle() noexcept { return reinterpret_cast<uv_handle_t *>(&handle); }

    Handle handle{};
    CloseGroup *group = nullptr;
    bool live         = false;
};

} // namespace detail

template <class Owner, Flow (Owner::*OnReady)(int events)>
class Poll : private detail::HandleBase<uv_poll_t> {
public:
    // Start owning `fd`. Nothing is watched until want() asks for events.
    Status open(Loop &loop, Owner &owner, ss_socket_t fd) noexcept
    {
        if (live) {
            return fail(Errc::invalid);
        }
#ifdef _WIN32
        int rc = uv_poll_init_socket(loop.native(), &handle, fd);
#else
        int rc = uv_poll_init(loop.native(), &handle, fd);
#endif
        if (rc != 0) {
            return fail(Errc::io, -rc);
        }
        handle.data = this;
        owner_      = &owner;
        fd_         = fd;
        interest_   = 0;
        live        = true;
        return {};
    }

    // Replace the set of events of interest (readable | writable); 0 stops
    // polling without closing.
    Status want(int events) noexcept
    {
        if (!live) {
            return fail(Errc::closed);
        }
        events &= readable | writable;
        if (events == interest_) {
            return {};
        }
        int rc = 0;
        if (events == 0) {
            rc = uv_poll_stop(&handle);
        } else {
            int uv_events = ((events & readable) ? UV_READABLE : 0) | ((events & writable) ? UV_WRITABLE : 0);
            rc = uv_poll_start(&handle, uv_events, &Poll::on_poll);
        }
        if (rc != 0) {
            return fail(Errc::io, -rc);
        }
        interest_ = events;
        return {};
    }

    int interest() const noexcept { return interest_; }
    ss_socket_t fd() const noexcept { return fd_; }
    bool is_open() const noexcept { return live; }
    bool is_closing() const noexcept { return group != nullptr; }

    // Stop polling and close; the socket is closed once libuv lets go,
    // unless someone else (c-ares) owns it.
    void close(CloseGroup &closer, bool close_socket = true) noexcept
    {
        if (!live || group != nullptr) {
            return;
        }
        close_socket_ = close_socket;
        group = &closer;
        closer.enter();
        uv_close(as_handle(), &Poll::on_closed);
    }

private:
    static void on_poll(uv_poll_t *h, int status, int events) noexcept
    {
        auto *self = static_cast<Poll *>(h->data);
        int ready  = ((events & UV_READABLE) ? readable : 0) | ((events & UV_WRITABLE) ? writable : 0);
        if (status < 0) {
            ready = readable | writable | failed;
        }
        (void)(self->owner_->*OnReady)(ready);
    }

    static void on_closed(uv_handle_t *h) noexcept
    {
        auto *self = static_cast<Poll *>(h->data);
        if (self->close_socket_) {
            ss_socket_close(self->fd_);
        }
        self->live           = false;
        CloseGroup *closer   = self->group;
        self->group          = nullptr;
        closer->leave(); // may destroy self
    }

    Owner *owner_      = nullptr;
    ss_socket_t fd_    = 0;
    int interest_      = 0;
    bool close_socket_ = true;
};

template <class Owner, void (Owner::*OnFire)()>
class Timer : private detail::HandleBase<uv_timer_t> {
public:
    Status open(Loop &loop, Owner &owner) noexcept
    {
        if (live) {
            return fail(Errc::invalid);
        }
        int rc = uv_timer_init(loop.native(), &handle);
        if (rc != 0) {
            return fail(Errc::io, -rc);
        }
        handle.data = this;
        owner_      = &owner;
        live        = true;
        return {};
    }

    // Fire after `timeout_ms`, then every `repeat_ms` if non-zero.
    void start(std::uint64_t timeout_ms, std::uint64_t repeat_ms = 0) noexcept
    {
        if (live) {
            (void)uv_timer_start(&handle, &Timer::on_fire, timeout_ms, repeat_ms);
        }
    }
    void stop() noexcept
    {
        if (live) {
            (void)uv_timer_stop(&handle);
        }
    }
    bool active() const noexcept { return live && uv_is_active(reinterpret_cast<const uv_handle_t *>(&handle)) != 0; }
    bool is_open() const noexcept { return live; }

    void close(CloseGroup &closer) noexcept
    {
        if (!live || group != nullptr) {
            return;
        }
        group = &closer;
        closer.enter();
        uv_close(as_handle(), &Timer::on_closed);
    }

private:
    static void on_fire(uv_timer_t *h) noexcept
    {
        auto *self = static_cast<Timer *>(h->data);
        (self->owner_->*OnFire)();
    }

    static void on_closed(uv_handle_t *h) noexcept
    {
        auto *self         = static_cast<Timer *>(h->data);
        self->live         = false;
        CloseGroup *closer = self->group;
        self->group        = nullptr;
        closer->leave();
    }

    Owner *owner_ = nullptr;
};

template <class Owner, void (Owner::*OnSignal)(int signum)>
class Signal : private detail::HandleBase<uv_signal_t> {
public:
    Status open(Loop &loop, Owner &owner, int signum) noexcept
    {
        if (live) {
            return fail(Errc::invalid);
        }
        int rc = uv_signal_init(loop.native(), &handle);
        if (rc != 0) {
            return fail(Errc::io, -rc);
        }
        handle.data = this;
        owner_      = &owner;
        live        = true;
        rc          = uv_signal_start(&handle, &Signal::on_signal, signum);
        if (rc != 0) {
            // The handle stays open (but idle) so the owner's normal close
            // path releases it.
            return fail(Errc::io, -rc);
        }
        return {};
    }

    bool is_open() const noexcept { return live; }

    void close(CloseGroup &closer) noexcept
    {
        if (!live || group != nullptr) {
            return;
        }
        group = &closer;
        closer.enter();
        uv_close(as_handle(), &Signal::on_closed);
    }

private:
    static void on_signal(uv_signal_t *h, int signum) noexcept
    {
        auto *self = static_cast<Signal *>(h->data);
        (self->owner_->*OnSignal)(signum);
    }

    static void on_closed(uv_handle_t *h) noexcept
    {
        auto *self         = static_cast<Signal *>(h->data);
        self->live         = false;
        CloseGroup *closer = self->group;
        self->group        = nullptr;
        closer->leave();
    }

    Owner *owner_ = nullptr;
};

// Wakes the loop from any thread; the callback runs on the loop thread.
// Several send() calls before the loop wakes up coalesce into one callback.
template <class Owner, void (Owner::*OnWake)()>
class Async : private detail::HandleBase<uv_async_t> {
public:
    Status open(Loop &loop, Owner &owner) noexcept
    {
        if (live) {
            return fail(Errc::invalid);
        }
        int rc = uv_async_init(loop.native(), &handle, &Async::on_wake);
        if (rc != 0) {
            return fail(Errc::io, -rc);
        }
        handle.data = this;
        owner_      = &owner;
        live        = true;
        return {};
    }

    // Thread-safe and async-signal-safe.
    void send() noexcept { (void)uv_async_send(&handle); }
    bool is_open() const noexcept { return live; }

    void close(CloseGroup &closer) noexcept
    {
        if (!live || group != nullptr) {
            return;
        }
        group = &closer;
        closer.enter();
        uv_close(as_handle(), &Async::on_closed);
    }

private:
    static void on_wake(uv_async_t *h) noexcept
    {
        auto *self = static_cast<Async *>(h->data);
        (self->owner_->*OnWake)();
    }

    static void on_closed(uv_handle_t *h) noexcept
    {
        auto *self         = static_cast<Async *>(h->data);
        self->live         = false;
        CloseGroup *closer = self->group;
        self->group        = nullptr;
        closer->leave();
    }

    Owner *owner_ = nullptr;
};

// Idle timeouts for many objects that share one timeout value, driven by a
// single timer. Because every entry gets the same timeout, refreshing an
// entry is a move to the back of the list, and the front is always the next
// one to expire.
struct DeadlineTag;

class Deadline : public ListNode<DeadlineTag> {
public:
    std::uint64_t deadline() const noexcept { return at_; }

private:
    template <class>
    friend class DeadlineList;
    std::uint64_t at_ = 0;
};

template <class T>
class DeadlineList {
    static_assert(std::is_base_of_v<Deadline, T>);

public:
    explicit DeadlineList(std::uint64_t timeout_ms = 0) noexcept : timeout_(timeout_ms) {}

    void set_timeout(std::uint64_t timeout_ms) noexcept { timeout_ = timeout_ms; }
    std::uint64_t timeout() const noexcept { return timeout_; }

    // (Re)start the item's timeout from `now`.
    void touch(T &item, std::uint64_t now) noexcept
    {
        static_cast<Deadline &>(item).at_ = now + timeout_;
        if (static_cast<ListNode<DeadlineTag> &>(item).linked()) {
            list_.move_to_back(item);
        } else {
            list_.push_back(item);
        }
    }

    static void remove(T &item) noexcept { IntrusiveList<T, DeadlineTag>::remove(item); }

    bool empty() const noexcept { return list_.empty(); }

    // When the earliest entry expires, if any.
    std::optional<std::uint64_t> next_due() noexcept
    {
        T *first = list_.front();
        if (first == nullptr) {
            return std::nullopt;
        }
        return static_cast<Deadline *>(first)->at_;
    }

    // Unlink every entry due at `now` and hand it to `on_expired`, which may
    // destroy it.
    template <class F>
    std::size_t expire(std::uint64_t now, F &&on_expired)
    {
        std::size_t n = 0;
        for (T *first = list_.front(); first != nullptr && static_cast<Deadline *>(first)->at_ <= now;
             first    = list_.front()) {
            remove(*first);
            on_expired(*first);
            ++n;
        }
        return n;
    }

private:
    IntrusiveList<T, DeadlineTag> list_;
    std::uint64_t timeout_;
};

} // namespace ss::event

#endif
