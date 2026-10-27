/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_EVENT_PROGRAM_HPP
#define SS_EVENT_PROGRAM_HPP

// The event loop of one program run: the loop itself, the signals that end
// it, and a few program-level watchers (a periodic callback, sockets).
// Replaces each main()'s ss_signal/ss_timer/ss_io plumbing. Everything is
// held by value in the Program object, which main() keeps on its stack.

#include <array>
#include <csignal>
#include <cstdint>

#include "core/result.hpp"
#include "event/loop.hpp"
#include "utils.h"

namespace ss::event {

class Program {
public:
    using Callback = void (*)(void *ctx) noexcept;

    Program() noexcept = default;
    Program(const Program &)            = delete;
    Program &operator=(const Program &) = delete;
    ~Program() { close(); }

    Status init() noexcept { return loop_.init(); }
    Loop &loop() noexcept { return loop_; }

    // In the child after daemonize(): kqueue and epoll descriptors do not
    // survive fork().
    Status after_fork() noexcept
    {
#ifndef _WIN32
        if (uv_loop_fork(loop_.native()) != 0) {
            return fail(Errc::io);
        }
#endif
        return {};
    }

    // SIGINT and SIGTERM end the run (and SIGUSR1 with `usr1`). With
    // `plugin_alive`, SIGCHLD ends it with exit code -1 once that reports
    // the plugin gone. Signals libuv cannot watch on this platform are
    // skipped.
    Status handle_signals(bool usr1, bool (*plugin_alive)() = nullptr) noexcept
    {
        plugin_alive_ = plugin_alive;
        int signals[]  = { SIGINT, SIGTERM,
#ifndef _WIN32
                          usr1 ? SIGUSR1 : 0, plugin_alive != nullptr ? SIGCHLD : 0
#endif
        };
        for (int signum : signals) {
            if (signum == 0) {
                continue;
            }
            if (signal_count_ == signals_.size()) {
                return fail(Errc::exhausted);
            }
            SignalWatch &w = signals_[signal_count_];
            w.program      = this;
            Status opened = w.signal.open(loop_, w, signum);
            if (w.signal.is_open()) {
                ++signal_count_; // close() releases it even if starting failed
            }
            SS_TRY(opened);
        }
        (void)usr1;
        return {};
    }

    // Call `fn` every `interval_ms`.
    Status every(std::uint64_t interval_ms, Callback fn, void *ctx) noexcept
    {
        tick_.fn  = fn;
        tick_.ctx = ctx;
        SS_TRY(tick_.timer.open(loop_, tick_));
        tick_.timer.start(interval_ms, interval_ms);
        return {};
    }

    // Call `fn` whenever `fd` is readable. The Program owns the socket.
    Status watch(ss_socket_t fd, Callback fn, void *ctx) noexcept
    {
        if (watch_count_ == watches_.size()) {
            return fail(Errc::exhausted);
        }
        SocketWatch &w = watches_[watch_count_];
        w.fn           = fn;
        w.ctx          = ctx;
        SS_TRY(w.poll.open(loop_, w, fd));
        ++watch_count_;
        return w.poll.want(readable);
    }

    // Let other threads end the run with request_stop().
    Status allow_remote_stop() noexcept
    {
        wake_.program = this;
        return wake_.async.open(loop_, wake_);
    }
    // Thread-safe; needs allow_remote_stop() first.
    void request_stop() noexcept { wake_.async.send(); }

    // Run until stop() or a signal; returns the exit code.
    int run() noexcept
    {
        loop_.run();
        return exit_code_;
    }

    void stop(int exit_code = 0) noexcept
    {
        if (exit_code != 0) {
            exit_code_ = exit_code;
        }
        loop_.stop();
    }

    int exit_code() const noexcept { return exit_code_; }

    // Close the program's own handles and let their closes finish. Other
    // owners (relays, resolvers) must be closed and drained first.
    void close() noexcept
    {
        if (closed_) {
            return;
        }
        closed_ = true;
        for (std::size_t i = 0; i < signal_count_; ++i) {
            signals_[i].signal.close(closer_);
        }
        for (std::size_t i = 0; i < watch_count_; ++i) {
            watches_[i].poll.close(closer_);
        }
        tick_.timer.close(closer_);
        wake_.async.close(closer_);
        static bool done;
        done = false;
        closer_.arm(CloseCompletion([](void *, std::uint32_t) { done = true; }, nullptr, 0));
        closer_.seal();
        while (!done) { // NOLINT(bugprone-infinite-loop): the close callback sets it
            loop_.run_nowait();
        }
        (void)loop_.shutdown();
    }

private:
    struct SignalWatch {
        Program *program = nullptr;
        void on_signal(int signum) noexcept { program->on_signal(signum); }
        Signal<SignalWatch, &SignalWatch::on_signal> signal;
    };
    struct SocketWatch {
        Callback fn = nullptr;
        void *ctx   = nullptr;
        Flow on_ready(int) noexcept
        {
            fn(ctx);
            return Flow::proceed;
        }
        Poll<SocketWatch, &SocketWatch::on_ready> poll;
    };
    struct Wake {
        Program *program = nullptr;
        void on_wake() noexcept { program->stop(0); }
        Async<Wake, &Wake::on_wake> async;
    };
    struct Tick {
        Callback fn = nullptr;
        void *ctx   = nullptr;
        void on_fire() noexcept { fn(ctx); }
        Timer<Tick, &Tick::on_fire> timer;
    };

    void on_signal(int signum) noexcept
    {
#ifndef _WIN32
        if (signum == SIGCHLD) {
            if (plugin_alive_ == nullptr || plugin_alive_()) {
                return;
            }
            LOGE("plugin service exit unexpectedly");
            stop(-1);
            return;
        }
#endif
        (void)signum;
        stop(0);
    }

    Loop loop_;
    std::array<SignalWatch, 4> signals_{};
    std::size_t signal_count_ = 0;
    std::array<SocketWatch, 4> watches_{};
    std::size_t watch_count_ = 0;
    Tick tick_;
    Wake wake_;
    CloseGroup closer_;
    bool (*plugin_alive_)() = nullptr;
    int exit_code_          = 0;
    bool closed_            = false;
};

} // namespace ss::event

#endif
