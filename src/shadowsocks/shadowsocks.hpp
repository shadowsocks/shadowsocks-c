/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SHADOWSOCKS_SHADOWSOCKS_HPP
#define SHADOWSOCKS_SHADOWSOCKS_HPP

// C++ wrapper for embedding ss-local (header-only; C++17 or later).
//
//     shadowsocks::LocalServer server;
//     if (int err = server.start(profile)) { ... }
//     ...
//     server.stop();          // from any thread
//     int result = server.wait();
//
// The library exports only the C entry points in <shadowsocks/control.h>,
// so this header adds no C++ ABI to libshadowsocks-c. The destructor stops
// and waits for a running server.

#include <errno.h>

#include <utility>

#include <shadowsocks/control.h>

namespace shadowsocks {

class LocalServer {
public:
    LocalServer() noexcept = default;
    LocalServer(const LocalServer &)            = delete;
    LocalServer &operator=(const LocalServer &) = delete;
    LocalServer(LocalServer &&other) noexcept : handle_(std::exchange(other.handle_, nullptr)) {}
    LocalServer &operator=(LocalServer &&other) noexcept
    {
        if (this != &other) {
            reset();
            handle_ = std::exchange(other.handle_, nullptr);
        }
        return *this;
    }
    ~LocalServer() { reset(); }

    // 0 on success, otherwise an errno value (EBUSY when a server already
    // runs in this process).
    int start(const profile_t &profile, ss_local_callback callback = nullptr, void *udata = nullptr) noexcept
    {
        if (handle_ != nullptr) {
            return EBUSY;
        }
        return ss_local_start(&profile, callback, udata, &handle_);
    }

    void stop() noexcept
    {
        if (handle_ != nullptr) {
            ss_local_stop(handle_);
        }
    }

    // The server's return value; the object can start again afterwards.
    int wait() noexcept
    {
        if (handle_ == nullptr) {
            return 0;
        }
        int result = ss_local_wait(handle_);
        ss_local_destroy(handle_);
        handle_ = nullptr;
        return result;
    }

    bool running() const noexcept { return handle_ != nullptr; }

private:
    void reset() noexcept
    {
        stop();
        (void)wait();
    }

    ss_local_handle *handle_ = nullptr;
};

} // namespace shadowsocks

#endif
