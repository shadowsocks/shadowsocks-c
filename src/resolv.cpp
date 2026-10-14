/*
 * Copyright (c) 2014, Dustin Lundquist <dustin@null-ptr.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

// The C resolver API, now a thin shim over ss::relay::Resolver (see
// src/relay/resolver.hpp), kept for the modules that still call it.

#include <cstdint>
#include <cstring>
#include <memory>
#include <new>

#include "ss_event.h"

#include "relay/resolver.hpp"
#include "resolv.h"
#include "utils.h"

namespace {

constexpr std::uint32_t kMaxQueries = 4096;

// Constructed in resolv_init and destroyed in resolv_shutdown, so there is
// no static destructor to run at exit.
alignas(ss::relay::Resolver) std::byte resolver_storage[sizeof(ss::relay::Resolver)];
alignas(ss::event::Loop) std::byte loop_storage[sizeof(ss::event::Loop)];
ss::relay::Resolver *resolver = nullptr;
ss::event::Loop *loop         = nullptr;

using client_cb_t = void (*)(struct sockaddr *, void *);
using free_cb_t   = void (*)(void *);

void deliver(const ss::relay::ResolveCallback &cb, const sockaddr *address) noexcept
{
    auto client = reinterpret_cast<client_cb_t>(cb.ctx);
    auto release = reinterpret_cast<free_cb_t>(cb.aux);
    void *data   = reinterpret_cast<void *>(static_cast<std::uintptr_t>(cb.token));
    client(const_cast<sockaddr *>(address), data);
    if (release != nullptr) {
        release(data);
    } else {
        ss_free(data);
    }
}

} // namespace

extern "C" int
resolv_init(struct ss_loop *ss_loop, char *nameservers, int ipv6first)
{
    if (resolver != nullptr) {
        return 0;
    }
    loop = std::construct_at(reinterpret_cast<ss::event::Loop *>(loop_storage));
    if (!loop->adopt(ss_native_loop(ss_loop))) {
        FATAL("failed to initialize c-ares");
    }
    resolver = std::construct_at(reinterpret_cast<ss::relay::Resolver *>(resolver_storage));
    if (!resolver->init(*loop, nameservers, ipv6first != 0, kMaxQueries)) {
        FATAL("failed to initialize c-ares");
    }
    return 0;
}

extern "C" void
resolv_start(const char *hostname, uint16_t port,
             void (*client_cb)(struct sockaddr *, void *),
             void (*free_cb)(void *), void *data)
{
    ss::relay::ResolveCallback cb;
    cb.fn    = &deliver;
    cb.ctx   = reinterpret_cast<void *>(client_cb);
    cb.aux   = reinterpret_cast<void *>(free_cb);
    cb.token = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(data));
    if (resolver == nullptr || !resolver->resolve(hostname, port, cb)) {
        LOGE("resolver: too many queries in flight");
        deliver(cb, nullptr);
    }
}

extern "C" void
resolv_shutdown(struct ss_loop *)
{
    if (resolver == nullptr) {
        return;
    }
    static bool closed;
    closed = false;
    resolver->shutdown(ss::CloseCompletion([](void *, std::uint32_t) { closed = true; }, nullptr, 0));
    while (!closed) {
        loop->run_nowait();
    }
    std::destroy_at(resolver);
    std::destroy_at(loop);
    resolver = nullptr;
    loop     = nullptr;
}
