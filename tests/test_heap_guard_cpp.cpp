/* SPDX-License-Identifier: GPL-3.0-or-later */
// The library heaps (src/core/heap_guard.cpp): a request no fixed heap can
// serve must fall back to the system allocator instead of failing. libuv
// aborts when growing its watcher array fails, which a poll on a high fd
// triggers (the array grows to next_pow2(fd) pointers).
#include <cstdio>
#include <cstring>

#ifndef _WIN32
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#include <uv.h>

#include "core/heap_guard.hpp"
#include "test_helpers.hpp"

extern "C" {
int verbose = 0;
}

namespace {

void test_realloc_past_largest_class()
{
#ifndef _WIN32
    constexpr int kHighFd = 16380; // 16384 * 8 bytes > the largest size class
    rlimit lim{};
    SS_CHECK(getrlimit(RLIMIT_NOFILE, &lim) == 0);
    if (lim.rlim_cur <= static_cast<rlim_t>(kHighFd)) {
        lim.rlim_cur = kHighFd + 16;
        if (lim.rlim_max != RLIM_INFINITY && lim.rlim_max < lim.rlim_cur) {
            std::printf("skip: RLIMIT_NOFILE hard limit %llu too low\n",
                        static_cast<unsigned long long>(lim.rlim_max));
            return;
        }
        if (setrlimit(RLIMIT_NOFILE, &lim) != 0) {
            std::printf("skip: cannot raise RLIMIT_NOFILE\n");
            return;
        }
    }
    uv_loop_t loop;
    SS_CHECK(uv_loop_init(&loop) == 0);
    // A low fd first, so the watcher array starts small inside the heap.
    int low = socket(AF_INET, SOCK_DGRAM, 0);
    SS_CHECK(low >= 0);
    uv_poll_t low_poll;
    SS_CHECK(uv_poll_init(&loop, &low_poll, low) == 0);
    SS_CHECK(uv_poll_start(&low_poll, UV_READABLE, [](uv_poll_t *, int, int) {}) == 0);
    SS_CHECK(uv_run(&loop, UV_RUN_NOWAIT) >= 0);
    std::size_t before = ss::heap_report().fallbacks;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    SS_CHECK(fd >= 0);
    SS_CHECK(dup2(fd, kHighFd) == kHighFd);
    close(fd);
    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len        = sizeof(addr);
    SS_CHECK(bind(kHighFd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    SS_CHECK(getsockname(kHighFd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    static int readable = 0;
    uv_poll_t poll;
    SS_CHECK(uv_poll_init(&loop, &poll, kHighFd) == 0);
    SS_CHECK(uv_poll_start(&poll, UV_READABLE, [](uv_poll_t *h, int status, int) {
        if (status == 0) {
            ++readable;
            uv_poll_stop(h);
        }
    }) == 0);
    SS_CHECK(ss::heap_report().fallbacks > before); // the array moved out of the heap
    // Both watchers still work after the move.
    SS_CHECK(sendto(low, "x", 1, 0, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 1);
    for (int i = 0; i < 200 && readable == 0; ++i) { // 2 s, not forever
        SS_CHECK(uv_run(&loop, UV_RUN_NOWAIT) >= 0);
        usleep(10000);
    }
    SS_CHECK(readable == 1);
    uv_close(reinterpret_cast<uv_handle_t *>(&low_poll), nullptr);
    close(low);
    uv_close(reinterpret_cast<uv_handle_t *>(&poll), nullptr);
    SS_CHECK(uv_run(&loop, UV_RUN_DEFAULT) == 0);
    SS_CHECK(uv_loop_close(&loop) == 0);
    close(kHighFd);
#endif
}

} // namespace

int main()
{
    ss::LibraryHeapBudgets budgets;
    budgets.uv    = 64 << 10;
    budgets.cares = 256 << 10;
    SS_CHECK(ss::install_library_heaps(budgets));
    SS_RUN(test_realloc_past_largest_class);
    return 0;
}
