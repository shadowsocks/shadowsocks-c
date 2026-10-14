/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <cstdint>
#include <cstring>

#include "core/arena.hpp"
#include "test_helpers.hpp"

namespace {

struct Pair {
    int a;
    double b;
};

void test_allocate_alignment()
{
    ss::MonotonicArena arena;
    SS_CHECK(arena.reserve(256));
    auto c = arena.allocate(1, 1);
    SS_CHECK(c);
    auto d = arena.allocate(8, 64);
    SS_CHECK(d);
    SS_CHECK(reinterpret_cast<std::uintptr_t>(d->data()) % 64 == 0);
    auto p = arena.make<Pair>(Pair{ 3, 1.5 });
    SS_CHECK(p && (*p)->a == 3 && (*p)->b == 1.5);
    SS_CHECK(!arena.allocate(8, 3));
}

void test_exhaustion_and_reset()
{
    ss::MonotonicArena arena;
    SS_CHECK(!arena.allocate(1));
    SS_CHECK(arena.reserve(64));
    SS_CHECK(arena.allocate(64, 1));
    auto over = arena.allocate(1, 1);
    SS_CHECK(!over && over.error().code == ss::Errc::exhausted);
    arena.reset();
    SS_CHECK(arena.used() == 0 && arena.peak() == 64);
    SS_CHECK(arena.allocate(32, 1));
}

void test_intern_and_arrays()
{
    ss::MonotonicArena arena;
    SS_CHECK(arena.reserve(128));
    auto s = arena.intern("aes-256-gcm");
    SS_CHECK(s && *s == "aes-256-gcm");
    SS_CHECK(s->data()[s->size()] == '\0');
    auto empty = arena.intern("");
    SS_CHECK(empty && empty->empty());
    auto ports = arena.make_array<std::uint16_t>(4);
    SS_CHECK(ports && ports->size() == 4 && (*ports)[3] == 0);
}

} // namespace

int main()
{
    SS_RUN(test_allocate_alignment);
    SS_RUN(test_exhaustion_and_reset);
    SS_RUN(test_intern_and_arrays);
    return 0;
}
