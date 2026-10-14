/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <cstring>
#include <string_view>

#include "core/buffer.hpp"
#include "test_helpers.hpp"

namespace {

ss::ConstBytes bytes(std::string_view s)
{
    return ss::as_bytes(s.data(), s.size());
}

bool equals(ss::ConstBytes b, std::string_view s)
{
    return b.size() == s.size() && std::memcmp(b.data(), s.data(), s.size()) == 0;
}

void test_append_consume()
{
    ss::FixedBuffer<8> buf;
    SS_CHECK(buf.empty() && buf.capacity() == 8);
    SS_CHECK(buf.append(bytes("hello")));
    SS_CHECK(equals(buf.readable(), "hello"));
    SS_CHECK(buf.consume(2));
    SS_CHECK(equals(buf.readable(), "llo"));
    SS_CHECK(!buf.consume(4));
    // Appending past the tail compacts first.
    SS_CHECK(buf.append(bytes("world")));
    SS_CHECK(equals(buf.readable(), "lloworld"));
    SS_CHECK(!buf.append(bytes("x")));
    SS_CHECK(buf.consume(8) && buf.empty());
}

void test_commit_writable()
{
    ss::FixedBuffer<4> buf;
    auto w = buf.writable();
    SS_CHECK(w.size() == 4);
    std::memcpy(w.data(), "abcd", 4);
    SS_CHECK(buf.commit(4));
    SS_CHECK(buf.full() && buf.writable().empty());
    SS_CHECK(!buf.commit(1));
    SS_CHECK(equals(buf.readable(), "abcd"));
}

void test_prepend()
{
    ss::FixedBuffer<10> buf;
    SS_CHECK(buf.append(bytes("data")));
    // No headroom: payload shifts right.
    SS_CHECK(buf.prepend(bytes("hdr")));
    SS_CHECK(equals(buf.readable(), "hdrdata"));
    SS_CHECK(buf.consume(3));
    // Headroom from the consumed bytes is reused in place.
    SS_CHECK(buf.prepend(bytes("ab")));
    SS_CHECK(equals(buf.readable(), "abdata"));
    SS_CHECK(!buf.prepend(bytes("12345")));
    SS_CHECK(equals(buf.readable(), "abdata"));
}

void test_assign_wipe()
{
    ss::FixedBuffer<4> buf;
    SS_CHECK(!buf.assign(bytes("toolong")));
    SS_CHECK(buf.assign(bytes("key")));
    SS_CHECK(equals(buf.readable(), "key"));
    buf.wipe();
    SS_CHECK(buf.empty());
}

} // namespace

int main()
{
    SS_RUN(test_append_consume);
    SS_RUN(test_commit_writable);
    SS_RUN(test_prepend);
    SS_RUN(test_assign_wipe);
    return 0;
}
