// SPDX-License-Identifier: GPL-3.0-or-later
// Legacy buffer helpers in the C crypto reference (tests/reference/crypto.h):
// balloc, brealloc and bprepend.
#include <cstdlib>
#include <cstring>

#include "test_helpers.hpp"

#include "crypto.h"

extern "C" {
int verbose = 0;
// Provide the nonce_cache symbol needed by the crypto reference.
struct cache *nonce_cache = nullptr;
}

namespace {

void test_balloc()
{
    buffer_t buf;
    std::memset(&buf, 0, sizeof(buf));

    SS_CHECK(balloc(&buf, 100) == 100);
    SS_CHECK(buf.data != nullptr);
    SS_CHECK(buf.capacity >= 100);
    SS_CHECK(buf.len == 0);
    SS_CHECK(buf.idx == 0);

    bfree(&buf);
    SS_CHECK(buf.data == nullptr);
    SS_CHECK(buf.capacity == 0);
}

void test_brealloc()
{
    buffer_t buf;
    std::memset(&buf, 0, sizeof(buf));

    balloc(&buf, 50);
    buf.len = 10;

    // Grow the buffer.
    SS_CHECK(brealloc(&buf, 10, 200) == 200);
    SS_CHECK(buf.capacity >= 200);
    SS_CHECK(buf.len == 10);

    bfree(&buf);
}

void test_bprepend()
{
    buffer_t dst;
    buffer_t src;
    std::memset(&dst, 0, sizeof(dst));
    std::memset(&src, 0, sizeof(src));

    balloc(&dst, 100);
    balloc(&src, 100);

    std::memcpy(src.data, "HEADER", 6);
    src.len = 6;

    std::memcpy(dst.data, "BODY", 4);
    dst.len = 4;

    SS_CHECK(bprepend(&dst, &src, 200) == 10);
    SS_CHECK(dst.len == 10);
    SS_CHECK(std::memcmp(dst.data, "HEADERBODY", 10) == 0);

    bfree(&dst);
    bfree(&src);
}

void test_balloc_zero()
{
    buffer_t buf;
    std::memset(&buf, 0, sizeof(buf));

    SS_CHECK(balloc(&buf, 0) == 0);
    // A zero-capacity buffer should still succeed.
    bfree(&buf);
}

} // namespace

int main()
{
    SS_RUN(test_balloc);
    SS_RUN(test_brealloc);
    SS_RUN(test_bprepend);
    SS_RUN(test_balloc_zero);
    return 0;
}
