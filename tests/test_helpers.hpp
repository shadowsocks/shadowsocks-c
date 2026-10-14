/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_TEST_HELPERS_HPP
#define SS_TEST_HELPERS_HPP

// Minimal harness for the C++ unit tests. Tests are built without
// exceptions, so a failed check reports its location and aborts.

#include <cstdio>
#include <cstdlib>

#define SS_CHECK(...)                                                         \
    do {                                                                      \
        if (!(__VA_ARGS__)) {                                                      \
            std::fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__,       \
                         __LINE__, #__VA_ARGS__);                                 \
            std::abort();                                                     \
        }                                                                     \
    } while (0)

#define SS_RUN(test)                                                          \
    do {                                                                      \
        test();                                                               \
        std::printf("ok %s\n", #test);                                        \
    } while (0)

#endif
