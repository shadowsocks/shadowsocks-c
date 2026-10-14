/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_ALLOC_PROBE_HPP
#define SS_ALLOC_PROBE_HPP

// Mark points in a test program for tests/alloc_audit/check_steady.py.
//
// When the alloc_counter shim is preloaded (it sets SS_ALLOC_AUDIT_OUT and
// handles SIGUSR2), each mark appends the running allocation count to the
// audit file. Without the shim the marks do nothing, so the same test binary
// also runs normally.

#include <csignal>
#include <cstdlib>

namespace ss::test {

inline bool alloc_audit_enabled()
{
    return std::getenv("SS_ALLOC_AUDIT_OUT") != nullptr;
}

inline void alloc_mark()
{
#ifdef SIGUSR2
    if (alloc_audit_enabled()) {
        std::raise(SIGUSR2);
    }
#endif
}

} // namespace ss::test

#endif
