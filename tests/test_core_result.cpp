/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <memory>
#include <utility>

#include "core/result.hpp"
#include "test_helpers.hpp"

namespace {

ss::Result<int> parse_positive(int v)
{
    if (v <= 0) {
        return ss::fail(ss::Errc::invalid);
    }
    return v;
}

ss::Status check_twice(int v)
{
    SS_TRY(parse_positive(v));
    SS_TRY(parse_positive(v - 1));
    return {};
}

void test_value_and_error()
{
    auto ok = parse_positive(5);
    SS_CHECK(ok.has_value());
    SS_CHECK(*ok == 5);
    SS_CHECK(ok.value_or(0) == 5);

    auto bad = parse_positive(-1);
    SS_CHECK(!bad);
    SS_CHECK(bad.error().code == ss::Errc::invalid);
    SS_CHECK(bad.value_or(42) == 42);
}

void test_status_and_try()
{
    SS_CHECK(check_twice(3).has_value());
    auto r = check_twice(1);
    SS_CHECK(!r);
    SS_CHECK(r.error() == ss::Error{ ss::Errc::invalid, 0 });
}

void test_move_only_value()
{
    auto make = []() -> ss::Result<std::unique_ptr<int> > { return std::make_unique<int>(7); };
    auto r    = make();
    SS_CHECK(r);
    std::unique_ptr<int> p = std::move(r).value();
    SS_CHECK(*p == 7);
}

void test_monadic()
{
    auto doubled = parse_positive(4).transform([](int v) { return v * 2; });
    SS_CHECK(doubled && *doubled == 8);
    auto chained = parse_positive(4).and_then([](int v) { return parse_positive(v - 10); });
    SS_CHECK(!chained && chained.error().code == ss::Errc::invalid);
}

void test_sys_errno()
{
    ss::Result<int> r = ss::fail(ss::Errc::io, 104);
    SS_CHECK(r.error().sys == 104);
}

} // namespace

int main()
{
    SS_RUN(test_value_and_error);
    SS_RUN(test_status_and_try);
    SS_RUN(test_move_only_value);
    SS_RUN(test_monadic);
    SS_RUN(test_sys_errno);
    return 0;
}
