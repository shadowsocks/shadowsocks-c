/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef SS_CORE_RESULT_HPP
#define SS_CORE_RESULT_HPP

// Error-or-value return type for code built without exceptions.
//
// The interface is a subset of C++23 std::expected (has_value, value, error,
// and_then, transform, value_or) so Result can become an alias of
// std::expected once the toolchain floor allows it.

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

namespace ss {

enum class Errc : std::uint8_t {
    exhausted, // a fixed-capacity pool or table is full
    io,        // socket or file error; Error::sys holds errno
    again,     // operation would block
    crypto,    // authentication or cipher failure
    protocol,  // malformed peer input
    config,    // invalid configuration
    closed,    // object is closing or already closed
    invalid,   // invalid argument from the caller
};

struct Error {
    Errc code;
    int sys = 0;

    friend constexpr bool operator==(const Error &, const Error &) = default;
};

template <class E>
struct Unexpected {
    E value;
};

template <class E>
constexpr Unexpected<std::decay_t<E> > fail(E &&e)
{
    return { std::forward<E>(e) };
}

constexpr Unexpected<Error> fail(Errc code, int sys = 0)
{
    return { Error{ code, sys } };
}

namespace detail {
[[noreturn]] inline void result_misuse() noexcept
{
    // Accessing the wrong alternative is a programming error. There is no
    // exception to throw, so stop here instead of reading garbage.
    std::abort();
}
} // namespace detail

template <class T, class E = Error>
class [[nodiscard]] Result {
    static_assert(!std::is_reference_v<T>, "Result<T&> is not supported; use a pointer");

public:
    using value_type = T;
    using error_type = E;

    template <class U = T>
    requires std::is_constructible_v<T, U &&>
    constexpr Result(U &&v) noexcept(std::is_nothrow_constructible_v<T, U &&>) // NOLINT(google-explicit-constructor)
        : ok_(true)
    {
        std::construct_at(&value_, std::forward<U>(v));
    }

    template <class G>
    constexpr Result(Unexpected<G> &&e) noexcept // NOLINT(google-explicit-constructor)
        : ok_(false)
    {
        std::construct_at(&error_, std::move(e.value));
    }

    Result(const Result &other) requires std::is_copy_constructible_v<T>
        : ok_(other.ok_)
    {
        if (ok_) {
            std::construct_at(&value_, other.value_);
        } else {
            std::construct_at(&error_, other.error_);
        }
    }

    Result(Result &&other) noexcept(std::is_nothrow_move_constructible_v<T>)
        : ok_(other.ok_)
    {
        if (ok_) {
            std::construct_at(&value_, std::move(other.value_));
        } else {
            std::construct_at(&error_, std::move(other.error_));
        }
    }

    Result &operator=(const Result &) = delete;

    Result &operator=(Result &&other) noexcept(std::is_nothrow_move_constructible_v<T>)
    {
        if (this != &other) {
            this->~Result();
            std::construct_at(this, std::move(other));
        }
        return *this;
    }

    ~Result()
    {
        if (ok_) {
            std::destroy_at(&value_);
        } else {
            std::destroy_at(&error_);
        }
    }

    constexpr bool has_value() const noexcept { return ok_; }
    constexpr explicit operator bool() const noexcept { return ok_; }

    constexpr T &value() & noexcept
    {
        if (!ok_) {
            detail::result_misuse();
        }
        return value_;
    }
    constexpr const T &value() const & noexcept
    {
        if (!ok_) {
            detail::result_misuse();
        }
        return value_;
    }
    constexpr T &&value() && noexcept
    {
        if (!ok_) {
            detail::result_misuse();
        }
        return std::move(value_);
    }

    constexpr T &operator*() & noexcept { return value(); }
    constexpr const T &operator*() const & noexcept { return value(); }
    constexpr T &&operator*() && noexcept { return std::move(*this).value(); }
    constexpr T *operator->() noexcept { return &value(); }
    constexpr const T *operator->() const noexcept { return &value(); }

    constexpr const E &error() const noexcept
    {
        if (ok_) {
            detail::result_misuse();
        }
        return error_;
    }

    template <class U>
    constexpr T value_or(U &&fallback) const & { return ok_ ? value_ : static_cast<T>(std::forward<U>(fallback)); }

    template <class F>
    constexpr auto and_then(F &&f) &&
    {
        using R = std::invoke_result_t<F, T &&>;
        if (ok_) {
            return std::forward<F>(f)(std::move(value_));
        }
        return R(Unexpected<E>{ error_ });
    }

    template <class F>
    constexpr auto transform(F &&f) &&
    {
        using U = std::invoke_result_t<F, T &&>;
        if (ok_) {
            return Result<U, E>(std::forward<F>(f)(std::move(value_)));
        }
        return Result<U, E>(Unexpected<E>{ error_ });
    }

private:
    union {
        T value_;
        E error_;
    };
    bool ok_;
};

template <class E>
class [[nodiscard]] Result<void, E> {
public:
    using value_type = void;
    using error_type = E;

    constexpr Result() noexcept : ok_(true), error_() {}

    template <class G>
    constexpr Result(Unexpected<G> &&e) noexcept // NOLINT(google-explicit-constructor)
        : ok_(false), error_(std::move(e.value))
    {
    }

    constexpr bool has_value() const noexcept { return ok_; }
    constexpr explicit operator bool() const noexcept { return ok_; }
    constexpr void value() const noexcept
    {
        if (!ok_) {
            detail::result_misuse();
        }
    }
    constexpr const E &error() const noexcept
    {
        if (ok_) {
            detail::result_misuse();
        }
        return error_;
    }

private:
    bool ok_;
    E error_;
};

using Status = Result<void>;

// Propagate an error out of a function returning any Result.
#define SS_TRY(expr)                                         \
    do {                                                     \
        auto ss_try_result_ = (expr);                        \
        if (!ss_try_result_) {                               \
            return ::ss::fail(ss_try_result_.error());       \
        }                                                    \
    } while (0)

// Declare `name` as the value of a Result, or propagate its error.
#define SS_TRY_ASSIGN(name, expr)                       \
    auto name##_result_ = (expr);                       \
    if (!name##_result_) {                              \
        return ::ss::fail(name##_result_.error());      \
    }                                                   \
    auto name = std::move(*name##_result_)

} // namespace ss

#endif
