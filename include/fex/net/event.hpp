// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Types shared by every poller backend, plus the concept the backends must satisfy.
// This header performs no syscalls and pulls in no platform headers, so both
// pollers/kqueue.hpp and pollers/epoll.hpp can include it freely.

#include <cerrno>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

namespace fex::net {

// What a registered descriptor should be woken up for.
//
// NOTE: a UDP socket is almost always writable, and the pollers are level-triggered,
// so `write` must be enabled only transiently -- after a send returned
// std::errc::resource_unavailable_try_again -- and dropped as soon as the backlog is
// flushed. Leaving it on turns the event loop into a busy loop.
enum struct interest : std::uint8_t {
    none = 0,
    read = 1,
    write = 2,
    read_write = 3
};

[[nodiscard]] constexpr bool wants_read(interest i) noexcept {
    return (static_cast<std::uint8_t>(i) & static_cast<std::uint8_t>(interest::read)) != 0;
}

[[nodiscard]] constexpr bool wants_write(interest i) noexcept {
    return (static_cast<std::uint8_t>(i) & static_cast<std::uint8_t>(interest::write)) != 0;
}

// One readiness notification.
//
// Contract shared by both backends: an event describes exactly one descriptor, but the
// same descriptor MAY appear more than once in a single wait() batch (kqueue reports one
// kevent per filter, so a read/write-ready socket yields two entries, not necessarily
// adjacent). The pollers do not merge them. Under level-triggering that is harmless --
// OR the flags together if a caller needs the combined view.
struct event {
    int fd = -1;
    std::uint64_t user = 0; // cookie handed to add()/mod()
    bool readable = false;
    bool writable = false;
    bool error = false;  // EPOLLERR / EV_ERROR / EV_EOF carrying a socket error
    bool hangup = false; // EPOLLHUP / EV_EOF
};

// The backend interface. poller.hpp static_asserts the selected backend against it, so
// building for macOS (kqueue) and for Linux (epoll) keeps the two from drifting apart.
//
// wait(out, timeout_ms): timeout_ms < 0 blocks, 0 polls. Returns the number of events
// written to `out`, which is clamped to P::max_batch. An empty `out` is rejected with
// std::errc::invalid_argument. Returning 0 does NOT mean the timeout elapsed: a wake()
// or a signal (EINTR) also returns 0 events. Callers must re-check their own state on
// every return and keep time with their own clock.
template <class P>
concept poller_backend =
    std::movable<P> && !std::copyable<P> &&
    requires(P p, const P cp, int fd, interest i, std::uint64_t user, std::span<event> out, int ms) {
        { P::open() } -> std::same_as<std::expected<P, std::errc>>;
        { p.add(fd, i, user) } -> std::same_as<std::expected<void, std::errc>>;
        { p.mod(fd, i, user) } -> std::same_as<std::expected<void, std::errc>>;
        { p.del(fd) } -> std::same_as<std::expected<void, std::errc>>;
        { p.wait(out, ms) } -> std::same_as<std::expected<std::size_t, std::errc>>;
        { p.wake() } -> std::same_as<std::expected<void, std::errc>>;
        { cp.fd() } -> std::same_as<int>;
        { P::max_batch } -> std::convertible_to<std::size_t>;
    };

namespace detail {

// errno at the point of failure, as an error value for std::expected.
// EAGAIN and EWOULDBLOCK both land on std::errc::resource_unavailable_try_again.
[[nodiscard]] inline std::unexpected<std::errc> fail() noexcept {
    return std::unexpected(std::errc{errno});
}

[[nodiscard]] inline std::unexpected<std::errc> fail(int err) noexcept {
    return std::unexpected(std::errc{err});
}

} // namespace detail

} // namespace fex::net
