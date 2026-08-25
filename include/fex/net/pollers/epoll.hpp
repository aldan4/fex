// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Level-triggered readiness poller on top of epoll (Linux).
// Selected automatically by <fex/net/poller.hpp>; include that instead of this header.

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <utility>

#include <fex/types.hpp>

#include <fex/net/event.hpp>
#include <fex/net/socket.hpp> // unique_fd

namespace fex::net::pollers {

class epoll {
public:
    // Upper bound on the events one wait() can report; a larger span is clamped.
    static constexpr std::size_t max_batch = 128;

    epoll() = default;
    epoll(epoll&&) = default;
    epoll& operator=(epoll&&) = default;

    [[nodiscard]] static std::expected<epoll, std::errc> open() {
        const int raw_ep = ::epoll_create1(EPOLL_CLOEXEC);
        if (raw_ep < 0) return detail::fail();
        unique_fd ep{raw_ep};

        // A counting eventfd: several wake()s before a wait() coalesce into one wakeup,
        // and a wake() raised before the wait is still pending when it starts.
        const int raw_wake = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (raw_wake < 0) return detail::fail();
        unique_fd wake{raw_wake};

        struct epoll_event change {};
        change.events = EPOLLIN;
        change.data.fd = raw_wake;
        if (::epoll_ctl(raw_ep, EPOLL_CTL_ADD, raw_wake, &change) < 0) return detail::fail();

        epoll p{std::move(ep), std::move(wake)};
        return p;
    }

    [[nodiscard]] int fd() const noexcept { return ep_.get(); }

    // Registering a descriptor twice updates it instead of failing, to match kqueue.
    [[nodiscard]] std::expected<void, std::errc> add(int fd, interest i, std::uint64_t user) {
        struct epoll_event change {};
        change.events = to_events(i);
        change.data.fd = fd;
        if (::epoll_ctl(ep_.get(), EPOLL_CTL_ADD, fd, &change) < 0) {
            if (errno != EEXIST) return detail::fail();
            if (::epoll_ctl(ep_.get(), EPOLL_CTL_MOD, fd, &change) < 0) return detail::fail();
        }
        users_.insert_or_assign(fd, user);
        return {};
    }

    [[nodiscard]] std::expected<void, std::errc> mod(int fd, interest i, std::uint64_t user) {
        struct epoll_event change {};
        change.events = to_events(i);
        change.data.fd = fd;
        if (::epoll_ctl(ep_.get(), EPOLL_CTL_MOD, fd, &change) < 0) return detail::fail();
        users_.insert_or_assign(fd, user);
        return {};
    }

    // Always del() before close(): a descriptor that was dup'd elsewhere stays registered
    // when one copy is closed, and the registration would outlive the caller's interest.
    [[nodiscard]] std::expected<void, std::errc> del(int fd) noexcept {
        if (::epoll_ctl(ep_.get(), EPOLL_CTL_DEL, fd, nullptr) < 0) return detail::fail();
        users_.erase(fd);
        return {};
    }

    // See the contract on fex::net::poller_backend: 0 events does not mean "timed out".
    [[nodiscard]] std::expected<std::size_t, std::errc> wait(std::span<event> out,
                                                             int timeout_ms) noexcept {
        // epoll_wait rejects maxevents <= 0 with EINVAL; reject it here so both backends
        // report the same thing.
        if (out.empty()) return std::unexpected(std::errc::invalid_argument);
        const auto want = static_cast<int>(std::min(out.size(), max_batch));

        struct epoll_event events[max_batch] {};
        const int got = ::epoll_wait(ep_.get(), events, want, timeout_ms < 0 ? -1 : timeout_ms);
        if (got < 0) {
            // A signal is a reason to re-check the caller's own state, so surface it as
            // an ordinary empty return rather than retrying with a recomputed timeout.
            if (errno == EINTR) return std::size_t{0};
            return detail::fail();
        }

        std::size_t n = 0;
        for (int i = 0; i < got; ++i) {
            const int fd = events[i].data.fd;
            if (fd == wake_.get()) { // wake(); never reported to the caller
                drain_wake();
                continue;
            }
            event e{};
            e.fd = fd;
            // epoll_data is a union, so the descriptor takes the one data word and the
            // 64-bit cookie lives here instead. kqueue carries both natively.
            if (const auto it = users_.find(fd); it != users_.end()) e.user = it->second;
            e.readable = (events[i].events & EPOLLIN) != 0;
            e.writable = (events[i].events & EPOLLOUT) != 0;
            e.error = (events[i].events & EPOLLERR) != 0;
            e.hangup = (events[i].events & EPOLLHUP) != 0;
            out[n++] = e;
        }
        return n;
    }

    // Safe to call from any thread against a live poller. Moving the poller while
    // another thread may call wake() is a data race -- create it once and keep it put.
    [[nodiscard]] std::expected<void, std::errc> wake() noexcept {
        const std::uint64_t one = 1;
        for (;;) {
            if (::write(wake_.get(), &one, sizeof(one)) == static_cast<ssize_t>(sizeof(one)))
                return {};
            if (errno == EINTR) continue;
            // The counter is saturated, so a wakeup is already pending: nothing to do.
            if (errno == EAGAIN || errno == EWOULDBLOCK) return {};
            return detail::fail();
        }
    }

private:
    epoll(unique_fd ep, unique_fd wake) noexcept: ep_{std::move(ep)}, wake_{std::move(wake)} {}

    // Never EPOLLET: these pollers are level-triggered by contract.
    [[nodiscard]] static std::uint32_t to_events(interest i) noexcept {
        return (wants_read(i) ? std::uint32_t{EPOLLIN} : 0u) |
               (wants_write(i) ? std::uint32_t{EPOLLOUT} : 0u);
    }

    void drain_wake() noexcept {
        std::uint64_t counter = 0;
        for (;;) {
            if (::read(wake_.get(), &counter, sizeof(counter)) >= 0) return;
            if (errno == EINTR) continue;
            return; // EAGAIN: already drained by a concurrent reader
        }
    }

    unique_fd ep_;
    unique_fd wake_;
    hash_map<int, std::uint64_t> users_;
};

} // namespace fex::net::pollers
