// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Level-triggered readiness poller on top of kqueue (macOS, FreeBSD, NetBSD, DragonFly).
// Selected automatically by <fex/net/poller.hpp>; include that instead of this header.

#include <sys/types.h>

#include <sys/event.h>
#include <sys/time.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <type_traits>
#include <utility>

#include <fex/net/event.hpp>
#include <fex/net/socket.hpp> // unique_fd

#if !defined(EVFILT_USER)
#error "fex::net: the kqueue backend needs EVFILT_USER for wake() (OpenBSD lacks it)"
#endif

namespace fex::net::detail {

// kevent::udata is void* on macOS/FreeBSD but intptr_t on NetBSD, so the cookie
// conversion has to be written once against whatever the platform declares.
using kq_udata = decltype(std::declval<struct kevent>().udata);

template <class T = kq_udata>
[[nodiscard]] inline T to_udata(std::uint64_t user) noexcept {
    if constexpr (std::is_pointer_v<T>)
        return reinterpret_cast<T>(static_cast<std::uintptr_t>(user));
    else
        return static_cast<T>(user);
}

template <class T = kq_udata>
[[nodiscard]] inline std::uint64_t from_udata(T udata) noexcept {
    if constexpr (std::is_pointer_v<T>)
        return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(udata));
    else
        return static_cast<std::uint64_t>(udata);
}

} // namespace fex::net::detail

namespace fex::net::pollers {

class kqueue {
public:
    // Upper bound on the events one wait() can report; a larger span is clamped.
    static constexpr std::size_t max_batch = 128;

    kqueue() noexcept = default;
    kqueue(kqueue&&) noexcept = default;
    kqueue& operator=(kqueue&&) noexcept = default;

    [[nodiscard]] static std::expected<kqueue, std::errc> open() noexcept {
        const int raw = ::kqueue();
        if (raw < 0) return detail::fail();
        kqueue p{unique_fd{raw}};
        if (::fcntl(raw, F_SETFD, FD_CLOEXEC) < 0) return detail::fail();

        // EV_CLEAR makes the wake knote auto-reset once delivered, so repeated wake()s
        // before a wait() coalesce into a single return instead of firing forever.
        struct kevent change {};
        EV_SET(&change, wake_ident, EVFILT_USER, EV_ADD | EV_CLEAR | EV_RECEIPT, 0, 0,
               detail::to_udata(0));
        int err = 0;
        const auto sent = p.submit(&change, 1, &err);
        if (!sent) return std::unexpected(sent.error());
        if (err != 0) return detail::fail(err);
        return p;
    }

    [[nodiscard]] int fd() const noexcept { return kq_.get(); }

    // EV_ADD is idempotent on kqueue, so add() and mod() are the same operation.
    [[nodiscard]] std::expected<void, std::errc> add(int fd, interest i, std::uint64_t user) noexcept {
        return mod(fd, i, user);
    }

    // Each filter is added or removed individually; EV_ADD on an existing knote also
    // refreshes its udata, so the cookie stays current on both filters.
    [[nodiscard]] std::expected<void, std::errc> mod(int fd, interest i, std::uint64_t user) noexcept {
        struct kevent changes[2] {};
        set_filter(changes[0], fd, EVFILT_READ, wants_read(i), user);
        set_filter(changes[1], fd, EVFILT_WRITE, wants_write(i), user);

        int errs[2] = {0, 0};
        const auto sent = submit(changes, 2, errs);
        if (!sent) return std::unexpected(sent.error());

        for (int k = 0; k < 2; ++k) {
            if (errs[k] == 0) continue;
            // Dropping a filter that was never registered is expected, not a failure.
            const bool removing = (changes[k].flags & EV_DELETE) != 0;
            if (removing && errs[k] == ENOENT) continue;
            return detail::fail(errs[k]);
        }
        return {};
    }

    [[nodiscard]] std::expected<void, std::errc> del(int fd) noexcept {
        struct kevent changes[2] {};
        set_filter(changes[0], fd, EVFILT_READ, false, 0);
        set_filter(changes[1], fd, EVFILT_WRITE, false, 0);

        int errs[2] = {0, 0};
        const auto sent = submit(changes, 2, errs);
        if (!sent) return std::unexpected(sent.error());

        for (int k = 0; k < 2; ++k)
            if (errs[k] != 0 && errs[k] != ENOENT) return detail::fail(errs[k]);
        // Nothing was registered at all: report it the way epoll_ctl(EPOLL_CTL_DEL) does.
        if (errs[0] == ENOENT && errs[1] == ENOENT) return detail::fail(ENOENT);
        return {};
    }

    // See the contract on fex::net::poller_backend: 0 events does not mean "timed out",
    // and one descriptor can occupy two entries (kqueue reports per filter).
    [[nodiscard]] std::expected<std::size_t, std::errc> wait(std::span<event> out,
                                                             int timeout_ms) noexcept {
        // kevent() with nevents == 0 returns immediately, which would silently turn a
        // blocking wait into a busy loop.
        if (out.empty()) return std::unexpected(std::errc::invalid_argument);
        const auto want = static_cast<int>(std::min(out.size(), max_batch));

        struct kevent events[max_batch] {};
        struct timespec ts {};
        const struct timespec* timeout = nullptr;
        if (timeout_ms >= 0) {
            ts.tv_sec = timeout_ms / 1000;
            ts.tv_nsec = static_cast<long>(timeout_ms % 1000) * 1000000L;
            timeout = &ts;
        }

        const int got = ::kevent(kq_.get(), nullptr, 0, events, want, timeout);
        if (got < 0) {
            // A signal is a reason to re-check the caller's own state, so surface it as
            // an ordinary empty return rather than retrying with a recomputed timeout.
            if (errno == EINTR) return std::size_t{0};
            return detail::fail();
        }

        std::size_t n = 0;
        for (int i = 0; i < got; ++i) {
            const struct kevent& k = events[i];
            if (k.filter == EVFILT_USER) continue; // wake(); never reported to the caller

            event e{};
            e.fd = static_cast<int>(k.ident);
            e.user = detail::from_udata(k.udata);
            e.readable = k.filter == EVFILT_READ;
            e.writable = k.filter == EVFILT_WRITE;
            if ((k.flags & EV_EOF) != 0) {
                e.hangup = true;
                if (k.fflags != 0) e.error = true; // fflags carries the socket error
            }
            if ((k.flags & EV_ERROR) != 0) e.error = true;
            out[n++] = e;
        }
        return n;
    }

    // Safe to call from any thread against a live poller. Moving the poller while
    // another thread may call wake() is a data race -- create it once and keep it put.
    [[nodiscard]] std::expected<void, std::errc> wake() noexcept {
        struct kevent change {};
        EV_SET(&change, wake_ident, EVFILT_USER, 0, NOTE_TRIGGER, 0, detail::to_udata(0));
        for (;;) {
            if (::kevent(kq_.get(), &change, 1, nullptr, 0, nullptr) >= 0) return {};
            if (errno == EINTR) continue;
            return detail::fail();
        }
    }

private:
    // Idents live in a per-filter namespace, so this cannot collide with a descriptor.
    static constexpr std::uintptr_t wake_ident = 0;

    explicit kqueue(unique_fd kq) noexcept: kq_{std::move(kq)} {}

    static void set_filter(struct kevent& change, int fd, std::int16_t filter, bool wanted,
                           std::uint64_t user) noexcept {
        const auto flags = static_cast<std::uint16_t>(
            wanted ? (EV_ADD | EV_ENABLE | EV_RECEIPT) : (EV_DELETE | EV_RECEIPT));
        EV_SET(&change, static_cast<std::uintptr_t>(fd), filter, flags, 0, 0,
               detail::to_udata(user));
    }

    // EV_RECEIPT makes kevent() emit exactly one result per change, in order, with that
    // change's errno in `data` and nothing dequeued from the queue. Without it a partial
    // failure is indistinguishable from a whole-call failure. At most 2 changes are ever
    // submitted (one per filter), which is what `results` is sized for.
    [[nodiscard]] std::expected<void, std::errc> submit(struct kevent* changes, int n,
                                                        int* errs) noexcept {
        struct kevent results[2] {};
        const struct timespec immediate {};
        int got = 0;
        for (;;) {
            got = ::kevent(kq_.get(), changes, n, results, n, &immediate);
            if (got >= 0) break;
            if (errno == EINTR) continue;
            return detail::fail();
        }
        for (int i = 0; i < n; ++i)
            errs[i] = (i < got && (results[i].flags & EV_ERROR) != 0)
                          ? static_cast<int>(results[i].data)
                          : 0;
        return {};
    }

    unique_fd kq_;
};

} // namespace fex::net::pollers
