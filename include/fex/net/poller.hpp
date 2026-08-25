// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Picks the readiness poller for the platform and exposes it as fex::net::poller.
// The backends are interchangeable: everything below is written against the alias, and
// the concept check keeps the two implementations from drifting apart (the macOS build
// verifies kqueue, `zig build -Dtarget=x86_64-linux-gnu` verifies epoll).

#include <fex/net/event.hpp>
#include <fex/net/socket.hpp>

#if defined(__linux__)
#include <fex/net/pollers/epoll.hpp>
namespace fex::net {
using poller = pollers::epoll;
}
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)
#include <fex/net/pollers/kqueue.hpp>
namespace fex::net {
using poller = pollers::kqueue;
}
#else
#error "fex::net: no poller backend for this platform"
#endif

namespace fex::net {
static_assert(poller_backend<poller>,
              "the selected poller backend does not satisfy fex::net::poller_backend");
}

// ---- Tests -----------------------------------------------------------------

#ifdef FEX_WITH_TESTS

#include <array>
#include <chrono>
#include <thread>

namespace fex::net::detail {

// Two bound loopback sockets: `a` sends, `b` is non-blocking and gets registered.
struct socket_pair {
    udp_socket a;
    udp_socket b;
    endpoint b_local;
};

[[nodiscard]] inline std::expected<socket_pair, std::errc> make_socket_pair() {
    auto a = udp_socket::open(family::v4);
    if (!a) return std::unexpected(a.error());
    auto b = udp_socket::open(family::v4);
    if (!b) return std::unexpected(b.error());
    if (const auto r = a->bind(endpoint::loopback(family::v4, 0)); !r)
        return std::unexpected(r.error());
    if (const auto r = b->bind(endpoint::loopback(family::v4, 0)); !r)
        return std::unexpected(r.error());
    if (const auto r = b->set_nonblocking(true); !r) return std::unexpected(r.error());
    const auto local = b->local_endpoint();
    if (!local) return std::unexpected(local.error());
    return socket_pair{std::move(*a), std::move(*b), *local};
}

[[nodiscard]] inline bool send_probe(socket_pair& sp) {
    constexpr std::array<std::uint8_t, 4> msg{0xDE, 0xAD, 0xBE, 0xEF};
    return sp.a.send_to(msg, sp.b_local).has_value();
}

[[nodiscard]] inline bool drain(udp_socket& sock) {
    std::array<std::uint8_t, 64> buf{};
    endpoint from;
    return sock.recv_from(buf, from).has_value();
}

} // namespace fex::net::detail

TEST_SUITE("fex::net") {

TEST_CASE("poller opens and reports nothing when idle") {
    using namespace fex::net;
    auto p = poller::open();
    REQUIRE(p.has_value());
    if (!p) return;
    REQUIRE(p->fd() >= 0);

    std::array<event, 8> evs{};
    const auto n = p->wait(evs, 0);
    REQUIRE(n.has_value());
    if (n) REQUIRE_EQ(*n, 0);

    // An empty output span would make a blocking wait spin, so it is rejected outright.
    const auto bad = p->wait(std::span<event>{}, 0);
    REQUIRE_FALSE(bad.has_value());
    if (!bad) REQUIRE_EQ(bad.error(), std::errc::invalid_argument);
}

TEST_CASE("poller reports readability with the registered cookie") {
    using namespace fex::net;
    auto p = poller::open();
    auto sp = detail::make_socket_pair();
    REQUIRE(p.has_value());
    REQUIRE(sp.has_value());
    if (!p || !sp) return;

    constexpr std::uint64_t cookie = 0xDEADBEEFull;
    REQUIRE(p->add(sp->b.fd(), interest::read, cookie).has_value());

    std::array<event, 8> evs{};
    auto n = p->wait(evs, 0);
    REQUIRE(n.has_value());
    if (n) REQUIRE_EQ(*n, 0);

    REQUIRE(detail::send_probe(*sp));

    n = p->wait(evs, 1000);
    REQUIRE(n.has_value());
    if (!n || *n != 1) {
        REQUIRE(false);
        return;
    }
    REQUIRE_EQ(evs[0].fd, sp->b.fd());
    REQUIRE_EQ(evs[0].user, cookie);
    REQUIRE(evs[0].readable);
    REQUIRE_FALSE(evs[0].writable);
    REQUIRE_FALSE(evs[0].error);

    // Level-triggered: the event goes away only once the socket is actually drained.
    REQUIRE(detail::drain(sp->b));
    n = p->wait(evs, 0);
    REQUIRE(n.has_value());
    if (n) REQUIRE_EQ(*n, 0);
}

TEST_CASE("poller changes what it watches with mod") {
    using namespace fex::net;
    auto p = poller::open();
    auto sp = detail::make_socket_pair();
    REQUIRE(p.has_value());
    REQUIRE(sp.has_value());
    if (!p || !sp) return;

    REQUIRE(p->add(sp->b.fd(), interest::read, 1).has_value());
    REQUIRE(p->mod(sp->b.fd(), interest::write, 7).has_value());

    // An idle UDP socket has room in its send buffer, so it is writable straight away.
    std::array<event, 8> evs{};
    auto n = p->wait(evs, 1000);
    REQUIRE(n.has_value());
    if (!n) return;
    REQUIRE(*n >= 1);
    bool writable = false;
    for (std::size_t i = 0; i < *n; ++i) {
        if (evs[i].fd != sp->b.fd()) continue;
        REQUIRE_EQ(evs[i].user, 7);
        writable = writable || evs[i].writable;
    }
    REQUIRE(writable);

    // interest::none silences a descriptor without unregistering it.
    REQUIRE(p->mod(sp->b.fd(), interest::none, 7).has_value());
    REQUIRE(detail::send_probe(*sp));
    n = p->wait(evs, 50);
    REQUIRE(n.has_value());
    if (n) REQUIRE_EQ(*n, 0);
}

TEST_CASE("poller stops reporting after del and re-registers cleanly") {
    using namespace fex::net;
    auto p = poller::open();
    auto sp = detail::make_socket_pair();
    REQUIRE(p.has_value());
    REQUIRE(sp.has_value());
    if (!p || !sp) return;
    const int fd = sp->b.fd();

    REQUIRE(p->add(fd, interest::read, 1).has_value());
    REQUIRE(p->del(fd).has_value());

    REQUIRE(detail::send_probe(*sp));
    std::array<event, 8> evs{};
    const auto n = p->wait(evs, 50);
    REQUIRE(n.has_value());
    if (n) REQUIRE_EQ(*n, 0);

    // Deleting an unregistered descriptor reports the same error on both backends.
    const auto again = p->del(fd);
    REQUIRE_FALSE(again.has_value());
    if (!again) REQUIRE_EQ(again.error(), std::errc::no_such_file_or_directory);

    // add() is idempotent: registering twice updates the cookie instead of failing.
    REQUIRE(p->add(fd, interest::read, 2).has_value());
    REQUIRE(p->add(fd, interest::read, 3).has_value());
    const auto after = p->wait(evs, 1000);
    REQUIRE(after.has_value());
    if (!after || *after < 1) {
        REQUIRE(false);
        return;
    }
    REQUIRE_EQ(evs[0].fd, fd);
    REQUIRE_EQ(evs[0].user, 3);
}

TEST_CASE("poller reports read and write readiness for one descriptor") {
    using namespace fex::net;
    auto p = poller::open();
    auto sp = detail::make_socket_pair();
    REQUIRE(p.has_value());
    REQUIRE(sp.has_value());
    if (!p || !sp) return;

    // macOS delivers loopback datagrams asynchronously, and a UDP socket is writable from
    // the moment it exists -- so watching for writes too would make every wait() return
    // instantly with only the write event, long before the datagram lands. Wait for the
    // read side on its own first; that pins the arrival down.
    REQUIRE(p->add(sp->b.fd(), interest::read, 9).has_value());
    REQUIRE(detail::send_probe(*sp));

    std::array<event, 8> evs{};
    auto n = p->wait(evs, 1000);
    REQUIRE(n.has_value());
    if (!n || *n < 1) {
        REQUIRE(false);
        return;
    }
    REQUIRE(evs[0].readable);

    // Now both sides are genuinely ready. kqueue emits one entry per filter and epoll one
    // per descriptor; the contract is only that the flags turn up somewhere in the batch.
    // The datagram is deliberately left undrained so the read side stays level-active.
    REQUIRE(p->mod(sp->b.fd(), interest::read_write, 9).has_value());
    bool readable = false;
    bool writable = false;
    for (int round = 0; round < 4 && !(readable && writable); ++round) {
        n = p->wait(evs, 200);
        REQUIRE(n.has_value());
        if (!n) break;
        for (std::size_t i = 0; i < *n; ++i) {
            if (evs[i].fd != sp->b.fd()) continue;
            REQUIRE_EQ(evs[i].user, 9);
            readable = readable || evs[i].readable;
            writable = writable || evs[i].writable;
        }
    }
    REQUIRE(readable);
    REQUIRE(writable);
}

TEST_CASE("poller wake unblocks a blocking wait") {
    using namespace fex::net;
    auto p = poller::open();
    REQUIRE(p.has_value());
    if (!p) return;
    std::array<event, 4> evs{};

    // A wake raised before the wait is sticky, so it is not lost...
    REQUIRE(p->wake().has_value());
    auto n = p->wait(evs, -1);
    REQUIRE(n.has_value());
    if (n) REQUIRE_EQ(*n, 0);

    // ...and it is consumed exactly once.
    n = p->wait(evs, 0);
    REQUIRE(n.has_value());
    if (n) REQUIRE_EQ(*n, 0);

    // A wake from another thread interrupts a blocking wait. Assertions stay on this
    // thread; the helper only sleeps and pokes the poller.
    const auto started = std::chrono::steady_clock::now();
    std::thread waker([&p] {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        (void)p->wake();
    });
    n = p->wait(evs, -1);
    waker.join();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - started)
                             .count();
    REQUIRE(n.has_value());
    if (n) REQUIRE_EQ(*n, 0);
    REQUIRE(elapsed < 5000);
}

TEST_CASE("poller honours its timeout") {
    using namespace fex::net;
    auto p = poller::open();
    REQUIRE(p.has_value());
    if (!p) return;

    std::array<event, 4> evs{};
    const auto started = std::chrono::steady_clock::now();
    const auto n = p->wait(evs, 30);
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::steady_clock::now() - started)
                             .count();
    REQUIRE(n.has_value());
    if (n) REQUIRE_EQ(*n, 0);
    REQUIRE(elapsed >= 25); // a little slack for clock granularity
}

} // TEST_SUITE

#endif // FEX_WITH_TESTS
