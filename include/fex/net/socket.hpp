// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Non-owning-free POSIX UDP sockets: an fd guard, a numeric address type and a thin
// datagram socket. Every call that can fail returns std::expected<T, std::errc>; errno
// is never left for the caller to read.

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <charconv>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>

#include <fex/net/event.hpp>

#if defined(FEX_WITH_TESTS) || defined(FEX_WITH_BENCHS)
#include <doctest/doctest.h>
#endif

namespace fex::net {

// ---- unique_fd -------------------------------------------------------------

// Move-only owner of a file descriptor; closes it on destruction.
class unique_fd {
public:
    unique_fd() noexcept = default;
    explicit unique_fd(int fd) noexcept: fd_{fd} {}

    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;

    unique_fd(unique_fd&& other) noexcept: fd_{other.fd_} { other.fd_ = -1; }

    unique_fd& operator=(unique_fd&& other) noexcept {
        if (this != &other) {
            reset(other.fd_);
            other.fd_ = -1;
        }
        return *this;
    }

    ~unique_fd() { reset(); }

    [[nodiscard]] int get() const noexcept { return fd_; }

    [[nodiscard]] int release() noexcept {
        const int fd = fd_;
        fd_ = -1;
        return fd;
    }

    // close() is not retried on EINTR: on Linux and the BSDs the descriptor is already
    // gone when it returns, so retrying would close an unrelated fd.
    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }

    [[nodiscard]] explicit operator bool() const noexcept { return fd_ >= 0; }

private:
    int fd_ = -1;
};

// ---- endpoint --------------------------------------------------------------

enum struct family : int { v4 = AF_INET, v6 = AF_INET6 };

namespace detail {

[[nodiscard]] inline std::expected<std::uint16_t, std::errc> parse_port(std::string_view s) noexcept {
    if (s.empty()) return std::unexpected(std::errc::invalid_argument);
    unsigned value = 0;
    const auto* const last = s.data() + s.size();
    const auto [ptr, ec] = std::from_chars(s.data(), last, value);
    if (ec != std::errc{} || ptr != last || value > 0xFFFFu)
        return std::unexpected(std::errc::invalid_argument);
    return static_cast<std::uint16_t>(value);
}

} // namespace detail

// An IPv4 or IPv6 socket address. Trivially copyable; addresses are numeric only, so
// nothing here resolves names or touches the network.
class endpoint {
public:
    endpoint() noexcept = default;

    // Numeric address plus port. The family follows from `ip`: a ':' means IPv6.
    // Scope ids ("fe80::1%en0") are rejected -- inet_pton does not accept them.
    [[nodiscard]] static std::expected<endpoint, std::errc> from(std::string_view ip,
                                                                 std::uint16_t port) noexcept {
        if (ip.empty() || ip.size() >= INET6_ADDRSTRLEN)
            return std::unexpected(std::errc::invalid_argument);

        // Scope ids are not supported. Apple inet_pton tolerates a "%en0" suffix and
        // silently mangles the address; glibc rejects it. Reject it so both agree.
        if (ip.find('%') != std::string_view::npos)
            return std::unexpected(std::errc::invalid_argument);

        char buf[INET6_ADDRSTRLEN];
        std::memcpy(buf, ip.data(), ip.size());
        buf[ip.size()] = '\0';

        if (ip.find(':') == std::string_view::npos) {
            in_addr a{};
            if (::inet_pton(AF_INET, buf, &a) != 1)
                return std::unexpected(std::errc::invalid_argument);
            return make_v4(a, port);
        }
        in6_addr a{};
        if (::inet_pton(AF_INET6, buf, &a) != 1)
            return std::unexpected(std::errc::invalid_argument);
        return make_v6(a, port);
    }

    // "1.2.3.4:80" or "[::1]:80". Brackets are required for (and restricted to) IPv6.
    [[nodiscard]] static std::expected<endpoint, std::errc> parse(std::string_view text) noexcept {
        if (text.empty()) return std::unexpected(std::errc::invalid_argument);

        if (text.front() == '[') {
            const auto close = text.find(']');
            if (close == std::string_view::npos) return std::unexpected(std::errc::invalid_argument);
            if (close + 1 >= text.size() || text[close + 1] != ':')
                return std::unexpected(std::errc::invalid_argument);
            const auto host = text.substr(1, close - 1);
            if (host.find(':') == std::string_view::npos)
                return std::unexpected(std::errc::invalid_argument);
            const auto port = detail::parse_port(text.substr(close + 2));
            if (!port) return std::unexpected(port.error());
            return from(host, *port);
        }

        // Exactly one ':' -- more than one means a bare (unbracketed) IPv6 address.
        const auto colon = text.find(':');
        if (colon == std::string_view::npos || text.rfind(':') != colon)
            return std::unexpected(std::errc::invalid_argument);
        const auto port = detail::parse_port(text.substr(colon + 1));
        if (!port) return std::unexpected(port.error());
        return from(text.substr(0, colon), *port);
    }

    // 0.0.0.0 / ::
    [[nodiscard]] static endpoint any(family f, std::uint16_t port = 0) noexcept {
        if (f == family::v4) {
            in_addr a{};
            a.s_addr = htonl(INADDR_ANY);
            return make_v4(a, port);
        }
        return make_v6(in6addr_any, port);
    }

    // 127.0.0.1 / ::1
    [[nodiscard]] static endpoint loopback(family f, std::uint16_t port = 0) noexcept {
        if (f == family::v4) {
            in_addr a{};
            a.s_addr = htonl(INADDR_LOOPBACK);
            return make_v4(a, port);
        }
        return make_v6(in6addr_loopback, port);
    }

    [[nodiscard]] family af() const noexcept { return static_cast<family>(storage_.ss_family); }

    [[nodiscard]] bool valid() const noexcept {
        return storage_.ss_family == AF_INET || storage_.ss_family == AF_INET6;
    }

    [[nodiscard]] std::uint16_t port() const noexcept {
        if (storage_.ss_family == AF_INET) return ntohs(as_v4().sin_port);
        if (storage_.ss_family == AF_INET6) return ntohs(as_v6().sin6_port);
        return 0;
    }

    [[nodiscard]] const sockaddr* addr() const noexcept {
        return reinterpret_cast<const sockaddr*>(&storage_);
    }

    [[nodiscard]] sockaddr* addr() noexcept { return reinterpret_cast<sockaddr*>(&storage_); }

    [[nodiscard]] socklen_t len() const noexcept { return len_; }

    [[nodiscard]] static socklen_t capacity() noexcept {
        return static_cast<socklen_t>(sizeof(sockaddr_storage));
    }

    // For recvfrom()/getsockname(), which report how much of the storage they filled.
    void set_len(socklen_t n) noexcept { len_ = n; }

    [[nodiscard]] std::string to_string() const {
        char host[INET6_ADDRSTRLEN] = {};
        char out[INET6_ADDRSTRLEN + 16] = {};
        if (storage_.ss_family == AF_INET) {
            const auto v4 = as_v4();
            if (::inet_ntop(AF_INET, &v4.sin_addr, host, sizeof(host)) == nullptr) return {};
            std::snprintf(out, sizeof(out), "%s:%u", host, static_cast<unsigned>(port()));
            return out;
        }
        if (storage_.ss_family == AF_INET6) {
            const auto v6 = as_v6();
            if (::inet_ntop(AF_INET6, &v6.sin6_addr, host, sizeof(host)) == nullptr) return {};
            std::snprintf(out, sizeof(out), "[%s]:%u", host, static_cast<unsigned>(port()));
            return out;
        }
        return {};
    }

    // Field-wise: a sockaddr_storage must never be memcmp'd (padding, sin_zero, sin_len).
    [[nodiscard]] bool operator==(const endpoint& other) const noexcept {
        if (storage_.ss_family != other.storage_.ss_family) return false;
        if (storage_.ss_family == AF_INET) {
            const auto a = as_v4();
            const auto b = other.as_v4();
            return a.sin_port == b.sin_port && a.sin_addr.s_addr == b.sin_addr.s_addr;
        }
        if (storage_.ss_family == AF_INET6) {
            const auto a = as_v6();
            const auto b = other.as_v6();
            return a.sin6_port == b.sin6_port && a.sin6_scope_id == b.sin6_scope_id &&
                   std::memcmp(&a.sin6_addr, &b.sin6_addr, sizeof(a.sin6_addr)) == 0;
        }
        return true; // both unspecified
    }

private:
    // Every access goes through a memcpy of a whole sockaddr_in/in6 rather than a
    // reinterpret_cast of the storage, so no strict-aliasing rules are bent at -O3.
    [[nodiscard]] sockaddr_in as_v4() const noexcept {
        sockaddr_in a{};
        std::memcpy(&a, &storage_, sizeof(a));
        return a;
    }

    [[nodiscard]] sockaddr_in6 as_v6() const noexcept {
        sockaddr_in6 a{};
        std::memcpy(&a, &storage_, sizeof(a));
        return a;
    }

    [[nodiscard]] static endpoint make_v4(const in_addr& a, std::uint16_t port) noexcept {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr = a;
#ifdef SIN6_LEN // BSD sockaddrs carry their own length
        sa.sin_len = sizeof(sa);
#endif
        endpoint ep;
        std::memcpy(&ep.storage_, &sa, sizeof(sa));
        ep.len_ = static_cast<socklen_t>(sizeof(sa));
        return ep;
    }

    [[nodiscard]] static endpoint make_v6(const in6_addr& a, std::uint16_t port) noexcept {
        sockaddr_in6 sa{};
        sa.sin6_family = AF_INET6;
        sa.sin6_port = htons(port);
        sa.sin6_addr = a;
#ifdef SIN6_LEN
        sa.sin6_len = sizeof(sa);
#endif
        endpoint ep;
        std::memcpy(&ep.storage_, &sa, sizeof(sa));
        ep.len_ = static_cast<socklen_t>(sizeof(sa));
        return ep;
    }

    sockaddr_storage storage_{};
    socklen_t len_ = 0;
};

// ---- udp_socket ------------------------------------------------------------

namespace detail {

// SIGPIPE cannot happen on an unconnected datagram socket; this covers connected ones.
inline constexpr int msg_flags =
#ifdef MSG_NOSIGNAL
    MSG_NOSIGNAL;
#else
    0;
#endif

} // namespace detail

// A UDP socket. Blocking by default -- call set_nonblocking(true) before handing the
// descriptor to a poller.
class udp_socket {
public:
    udp_socket() noexcept = default;

    [[nodiscard]] static std::expected<udp_socket, std::errc> open(family f) noexcept {
        int type = SOCK_DGRAM;
#ifdef SOCK_CLOEXEC // Linux and the newer BSDs; macOS has no atomic form
        type |= SOCK_CLOEXEC;
#endif
        const int raw = ::socket(static_cast<int>(f), type, 0);
        if (raw < 0) return detail::fail();
        unique_fd fd{raw};
#ifndef SOCK_CLOEXEC
        if (::fcntl(raw, F_SETFD, FD_CLOEXEC) < 0) return detail::fail();
#endif
#ifdef SO_NOSIGPIPE // Apple; best effort, a failure here is not worth aborting open()
        const int on = 1;
        (void)::setsockopt(raw, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
#endif
        udp_socket sock{std::move(fd)};
        return sock;
    }

    [[nodiscard]] int fd() const noexcept { return fd_.get(); }

    [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(fd_); }

    [[nodiscard]] std::expected<void, std::errc> bind(const endpoint& ep) noexcept {
        if (::bind(fd_.get(), ep.addr(), ep.len()) < 0) return detail::fail();
        return {};
    }

    // Sets the default peer for send()/recv() and filters inbound datagrams. After the
    // peer answers an ICMP port-unreachable, one subsequent recv()/send() reports
    // std::errc::connection_refused; that is not fatal and the socket stays usable.
    [[nodiscard]] std::expected<void, std::errc> connect(const endpoint& ep) noexcept {
        if (::connect(fd_.get(), ep.addr(), ep.len()) < 0) return detail::fail();
        return {};
    }

    // fcntl is the only portable way; SOCK_NONBLOCK does not exist on macOS.
    [[nodiscard]] std::expected<void, std::errc> set_nonblocking(bool on) noexcept {
        const int flags = ::fcntl(fd_.get(), F_GETFL, 0);
        if (flags < 0) return detail::fail();
        const int wanted = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
        if (wanted != flags && ::fcntl(fd_.get(), F_SETFL, wanted) < 0) return detail::fail();
        return {};
    }

    [[nodiscard]] std::expected<void, std::errc> set_reuse_addr(bool on) noexcept {
        return set_flag(SOL_SOCKET, SO_REUSEADDR, on);
    }

    // Off means dual-stack: a bound "::" socket also accepts IPv4-mapped traffic.
    [[nodiscard]] std::expected<void, std::errc> set_v6_only(bool on) noexcept {
        return set_flag(IPPROTO_IPV6, IPV6_V6ONLY, on);
    }

    [[nodiscard]] std::expected<void, std::errc> set_recv_buffer_size(int bytes) noexcept {
        return set_int(SOL_SOCKET, SO_RCVBUF, bytes);
    }

    [[nodiscard]] std::expected<void, std::errc> set_send_buffer_size(int bytes) noexcept {
        return set_int(SOL_SOCKET, SO_SNDBUF, bytes);
    }

    // Linux reports roughly twice what was requested (kernel bookkeeping overhead).
    [[nodiscard]] std::expected<int, std::errc> recv_buffer_size() const noexcept {
        return get_int(SOL_SOCKET, SO_RCVBUF);
    }

    [[nodiscard]] std::expected<int, std::errc> send_buffer_size() const noexcept {
        return get_int(SOL_SOCKET, SO_SNDBUF);
    }

    [[nodiscard]] std::expected<endpoint, std::errc> local_endpoint() const noexcept {
        endpoint ep;
        socklen_t n = endpoint::capacity();
        if (::getsockname(fd_.get(), ep.addr(), &n) < 0) return detail::fail();
        ep.set_len(n);
        return ep;
    }

    // A datagram longer than `buf` is silently truncated (no MSG_TRUNC): fex packets are
    // fixed-size, so callers pass a buffer at least as large as the biggest one.
    [[nodiscard]] std::expected<std::size_t, std::errc> recv_from(std::span<std::uint8_t> buf,
                                                                  endpoint& from) noexcept {
        for (;;) {
            socklen_t n = endpoint::capacity();
            const auto got = ::recvfrom(fd_.get(), buf.data(), buf.size(), 0, from.addr(), &n);
            if (got >= 0) {
                from.set_len(n);
                return static_cast<std::size_t>(got);
            }
            if (errno == EINTR) continue;
            return detail::fail();
        }
    }

    [[nodiscard]] std::expected<std::size_t, std::errc> send_to(std::span<const std::uint8_t> buf,
                                                                const endpoint& to) noexcept {
        for (;;) {
            const auto sent = ::sendto(fd_.get(), buf.data(), buf.size(), detail::msg_flags,
                                       to.addr(), to.len());
            if (sent >= 0) return static_cast<std::size_t>(sent);
            if (errno == EINTR) continue;
            return detail::fail();
        }
    }

    // recv()/send() require a prior connect().
    [[nodiscard]] std::expected<std::size_t, std::errc> recv(std::span<std::uint8_t> buf) noexcept {
        for (;;) {
            const auto got = ::recv(fd_.get(), buf.data(), buf.size(), 0);
            if (got >= 0) return static_cast<std::size_t>(got);
            if (errno == EINTR) continue;
            return detail::fail();
        }
    }

    [[nodiscard]] std::expected<std::size_t, std::errc> send(std::span<const std::uint8_t> buf) noexcept {
        for (;;) {
            const auto sent = ::send(fd_.get(), buf.data(), buf.size(), detail::msg_flags);
            if (sent >= 0) return static_cast<std::size_t>(sent);
            if (errno == EINTR) continue;
            return detail::fail();
        }
    }

    // TODO(batch): recv_batch/send_batch over recvmmsg/sendmmsg on Linux with a plain
    // loop elsewhere, once the server loop fixes the packet descriptor type.

private:
    explicit udp_socket(unique_fd fd) noexcept: fd_{std::move(fd)} {}

    [[nodiscard]] std::expected<void, std::errc> set_flag(int level, int name, bool on) noexcept {
        return set_int(level, name, on ? 1 : 0);
    }

    [[nodiscard]] std::expected<void, std::errc> set_int(int level, int name, int value) noexcept {
        if (::setsockopt(fd_.get(), level, name, &value, sizeof(value)) < 0) return detail::fail();
        return {};
    }

    [[nodiscard]] std::expected<int, std::errc> get_int(int level, int name) const noexcept {
        int value = 0;
        socklen_t n = sizeof(value);
        if (::getsockopt(fd_.get(), level, name, &value, &n) < 0) return detail::fail();
        return value;
    }

    unique_fd fd_;
};

} // namespace fex::net

// ---- Tests -----------------------------------------------------------------

#ifdef FEX_WITH_TESTS

#include <array>

TEST_SUITE("fex::net") {

TEST_CASE("endpoint parses and formats IPv4") {
    using namespace fex::net;
    const auto ep = endpoint::parse("127.0.0.1:8080");
    REQUIRE(ep.has_value());
    if (!ep) return;
    REQUIRE_EQ(ep->af(), family::v4);
    REQUIRE_EQ(ep->port(), 8080);
    REQUIRE_EQ(ep->len(), sizeof(sockaddr_in));
    REQUIRE_EQ(ep->to_string(), "127.0.0.1:8080");

    const auto same = endpoint::from("127.0.0.1", 8080);
    REQUIRE(same.has_value());
    if (same) REQUIRE_EQ(*same, *ep);

    REQUIRE_EQ(endpoint::loopback(family::v4, 8080), *ep);
    REQUIRE_FALSE(endpoint::any(family::v4, 8080) == *ep);
}

TEST_CASE("endpoint parses and formats IPv6") {
    using namespace fex::net;
    const auto ep = endpoint::parse("[::1]:443");
    REQUIRE(ep.has_value());
    if (!ep) return;
    REQUIRE_EQ(ep->af(), family::v6);
    REQUIRE_EQ(ep->port(), 443);
    REQUIRE_EQ(ep->len(), sizeof(sockaddr_in6));
    REQUIRE_EQ(ep->to_string(), "[::1]:443");
    REQUIRE_EQ(endpoint::loopback(family::v6, 443), *ep);

    // Different families never compare equal.
    REQUIRE_FALSE(*ep == endpoint::loopback(family::v4, 443));
}

TEST_CASE("endpoint rejects malformed input") {
    using namespace fex::net;
    constexpr std::string_view bad[] = {
        "",                 // empty
        "::1:443",          // bare IPv6, needs brackets
        "[::1]",            // no port
        "[::1]443",         // no ':' after ']'
        "[127.0.0.1]:443",  // brackets are IPv6-only
        "1.2.3.4",          // no port
        "1.2.3.4:",         // empty port
        "1.2.3.4:70000",    // port out of range
        "1.2.3.4:x",        // non-numeric port
        "1.2.3.4:-1",       // negative port
        "[fe80::1%en0]:1",  // scope ids are not accepted
        "999.1.1.1:80",     // not an address
    };
    for (const auto text : bad) {
        const auto ep = endpoint::parse(text);
        REQUIRE_FALSE(ep.has_value());
        if (!ep) REQUIRE_EQ(ep.error(), std::errc::invalid_argument);
    }
}

TEST_CASE("udp_socket binds an ephemeral port") {
    using namespace fex::net;
    auto sock = udp_socket::open(family::v4);
    REQUIRE(sock.has_value());
    if (!sock) return;
    REQUIRE(sock->bind(endpoint::loopback(family::v4, 0)).has_value());

    const auto local = sock->local_endpoint();
    REQUIRE(local.has_value());
    if (!local) return;
    REQUIRE_EQ(local->af(), family::v4);
    REQUIRE_NE(local->port(), 0);
    REQUIRE_EQ(*local, endpoint::loopback(family::v4, local->port()));
}

TEST_CASE("udp_socket round trips a datagram over IPv4 loopback") {
    using namespace fex::net;
    auto a = udp_socket::open(family::v4);
    auto b = udp_socket::open(family::v4);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    if (!a || !b) return;
    REQUIRE(a->bind(endpoint::loopback(family::v4, 0)).has_value());
    REQUIRE(b->bind(endpoint::loopback(family::v4, 0)).has_value());

    const auto a_local = a->local_endpoint();
    const auto b_local = b->local_endpoint();
    REQUIRE(a_local.has_value());
    REQUIRE(b_local.has_value());
    if (!a_local || !b_local) return;

    constexpr std::array<std::uint8_t, 5> msg{1, 2, 3, 4, 5};
    const auto sent = a->send_to(msg, *b_local);
    REQUIRE(sent.has_value());
    if (sent) REQUIRE_EQ(*sent, msg.size());

    std::array<std::uint8_t, 64> buf{};
    endpoint from;
    const auto got = b->recv_from(buf, from);
    REQUIRE(got.has_value());
    if (!got) return;
    REQUIRE_EQ(*got, msg.size());
    REQUIRE_EQ(std::memcmp(buf.data(), msg.data(), msg.size()), 0);
    REQUIRE_EQ(from, *a_local);
}

TEST_CASE("udp_socket round trips a datagram over IPv6 loopback") {
    using namespace fex::net;
    auto a = udp_socket::open(family::v6);
    auto b = udp_socket::open(family::v6);
    if (!a || !b) {
        MESSAGE("IPv6 unavailable, skipping");
        return;
    }
    if (!a->bind(endpoint::loopback(family::v6, 0)) || !b->bind(endpoint::loopback(family::v6, 0))) {
        MESSAGE("IPv6 loopback unavailable, skipping");
        return;
    }
    const auto b_local = b->local_endpoint();
    REQUIRE(b_local.has_value());
    if (!b_local) return;
    REQUIRE_EQ(b_local->af(), family::v6);

    constexpr std::array<std::uint8_t, 3> msg{0xAA, 0xBB, 0xCC};
    REQUIRE(a->send_to(msg, *b_local).has_value());

    std::array<std::uint8_t, 64> buf{};
    endpoint from;
    const auto got = b->recv_from(buf, from);
    REQUIRE(got.has_value());
    if (!got) return;
    REQUIRE_EQ(*got, msg.size());
    REQUIRE_EQ(std::memcmp(buf.data(), msg.data(), msg.size()), 0);
}

TEST_CASE("udp_socket reports would-block on an empty non-blocking socket") {
    using namespace fex::net;
    auto sock = udp_socket::open(family::v4);
    REQUIRE(sock.has_value());
    if (!sock) return;
    REQUIRE(sock->bind(endpoint::loopback(family::v4, 0)).has_value());
    REQUIRE(sock->set_nonblocking(true).has_value());

    std::array<std::uint8_t, 64> buf{};
    endpoint from;
    const auto got = sock->recv_from(buf, from);
    REQUIRE_FALSE(got.has_value());
    if (!got) REQUIRE_EQ(got.error(), std::errc::resource_unavailable_try_again);
}

TEST_CASE("udp_socket sends and receives on a connected socket") {
    using namespace fex::net;
    auto a = udp_socket::open(family::v4);
    auto b = udp_socket::open(family::v4);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    if (!a || !b) return;
    REQUIRE(b->bind(endpoint::loopback(family::v4, 0)).has_value());

    const auto b_local = b->local_endpoint();
    REQUIRE(b_local.has_value());
    if (!b_local) return;
    REQUIRE(a->connect(*b_local).has_value()); // also assigns `a` an ephemeral local port

    const auto a_local = a->local_endpoint();
    REQUIRE(a_local.has_value());
    if (!a_local) return;
    REQUIRE_NE(a_local->port(), 0);

    constexpr std::array<std::uint8_t, 4> ping{'p', 'i', 'n', 'g'};
    REQUIRE(a->send(ping).has_value());

    std::array<std::uint8_t, 64> buf{};
    endpoint from;
    const auto got = b->recv_from(buf, from);
    REQUIRE(got.has_value());
    if (!got) return;
    REQUIRE_EQ(*got, ping.size());
    REQUIRE_EQ(from, *a_local);

    constexpr std::array<std::uint8_t, 4> pong{'p', 'o', 'n', 'g'};
    REQUIRE(b->send_to(pong, from).has_value());

    std::array<std::uint8_t, 64> back{};
    const auto echoed = a->recv(back);
    REQUIRE(echoed.has_value());
    if (!echoed) return;
    REQUIRE_EQ(*echoed, pong.size());
    REQUIRE_EQ(std::memcmp(back.data(), pong.data(), pong.size()), 0);
}

TEST_CASE("udp_socket exposes socket buffer sizes") {
    using namespace fex::net;
    auto sock = udp_socket::open(family::v4);
    REQUIRE(sock.has_value());
    if (!sock) return;
    REQUIRE(sock->set_recv_buffer_size(64 * 1024).has_value());
    const auto size = sock->recv_buffer_size();
    REQUIRE(size.has_value());
    if (size) REQUIRE(*size > 0);
}

} // TEST_SUITE

#endif // FEX_WITH_TESTS
