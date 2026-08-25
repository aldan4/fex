// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Client request engine: one connected UDP socket, blocking waits with a
// deadline. No answer within the timeout -> peek, await head, resend the same
// request (same req_id, so a late original still matches; the nonce is fresh).

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <netdb.h>
#include <poll.h>

#include <fex/channel.hpp>
#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/net/socket.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::client {

struct net_options {
    int request_timeout_ms = 500;  // doubles per attempt...
    int request_timeout_cap_ms = 4000; // ...up to this
    int max_attempts = 5;          // per logical request
    int peek_timeout_ms = 1000;
    int peek_attempts = 3;
    int put_window = 64;           // puts sent between polls
    int stall_rounds = 3;          // #10.1: rounds without progress -> abort
    int max_restarts = 3;          // #10.1: mismatch restarts -> abort
}; // net_options

// name resolution for the relay card's addr (#3 allows a hostname)
[[nodiscard]] inline std::expected<net::endpoint, std::errc>
resolve(std::string_view addr) noexcept {
    if (const auto ep = net::endpoint::parse(addr))
        return *ep; // already numeric
    const auto colon = addr.rfind(':');
    if (colon == std::string_view::npos)
        return std::unexpected(std::errc::invalid_argument);
    const std::string host{addr.substr(0, colon)};
    const std::string port{addr.substr(colon + 1)};
    ::addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    ::addrinfo* found = nullptr;
    if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &found) != 0 || found == nullptr)
        return std::unexpected(std::errc::address_not_available);
    net::endpoint ep;
    if (found->ai_addrlen <= net::endpoint::capacity()) {
        std::memcpy(ep.addr(), found->ai_addr, found->ai_addrlen);
        ep.set_len(found->ai_addrlen);
    }
    ::freeaddrinfo(found);
    if (!ep.valid())
        return std::unexpected(std::errc::address_not_available);
    return ep;
}

[[nodiscard]] inline u64 fresh_req_id() noexcept {
    u8 raw[6];
    u64 id = 0;
    do {
        crypto::random_bytes(raw);
        id = 0;
        for (unsigned i = 0; i != 6; ++i)
            id |= u64{raw[i]} << (8 * i);
    } while (id == 0); // zero is head's req_id
    return id;
}

class requester {
    net::udp_socket sock_;
    channel::key k_{};
    u64 id_ = 0;
    net_options opts_{};

public:

    requester() = default;
    requester(requester&&) = default;
    requester& operator=(requester&&) = default;

    [[nodiscard]] const net_options& options() const noexcept { return opts_; }

    [[nodiscard]] static std::expected<requester, std::errc>
    connect(const identity& self, const identity_card& relay,
            const net_options& opts = {}) noexcept {
        if (relay.addr.empty())
            return std::unexpected(std::errc::invalid_argument);
        const auto ep = resolve(relay.addr);
        if (!ep)
            return std::unexpected(ep.error());
        requester r;
        r.opts_ = opts;
        r.id_ = fingerprint(self.pub);
        if (!channel::derive(r.k_, self.priv, relay.pub))
            return std::unexpected(std::errc::bad_message);
        auto sock = net::udp_socket::open(ep->af());
        if (!sock)
            return std::unexpected(sock.error());
        r.sock_ = std::move(*sock);
        (void)r.sock_.set_send_buffer_size(1 << 20); // put windows, best effort
        if (auto c = r.sock_.connect(*ep); !c)
            return std::unexpected(c.error());
        return r;
    }

    // #4 peek -> head; also re-confirms our address after silence
    [[nodiscard]] std::expected<wire::head, std::errc> peek() noexcept {
        std::array<u8, wire::peek_size> pk;
        std::array<u8, wire::max_command> plain;
        for (int attempt = 0; attempt != opts_.peek_attempts; ++attempt) {
            if (channel::make_peek(pk, id_) != wire::peek_size)
                return std::unexpected(std::errc::invalid_argument);
            if (auto s = sock_.send(fex::bytes{pk}); !s)
                return std::unexpected(s.error());
            const auto n = await(0, plain, opts_.peek_timeout_ms);
            if (!n)
                continue;
            const auto mh = wire::read_mheader(fex::bytes{plain.data(), *n});
            if (!mh || wire::mkind_of(*mh) != wire::mkind::head)
                continue;
            const auto head = wire::read_head(fex::bytes{plain.data(), *n});
            if (head)
                return *head;
        }
        return std::unexpected(std::errc::timed_out);
    }

    // fire-and-forget (put)
    [[nodiscard]] std::expected<void, std::errc> cast(fex::bytes cmd) noexcept {
        return send_request(cmd);
    }

    // one logical request: cmd carries its req_id already; the matching
    // response's plaintext lands in out
    [[nodiscard]] std::expected<std::size_t, std::errc>
    call(fex::bytes cmd, std::span<u8> out) noexcept {
        const auto mh = wire::read_mheader(cmd);
        if (!mh)
            return std::unexpected(std::errc::invalid_argument);
        const auto req_id = wire::request_id_of(*mh);
        int timeout = opts_.request_timeout_ms;
        for (int attempt = 0; attempt != opts_.max_attempts; ++attempt) {
            if (attempt != 0) { // #5: no answer -> peek, await head, repeat
                if (const auto h = peek(); !h)
                    return std::unexpected(h.error());
            }
            if (auto s = send_request(cmd); !s)
                return std::unexpected(s.error());
            if (const auto n = await(req_id, out, timeout))
                return *n;
            timeout = std::min(timeout * 2, opts_.request_timeout_cap_ms);
        }
        return std::unexpected(std::errc::timed_out);
    }

private:

    [[nodiscard]] std::expected<void, std::errc> send_request(fex::bytes cmd) noexcept {
        std::array<u8, wire::datagram_max> dgram;
        const auto n = channel::seal(dgram, wire::pkind::request, id_, cmd, k_);
        if (n == 0)
            return std::unexpected(std::errc::invalid_argument);
        if (auto s = sock_.send(fex::bytes{dgram.data(), n}); !s)
            return std::unexpected(s.error());
        return {};
    }

    // waits until the deadline for the response with this req_id; everything
    // else -- foreign nonsense, stale responses -- is dropped on the floor
    [[nodiscard]] std::optional<std::size_t>
    await(u64 req_id, std::span<u8> out, int timeout_ms) noexcept {
        const u64 deadline = fs::now_ns() + u64(timeout_ms) * 1'000'000;
        std::array<u8, 2048> in;
        std::array<u8, wire::max_command> plain;
        for (;;) {
            const u64 now = fs::now_ns();
            if (now >= deadline)
                return std::nullopt;
            ::pollfd pfd{sock_.fd(), POLLIN, 0};
            const int ready = ::poll(&pfd, 1, int((deadline - now) / 1'000'000) + 1);
            if (ready < 0 && errno == EINTR)
                continue;
            if (ready <= 0)
                return std::nullopt;
            const auto got = sock_.recv(in);
            if (!got)
                continue;
            const fex::bytes dgram{in.data(), *got};
            const auto h = wire::read_pheader(dgram);
            if (!h || h->kind != wire::pkind::response || h->id != id_)
                continue;
            const auto n = channel::open(plain, dgram, k_);
            if (!n)
                continue;
            const auto mh = wire::read_mheader(fex::bytes{plain.data(), *n});
            if (!mh || !wire::is_response_kind(wire::mkind_of(*mh))
                || wire::request_id_of(*mh) != req_id)
                continue;
            if (out.size() < *n)
                return std::nullopt;
            std::copy(plain.data(), plain.data() + *n, out.data());
            return *n;
        }
    }
}; // requester

} // namespace fex::client

#ifdef FEX_WITH_TESTS

TEST_SUITE("fex::client") {

SCENARIO("requester: a deaf relay times out") {
    using namespace fex;
    // a socket that never answers
    auto deaf = net::udp_socket::open(net::family::v4);
    REQUIRE(deaf.has_value());
    REQUIRE(deaf->bind(net::endpoint::loopback(net::family::v4, 0)).has_value());
    const auto addr = deaf->local_endpoint();
    REQUIRE(addr.has_value());

    const auto self = generate_identity();
    const auto relay = generate_identity();
    auto card = card_of(relay, addr->to_string());

    client::net_options opts;
    opts.request_timeout_ms = 20;
    opts.request_timeout_cap_ms = 20;
    opts.max_attempts = 2;
    opts.peek_timeout_ms = 20;
    opts.peek_attempts = 1;
    auto req = client::requester::connect(self, card, opts);
    REQUIRE(req.has_value());

    const auto t0 = fs::now_ns();
    const auto head = req->peek();
    REQUIRE(!head.has_value());
    CHECK(head.error() == std::errc::timed_out);

    std::array<fex::u8, wire::get_size> cmd;
    wire::get g{};
    REQUIRE(wire::write_get(cmd, wire::mheader_of(wire::mkind::get, wire::mstatus::ok,
                                                  client::fresh_req_id()), g)
            == wire::get_size);
    std::array<fex::u8, wire::max_command> out;
    const auto r = req->call(fex::bytes{cmd}, out);
    REQUIRE(!r.has_value());
    CHECK(r.error() == std::errc::timed_out);
    const auto elapsed_ms = (fs::now_ns() - t0) / 1'000'000;
    CHECK(elapsed_ms < 5000); // bounded by the tiny timeouts, not hanging
}

SCENARIO("resolve: numeric and named forms") {
    using namespace fex;
    const auto num = client::resolve("127.0.0.1:4444");
    REQUIRE(num.has_value());
    CHECK(num->port() == 4444);
    const auto named = client::resolve("localhost:4444");
    REQUIRE(named.has_value());
    CHECK(named->port() == 4444);
    CHECK(!client::resolve("no-port").has_value());
}

}

#endif
