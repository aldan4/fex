// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Relay event loop (#4): one UDP socket, one poller, single-threaded.
// Drop rules are enforced in spec order; drops are always silent.

#include <atomic>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include <fex/channel.hpp>
#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/net/poller.hpp>
#include <fex/net/socket.hpp>
#include <fex/relay/capsule.hpp>
#include <fex/relay/registry.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::relay {

struct options {
    std::string root = ".";
    std::string key_path;              // default <root>/node.dano
    std::string addr = "0.0.0.0:4444";
}; // options

class server {
    std::string root_;
    identity self_{};
    registry reg_;
    net::udp_socket sock_;
    net::poller poller_;
    hash_map<u64, net::endpoint> addrs_; // the peek-learned cache
    hash_map<u64, channel::key> keys_;
    hash_map<u64, capsule> capsules_;
    std::atomic<bool> stopping_{false};
    u64 last_reg_check_ns_ = 0;

    static constexpr u64 reg_check_period_ns = 1'000'000'000; // 1 s

public:

    server() = default;
    server(const server&) = delete;
    server& operator=(const server&) = delete;

    [[nodiscard]] std::expected<void, std::errc> start(const options& opts) noexcept {
        root_ = opts.root;
        const auto key_path = opts.key_path.empty() ? root_ + "/node.dano" : opts.key_path;
        auto self = read_identity(key_path.c_str());
        if (!self)
            return std::unexpected(self.error());
        self_ = *self;
        if (auto r = fs::ensure_dirs(members_dir()); !r)
            return r;
        if (auto r = fs::ensure_dirs(root_ + "/capsules"); !r)
            return r;
        auto reg = registry::load(members_dir());
        if (!reg)
            return std::unexpected(reg.error());
        reg_ = std::move(*reg);
        const auto ep = net::endpoint::parse(opts.addr);
        if (!ep)
            return std::unexpected(ep.error());
        auto sock = net::udp_socket::open(ep->af());
        if (!sock)
            return std::unexpected(sock.error());
        sock_ = std::move(*sock);
        if (auto r = sock_.set_reuse_addr(true); !r)
            return r;
        (void)sock_.set_recv_buffer_size(1 << 20); // absorb put bursts, best effort
        if (auto r = sock_.bind(*ep); !r)
            return r;
        if (auto r = sock_.set_nonblocking(true); !r)
            return r;
        auto poller = net::poller::open();
        if (!poller)
            return std::unexpected(poller.error());
        poller_ = std::move(*poller);
        return poller_.add(sock_.fd(), net::interest::read, 0);
    }

    [[nodiscard]] net::endpoint local_addr() const noexcept {
        const auto ep = sock_.local_endpoint();
        return ep ? *ep : net::endpoint{};
    }

    // serves until stop(); returns only on stop or a fatal poller error
    [[nodiscard]] std::expected<void, std::errc> run() noexcept {
        std::array<net::event, net::poller::max_batch> events;
        while (!stopping_.load(std::memory_order_relaxed)) {
            const auto n = poller_.wait(events, -1);
            if (!n) {
                if (n.error() == std::errc::interrupted)
                    continue;
                return std::unexpected(n.error());
            }
            if (stopping_.load(std::memory_order_relaxed))
                break;
            drain();
        }
        return {};
    }

    // thread-safe (and async-signal-tolerable: an atomic store + kevent/eventfd)
    void stop() noexcept {
        stopping_.store(true, std::memory_order_relaxed);
        (void)poller_.wake();
    }

private:

    [[nodiscard]] std::string members_dir() const { return root_ + "/members"; }

    void drain() noexcept {
        std::array<u8, 2048> buf; // > datagram_max: oversized input never fits a layout
        net::endpoint src;
        for (;;) {
            const auto n = sock_.recv_from(buf, src);
            if (!n)
                return; // would-block or a transient error: back to the poller
            on_datagram(fex::bytes{buf.data(), *n}, src);
        }
    }

    void on_datagram(fex::bytes dgram, const net::endpoint& src) noexcept {
        const auto h = wire::read_pheader(dgram); // length + version
        if (!h)
            return;
        switch (h->kind) {
        case wire::pkind::peek:
            if (dgram.size() == wire::peek_size)
                on_peek(h->id, src);
            return;
        case wire::pkind::request:
            on_request(*h, dgram, src);
            return;
        default: // the relay's own half or an unknown kind
            return;
        }
    }

    void check_registry(u64 now_ns, bool force) noexcept {
        if (!force && now_ns - last_reg_check_ns_ < reg_check_period_ns)
            return;
        last_reg_check_ns_ = now_ns;
        const auto reloaded = reg_.maybe_reload(members_dir());
        if (!reloaded || !*reloaded)
            return;
        // #3: removing a member resets the address cache for it
        for (auto it = addrs_.begin(); it != addrs_.end();)
            it = reg_.find(it->first) == nullptr ? addrs_.erase(it) : std::next(it);
        for (auto it = keys_.begin(); it != keys_.end();)
            it = reg_.find(it->first) == nullptr ? keys_.erase(it) : std::next(it);
        for (auto it = capsules_.begin(); it != capsules_.end();)
            it = reg_.find(it->first) == nullptr ? capsules_.erase(it) : std::next(it);
    }

    [[nodiscard]] const channel::key* key_for(const member& m) noexcept {
        if (const auto it = keys_.find(m.id); it != keys_.end())
            return &it->second;
        channel::key k;
        if (!channel::derive(k, self_.priv, m.pub))
            return nullptr;
        return &keys_.emplace(m.id, k).first->second;
    }

    [[nodiscard]] capsule* capsule_for(const member& m) noexcept {
        if (const auto it = capsules_.find(m.id); it != capsules_.end())
            return &it->second;
        auto cap = capsule::open(root_ + "/capsules/" + m.name);
        if (!cap)
            return nullptr;
        return &capsules_.emplace(m.id, std::move(*cap)).first->second;
    }

    void on_peek(u64 id, const net::endpoint& src) noexcept {
        const auto now = fs::now_ns();
        check_registry(now, reg_.find(id) == nullptr);
        const auto* m = reg_.find(id);
        if (m == nullptr)
            return;
        const auto* k = key_for(*m);
        if (k == nullptr)
            return;
        auto* cap = capsule_for(*m);
        if (cap == nullptr)
            return;
        addrs_[id] = src;
        (void)cap->maybe_enforce(now);
        std::array<u8, wire::head_size> plain;
        const auto n = wire::write_head(
            plain, wire::mheader_of(wire::mkind::head, wire::mstatus::ok, 0),
            cap->head_msg());
        respond(id, fex::bytes{plain.data(), n}, *k, src);
    }

    void on_request(const wire::pheader& h, fex::bytes dgram,
                    const net::endpoint& src) noexcept {
        const auto* m = reg_.find(h.id);
        if (m == nullptr)
            return;
        const auto it = addrs_.find(h.id);
        if (it == addrs_.end() || !(it->second == src))
            return; // #4: source address must match the peek-confirmed one
        const auto* k = key_for(*m);
        if (k == nullptr)
            return;
        std::array<u8, wire::max_command> plain;
        const auto n = channel::open(plain, dgram, *k);
        if (!n)
            return;
        const fex::bytes cmd{plain.data(), *n};
        const auto mh = wire::read_mheader(cmd);
        if (!mh || !wire::is_request_kind(wire::mkind_of(*mh)))
            return;
        auto* cap = capsule_for(*m);
        if (cap == nullptr)
            return;
        (void)cap->maybe_enforce(fs::now_ns());
        const auto req_id = wire::request_id_of(*mh);

        std::array<u8, wire::max_command> reply;
        std::size_t reply_len = 0;
        switch (wire::mkind_of(*mh)) {
        case wire::mkind::put: {
            const auto p = wire::read_put(cmd);
            if (p)
                cap->put_chunk(*p);
            return; // put is never answered (#5)
        }
        case wire::mkind::get: {
            const auto g = wire::read_get(cmd);
            if (!g)
                return;
            std::array<u8, wire::chunk_data_size> data;
            const auto got = cap->get_chunk(*g, data);
            const auto status = got ? wire::mstatus::ok : got.error();
            const auto body = got ? fex::bytes{data.data(), *got} : fex::bytes{};
            reply_len = wire::write_chunk(
                reply, wire::mheader_of(wire::mkind::chunk, status, req_id), body);
            break;
        }
        case wire::mkind::poll: {
            const auto p = wire::read_poll(cmd);
            if (!p)
                return;
            const auto g = cap->poll_file(*p);
            reply_len = wire::write_gaps(
                reply, wire::mheader_of(wire::mkind::gaps, g.status, req_id),
                std::span<const wire::range>{g.ranges.data(), g.count});
            break;
        }
        case wire::mkind::commit: {
            const auto c = wire::read_commit(cmd);
            if (!c)
                return;
            const auto status = cap->commit(*c);
            reply_len = wire::write_done(
                reply, wire::mheader_of(wire::mkind::done, status, req_id));
            break;
        }
        default:
            return;
        }
        if (reply_len != 0)
            respond(h.id, fex::bytes{reply.data(), reply_len}, *k, src);
    }

    void respond(u64 id, fex::bytes plain, const channel::key& k,
                 const net::endpoint& dst) noexcept {
        std::array<u8, wire::datagram_max> dgram;
        const auto n = channel::seal(dgram, wire::pkind::response, id, plain, k);
        if (n != 0)
            (void)sock_.send_to(fex::bytes{dgram.data(), n}, dst);
    }
}; // server

} // namespace fex::relay

#ifdef FEX_WITH_TESTS

#include <cstdlib>
#include <optional>
#include <thread>

#include <poll.h>

TEST_SUITE("fex::relay") {

namespace fex_server_test {

inline std::optional<std::size_t> recv_within(fex::net::udp_socket& s,
                                              std::span<fex::u8> buf, int ms) {
    ::pollfd pfd{s.fd(), POLLIN, 0};
    if (::poll(&pfd, 1, ms) <= 0)
        return std::nullopt;
    const auto n = s.recv(buf);
    if (!n)
        return std::nullopt;
    return *n;
}

} // namespace fex_server_test

SCENARIO("server: peek -> head, request dispatch, drop rules") {
    using namespace fex;
    using namespace fex_server_test;
    char tmpl[] = "/tmp/fex-srv-XXXXXX";
    char* tmp = ::mkdtemp(tmpl);
    REQUIRE(tmp != nullptr);
    const std::string root{tmp};

    const auto relay_id = generate_identity();
    const auto alice = generate_identity();
    REQUIRE(write_new_file((root + "/node.dano").c_str(), to_dano(relay_id),
                           identity_mode).has_value());
    REQUIRE(fs::ensure_dirs(root + "/members").has_value());
    REQUIRE(write_new_file((root + "/members/alice.dano").c_str(),
                           to_dano(card_of(alice)), identity_card_mode).has_value());

    relay::server srv;
    relay::options opts;
    opts.root = root;
    opts.addr = "127.0.0.1:0";
    REQUIRE(srv.start(opts).has_value());
    const auto addr = srv.local_addr();
    REQUIRE(addr.valid());
    std::thread runner{[&] { (void)srv.run(); }};

    const auto id = fingerprint(alice.pub);
    channel::key k{};
    REQUIRE(channel::derive(k, alice.priv, relay_id.pub));

    auto sock = net::udp_socket::open(net::family::v4);
    REQUIRE(sock.has_value());
    REQUIRE(sock->connect(addr).has_value());

    std::array<fex::u8, wire::datagram_max> out{};
    std::array<fex::u8, wire::datagram_max> in{};
    std::array<fex::u8, wire::max_command> plain{};

    // peek -> head with seq 0 (never published)
    REQUIRE(channel::make_peek(out, id) == wire::peek_size);
    REQUIRE(sock->send(fex::bytes{out.data(), wire::peek_size}).has_value());
    auto n = recv_within(*sock, in, 2000);
    REQUIRE(n.has_value());
    const auto ph = wire::read_pheader(fex::bytes{in.data(), *n});
    REQUIRE(ph.has_value());
    CHECK(ph->kind == wire::pkind::response);
    CHECK(ph->id == id);
    auto m = channel::open(plain, fex::bytes{in.data(), *n}, k);
    REQUIRE(m.has_value());
    const auto mh = wire::read_mheader(fex::bytes{plain.data(), *m});
    REQUIRE(mh.has_value());
    CHECK(wire::mkind_of(*mh) == wire::mkind::head);
    CHECK(wire::request_id_of(*mh) == 0);
    const auto head = wire::read_head(fex::bytes{plain.data(), *m});
    REQUIRE(head.has_value());
    CHECK(head->seq == 0);

    // get of an unknown hash -> chunk with not_found
    wire::get g{};
    g.chunk_no = 0;
    for (auto& b : g.file_hash)
        b = 0x42;
    std::array<fex::u8, wire::get_size> cmd;
    REQUIRE(wire::write_get(cmd, wire::mheader_of(wire::mkind::get, wire::mstatus::ok,
                                                  0x123456), g) == wire::get_size);
    const auto sealed = channel::seal(out, wire::pkind::request, id,
                                      fex::bytes{cmd}, k);
    REQUIRE(sealed != 0);
    REQUIRE(sock->send(fex::bytes{out.data(), sealed}).has_value());
    n = recv_within(*sock, in, 2000);
    REQUIRE(n.has_value());
    m = channel::open(plain, fex::bytes{in.data(), *n}, k);
    REQUIRE(m.has_value());
    const auto rh = wire::read_mheader(fex::bytes{plain.data(), *m});
    REQUIRE(rh.has_value());
    CHECK(wire::mkind_of(*rh) == wire::mkind::chunk);
    CHECK(wire::mstatus_of(*rh) == wire::mstatus::not_found);
    CHECK(wire::request_id_of(*rh) == 0x123456);

    // silent drops: request from an address that never peeked
    {
        auto other = net::udp_socket::open(net::family::v4);
        REQUIRE(other.has_value());
        REQUIRE(other->connect(addr).has_value());
        REQUIRE(other->send(fex::bytes{out.data(), sealed}).has_value());
        CHECK(!recv_within(*other, in, 200).has_value());
    }
    // silent drops: bad version, unknown id, wrong-length peek, response half
    REQUIRE(channel::make_peek(out, id) == wire::peek_size);
    out[0] = 2;
    REQUIRE(sock->send(fex::bytes{out.data(), wire::peek_size}).has_value());
    CHECK(!recv_within(*sock, in, 200).has_value());
    REQUIRE(channel::make_peek(out, 0xdeadbeef) == wire::peek_size);
    REQUIRE(sock->send(fex::bytes{out.data(), wire::peek_size}).has_value());
    CHECK(!recv_within(*sock, in, 200).has_value());
    REQUIRE(channel::make_peek(out, id) == wire::peek_size);
    REQUIRE(sock->send(fex::bytes{out.data(), wire::peek_size - 1}).has_value());
    CHECK(!recv_within(*sock, in, 200).has_value());
    out[1] = 0x81;
    REQUIRE(sock->send(fex::bytes{out.data(), wire::peek_size}).has_value());
    CHECK(!recv_within(*sock, in, 200).has_value());

    // #3: removing a member's card cuts the channel and resets its address
    {
        auto bob_sock = net::udp_socket::open(net::family::v4);
        REQUIRE(bob_sock.has_value());
        REQUIRE(bob_sock->connect(addr).has_value());
        const auto bob = generate_identity();
        REQUIRE(write_new_file((root + "/members/bob.dano").c_str(),
                               to_dano(card_of(bob)), identity_card_mode).has_value());
        const auto bob_id = fingerprint(bob.pub);
        REQUIRE(channel::make_peek(out, bob_id) == wire::peek_size);
        REQUIRE(bob_sock->send(fex::bytes{out.data(), wire::peek_size}).has_value());
        REQUIRE(recv_within(*bob_sock, in, 2000).has_value()); // registered -> answered
        REQUIRE(::unlink((root + "/members/bob.dano").c_str()) == 0);
        ::usleep(1'100'000); // past the registry's 1 s re-check period
        REQUIRE(bob_sock->send(fex::bytes{out.data(), wire::peek_size}).has_value());
        CHECK(!recv_within(*bob_sock, in, 300).has_value()); // gone -> silence
    }

    srv.stop();
    runner.join();
    REQUIRE(fs::remove_tree(root).has_value());
}

}

#endif
