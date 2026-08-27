// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Relay event loop (#4): one UDP socket, one poller, single-threaded.
// Drop rules are enforced in spec order; drops are always silent.

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <expected>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <fex/channel.hpp>
#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/net/poller.hpp>
#include <fex/net/socket.hpp>
#include <fex/relay/capsule.hpp>
#include <fex/relay/objects.hpp>
#include <fex/relay/registry.hpp>
#include <fex/roster.hpp>
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
    u64 peek_window_s = 120;           // #4: W, the direct-peek replay window
}; // options

class server {
    // #4: one direct peek seen inside the window, kept only long enough to
    // refuse its twin
    struct seen_peek {
        std::array<u8, wire::nonce_size> nonce;
        u64 expires_s;
    }; // seen_peek

    std::string root_;
    identity self_{};
    u64 self_id_ = 0;                    // what a reply carries as its sender
    u64 window_s_ = 120;
    registry reg_;
    store objects_;                      // #6: content, relay-wide
    wire::roster roster_{};              // #6: where the published directory stands
    std::size_t missing_objects_ = 0;
    u64 last_collect_ns_ = 0;
    net::udp_socket sock_;
    net::poller poller_;
    hash_map<u64, net::endpoint> addrs_; // the peek-learned cache
    hash_map<u64, channel::key> keys_;
    hash_map<u64, capsule> capsules_;
    hash_map<u64, std::vector<seen_peek>> peeks_; // the peek nonce cache
    std::atomic<bool> stopping_{false};
    u64 last_reg_check_ns_ = 0;
    // what start() was doing when it gave up: every failure it can report is
    // std::errc, and "invalid argument" alone does not say whether the roster,
    // the identity or the address is the one at fault
    std::string failed_at_;

    static constexpr u64 reg_check_period_ns = 1'000'000'000; // 1 s
    static constexpr u64 collect_period_ns = 3600ull * 1'000'000'000; // 1 h
    // a backstop, not a policy: a member peeking once a second fills a hundred
    // and twenty of these in a two-minute window
    static constexpr std::size_t max_peeks_per_id = 1024;

public:

    server() = default;
    server(const server&) = delete;
    server& operator=(const server&) = delete;

    // The roster is loaded, and so refused, before the socket is opened: a relay
    // that cannot read its registry never reaches the port, rather than coming
    // up serving nobody.
    [[nodiscard]] std::expected<void, std::errc> start(const options& opts) noexcept {
        root_ = opts.root;
        failed_at_.clear();
        const auto fail = [this](std::string what, std::errc e)
            -> std::expected<void, std::errc> {
            failed_at_ = std::move(what);
            return std::unexpected(e);
        };
        const auto key_path = opts.key_path.empty() ? root_ + "/node.dano" : opts.key_path;
        auto self = read_identity(key_path.c_str());
        if (!self)
            return fail("reading the identity " + key_path, self.error());
        self_ = *self;
        self_id_ = fingerprint(self_.pub);
        window_s_ = opts.peek_window_s;
        if (auto r = fs::ensure_dirs(root_ + "/capsules"); !r)
            return fail("creating " + root_ + "/capsules", r.error());
        auto objects = store::open(root_ + "/objects");
        if (!objects)
            return fail("opening the object store " + root_ + "/objects", objects.error());
        objects_ = std::move(*objects);
        auto reg = registry::load(roster_path());
        if (!reg)
            return fail("loading the roster " + roster_path(), reg.error());
        reg_ = std::move(*reg);
        publish_roster();
        // #6, #9: every capsule is opened once at startup -- that is where a
        // staged commit is replayed and where the "every pinned object is
        // stored" invariant is checked -- and then the store is swept
        sweep(fs::now_ns(), true);
        const auto ep = net::endpoint::parse(opts.addr);
        if (!ep)
            return fail("reading the address " + opts.addr, ep.error());
        auto sock = net::udp_socket::open(ep->af());
        if (!sock)
            return fail("opening the socket", sock.error());
        sock_ = std::move(*sock);
        if (auto r = sock_.set_reuse_addr(true); !r)
            return fail("opening the socket", r.error());
        (void)sock_.set_recv_buffer_size(1 << 20); // absorb put bursts, best effort
        if (auto r = sock_.bind(*ep); !r)
            return fail("binding " + opts.addr, r.error());
        if (auto r = sock_.set_nonblocking(true); !r)
            return fail("binding " + opts.addr, r.error());
        auto poller = net::poller::open();
        if (!poller)
            return fail("opening the poller", poller.error());
        poller_ = std::move(*poller);
        if (auto r = poller_.add(sock_.fd(), net::interest::read, 0); !r)
            return fail("opening the poller", r.error());
        return {};
    }

    // what start() was doing when it failed, for the caller to say out loud
    [[nodiscard]] std::string_view failed_at() const noexcept { return failed_at_; }

    // #6: pinned objects that were not in the store at startup. Nothing can
    // conjure them back; a relay reporting a non-zero count has lost content.
    [[nodiscard]] std::size_t missing_objects() const noexcept { return missing_objects_; }

    [[nodiscard]] std::size_t members() const noexcept { return reg_.size(); }

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

    // #3, #6: the registry and the published directory are one file
    [[nodiscard]] std::string roster_path() const { return root_ + "/roster.danl"; }

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

    // #4, in spec order: version, a known sender, a valid tag -- and only then
    // is there an inner kind to dispatch on. Every drop here is silent.
    void on_datagram(fex::bytes dgram, const net::endpoint& src) noexcept {
        if (dgram.size() < wire::min_datagram)
            return;
        const auto h = wire::read_pheader(dgram); // length + version
        if (!h)
            return;
        const auto now = fs::now_ns();
        check_registry(now, reg_.find(h->id) == nullptr);
        maybe_sweep(now);
        const auto* m = reg_.find(h->id);
        if (m == nullptr)
            return;
        const auto* k = key_for(*m);
        if (k == nullptr)
            return;
        std::array<u8, wire::max_command> plain;
        const auto n = channel::open(plain, dgram, *k);
        if (!n)
            return;
        const fex::bytes cmd{plain.data(), *n};
        const auto mh = wire::read_mheader(cmd);
        if (!mh)
            return;
        // federation is a later stage: this relay is the far end of every route
        // it serves, so a packet naming a second one is not for it
        if (h->peer != 0)
            return;
        if (wire::mkind_of(*mh) == wire::mkind::peek) {
            on_peek(*h, cmd, *mh, *k, src, now);
            return;
        }
        if (!wire::is_request_kind(wire::mkind_of(*mh)))
            return; // a reply, or a kind this relay does not speak
        const auto it = addrs_.find(h->id);
        if (it == addrs_.end() || !(it->second == src))
            return; // #4: the source must be the address a peek confirmed
        on_request(*m, cmd, *mh, *k, src, now);
    }

    void check_registry(u64 now_ns, bool force) noexcept {
        if (!force && now_ns - last_reg_check_ns_ < reg_check_period_ns)
            return;
        last_reg_check_ns_ = now_ns;
        const auto reloaded = reg_.maybe_reload(roster_path());
        if (!reloaded) {
            // #6 refuses a roster whole rather than in part, so a bad edit leaves
            // the previous registry standing -- which from the outside looks
            // exactly like a registration that did not take. maybe_reload takes
            // the new mtime even on failure, so this is said once per edit, not
            // once per packet.
            std::println(stderr, "fexerver: warning: {} was not loaded ({}); "
                                 "the registry in force is the one before it",
                         roster_path(),
                         std::make_error_code(reloaded.error()).message());
            return;
        }
        if (!*reloaded)
            return;
        // #3: removing a member resets the address cache for it
        for (auto it = addrs_.begin(); it != addrs_.end();)
            it = reg_.find(it->first) == nullptr ? addrs_.erase(it) : std::next(it);
        for (auto it = keys_.begin(); it != keys_.end();)
            it = reg_.find(it->first) == nullptr ? keys_.erase(it) : std::next(it);
        for (auto it = capsules_.begin(); it != capsules_.end();)
            it = reg_.find(it->first) == nullptr ? capsules_.erase(it) : std::next(it);
        for (auto it = peeks_.begin(); it != peeks_.end();)
            it = reg_.find(it->first) == nullptr ? peeks_.erase(it) : std::next(it);
        publish_roster();
    }

    // #6: what list points at and get serves is the registry file itself, byte
    // for byte. Nothing is rendered, so there is nothing that can fall out of
    // step with what the operator wrote.
    void publish_roster() noexcept {
        const auto body = reg_.text();
        roster_.size = body.size();
        std::copy(reg_.hash().begin(), reg_.hash().end(), roster_.hash);
        if (!body.empty())
            (void)objects_.put(body, reg_.hash()); // an empty one is nothing to fetch
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
        auto cap = capsule::open(root_ + "/capsules/" + m.name, objects_);
        if (!cap)
            return nullptr;
        return &capsules_.emplace(m.id, std::move(*cap)).first->second;
    }

    // #6: garbage collection, and at startup the invariant that goes with it.
    // Every registered member's capsule is opened first: a capsule nobody has
    // spoken to yet still pins objects, and collecting them would be the one
    // irreversible mistake this relay can make.
    void sweep(u64 now_ns, bool startup) noexcept {
        last_collect_ns_ = now_ns;
        hash256_set pinned;
        hash256 roster_hash;
        std::copy(roster_.hash, roster_.hash + 32, roster_hash.begin());
        pinned.insert(roster_hash); // #6: the current roster is pinned
        for (const auto& [id, m] : reg_)
            if (auto* cap = capsule_for(m); cap != nullptr)
                cap->pins(pinned);
        if (startup)
            missing_objects_ = objects_.missing(pinned);
        (void)objects_.collect(pinned, now_ns);
    }

    void maybe_sweep(u64 now_ns) noexcept {
        if (now_ns - last_collect_ns_ < collect_period_ns)
            return;
        sweep(now_ns, false);
    }

    // #4: the nonce cache, per sender, holding what was seen inside the window.
    // False means this nonce has been seen -- a replay, and a silent drop. Like
    // the addr cache it may be lost, so none of it is written down.
    [[nodiscard]] bool remember(u64 id, const u8 (&nonce)[wire::nonce_size],
                                u64 now_s) noexcept {
        auto& seen = peeks_[id];
        std::erase_if(seen, [now_s](const seen_peek& p) { return p.expires_s <= now_s; });
        for (const auto& p : seen)
            if (std::equal(p.nonce.begin(), p.nonce.end(), nonce))
                return false;
        if (seen.size() >= max_peeks_per_id)
            return false; // a sender flooding its own cache waits out the window
        seen_peek fresh{};
        std::copy(nonce, nonce + wire::nonce_size, fresh.nonce.begin());
        fresh.expires_s = now_s + window_s_;
        seen.push_back(fresh);
        return true;
    }

    // peek (#4, #5): the head of a capsule, and on the direct leg the one packet
    // that need not come from the confirmed address -- it is what confirms it.
    // What stands in for the address rule is the window and the nonce cache.
    void on_peek(const wire::pheader& h, fex::bytes cmd, wire::mheader mh,
                 const channel::key& k, const net::endpoint& src, u64 now_ns) noexcept {
        const auto p = wire::read_peek(cmd);
        if (!p)
            return;
        const u64 now_s = now_ns / 1'000'000'000ull;
        const u64 skew = now_s > p->time ? now_s - p->time : p->time - now_s;
        if (skew > window_s_)
            return;
        if (!remember(h.id, h.nonce, now_s))
            return;
        addrs_[h.id] = src;
        // #5: target is always explicit, the requester's own capsule included;
        // one this relay does not hold is not_found with the rest zeroed
        wire::head msg{};
        auto status = wire::mstatus::not_found;
        if (const auto* t = reg_.find(p->target); t != nullptr) {
            status = wire::mstatus::internal;
            if (auto* cap = capsule_for(*t); cap != nullptr) {
                msg = cap->head_msg();
                status = wire::mstatus::ok;
            }
        }
        std::array<u8, wire::head_size> plain;
        const auto n = wire::write_head(
            plain, wire::mheader_of(wire::mkind::head, status,
                                    wire::request_id_of(mh)), msg);
        respond(fex::bytes{plain.data(), n}, k, src);
    }

    // put, poll and commit act on the sender's own capsule; get is answered
    // from the object store, which is the relay's and not any one member's (#6)
    void on_request(const member& m, fex::bytes cmd, wire::mheader mh,
                    const channel::key& k, const net::endpoint& src,
                    u64 now_ns) noexcept {
        const auto req_id = wire::request_id_of(mh);
        std::array<u8, wire::max_command> reply;
        std::size_t reply_len = 0;

        if (wire::mkind_of(mh) == wire::mkind::list) {
            if (!wire::read_list(cmd))
                return;
            reply_len = wire::write_roster(
                reply, wire::mheader_of(wire::mkind::roster, wire::mstatus::ok, req_id),
                roster_);
            if (reply_len != 0)
                respond(fex::bytes{reply.data(), reply_len}, k, src);
            return;
        }

        if (wire::mkind_of(mh) == wire::mkind::get) {
            const auto g = wire::read_get(cmd);
            if (!g)
                return;
            std::array<u8, wire::chunk_data_size> data;
            const auto got = objects_.get_chunk(*g, data, now_ns);
            const auto status = got ? wire::mstatus::ok : got.error();
            const auto body = got ? fex::bytes{data.data(), *got} : fex::bytes{};
            reply_len = wire::write_chunk(
                reply, wire::mheader_of(wire::mkind::chunk, status, req_id), body);
            if (reply_len != 0)
                respond(fex::bytes{reply.data(), reply_len}, k, src);
            return;
        }

        auto* cap = capsule_for(m);
        if (cap == nullptr)
            return;
        switch (wire::mkind_of(mh)) {
        case wire::mkind::put: {
            const auto p = wire::read_put(cmd);
            if (p)
                cap->put_chunk(*p);
            return; // put is never answered (#5)
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
            respond(fex::bytes{reply.data(), reply_len}, k, src);
    }

    // #4: a reply names this relay as its sender and peer = 0 -- the packet is
    // for the node it goes to. The nonce is fresh: the relay is the sender on
    // this leg.
    void respond(fex::bytes plain, const channel::key& k,
                 const net::endpoint& dst) noexcept {
        std::array<u8, wire::datagram_max> dgram;
        const auto n = channel::seal(dgram, self_id_, 0, plain, k);
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

// a direct peek as a member sends one (#4, #5): sealed like everything else,
// carrying the instant it was made and the capsule it asks about
inline std::size_t make_peek(std::span<fex::u8> out, const fex::channel::key& k,
                             fex::u64 id, fex::u64 target, fex::u64 time,
                             fex::u64 req_id) {
    using namespace fex;
    std::array<u8, wire::peek_size> cmd;
    const auto n = wire::write_peek(
        cmd, wire::mheader_of(wire::mkind::peek, wire::mstatus::ok, req_id),
        wire::peek{time, target});
    return channel::seal(out, id, 0, fex::bytes{cmd.data(), n}, k);
}

inline fex::u64 now_s() noexcept { return fex::fs::now_ns() / 1'000'000'000ull; }

// registration (#3), as an operator does it: a member line in the relay's
// roster.danl, which is the registry and the published directory at once (#6)
inline void write_roster(
    const std::string& root,
    const std::vector<std::pair<std::string, fex::crypto::x25519::public_key>>& who) {
    fex::roster::file r;
    for (const auto& [name, pub] : who)
        r.records.push_back(fex::roster::member_record(name, pub));
    const auto text = fex::roster::to_danl(r);
    REQUIRE(fex::fs::write_file_atomic(
                root + "/roster.danl",
                fex::bytes{reinterpret_cast<const fex::u8*>(text.data()), text.size()})
                .has_value());
    ::usleep(20'000); // so a rewrite is a visible change of mtime
}

} // namespace fex_server_test

SCENARIO("server: peek -> head, request dispatch, drop rules") {
    using namespace fex;
    using namespace fex_server_test;
    char tmpl[] = "/tmp/fex-srv-XXXXXX";
    char* tmp = ::mkdtemp(tmpl);
    REQUIRE(tmp != nullptr);
    const std::string root{tmp};

    const auto relay_key = generate_identity();
    const auto alice = generate_identity();
    const auto carol = generate_identity();
    REQUIRE(write_new_file((root + "/node.dano").c_str(), to_dano(relay_key),
                           identity_mode).has_value());
    write_roster(root, {{"alice", alice.pub}, {"carol", carol.pub}});

    relay::server srv;
    relay::options opts;
    opts.root = root;
    opts.addr = "127.0.0.1:0";
    REQUIRE(srv.start(opts).has_value());
    const auto addr = srv.local_addr();
    REQUIRE(addr.valid());
    std::thread runner{[&] { (void)srv.run(); }};

    const auto id = fingerprint(alice.pub);
    const auto carol_id = fingerprint(carol.pub);
    const auto relay_fp = fingerprint(relay_key.pub);
    channel::key k{};
    REQUIRE(channel::derive(k, alice.priv, relay_key.pub));

    auto sock = net::udp_socket::open(net::family::v4);
    REQUIRE(sock.has_value());
    REQUIRE(sock->connect(addr).has_value());

    std::array<fex::u8, wire::datagram_max> out{};
    std::array<fex::u8, wire::datagram_max> in{};
    std::array<fex::u8, wire::max_command> plain{};

    // a sealed peek -> head with seq 0 (never published), the request id echoed,
    // and the relay -- not the member -- named as the sender
    auto len = make_peek(out, k, id, id, now_s(), 0xabcdef);
    REQUIRE(len == wire::pheader_size + wire::peek_size + wire::aead_tag_size);
    REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value());
    auto n = recv_within(*sock, in, 2000);
    REQUIRE(n.has_value());
    const auto ph = wire::read_pheader(fex::bytes{in.data(), *n});
    REQUIRE(ph.has_value());
    CHECK(ph->id == relay_fp);
    CHECK(ph->peer == 0);
    auto m = channel::open(plain, fex::bytes{in.data(), *n}, k);
    REQUIRE(m.has_value());
    auto mh = wire::read_mheader(fex::bytes{plain.data(), *m});
    REQUIRE(mh.has_value());
    CHECK(wire::mkind_of(*mh) == wire::mkind::head);
    CHECK(wire::mstatus_of(*mh) == wire::mstatus::ok);
    CHECK(wire::request_id_of(*mh) == 0xabcdef);
    const auto head = wire::read_head(fex::bytes{plain.data(), *m});
    REQUIRE(head.has_value());
    CHECK(head->seq == 0);

    // #4: that very datagram again is a replay, and the nonce cache refuses it
    REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value());
    CHECK(!recv_within(*sock, in, 300).has_value());

    // a peek made long enough ago to fall outside the window, either way
    len = make_peek(out, k, id, id, now_s() - 500, 0x111111);
    REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value());
    CHECK(!recv_within(*sock, in, 300).has_value());
    len = make_peek(out, k, id, id, now_s() + 500, 0x222222);
    REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value());
    CHECK(!recv_within(*sock, in, 300).has_value());

    // #5: a target this relay does not hold -> not_found, the rest zeroed
    len = make_peek(out, k, id, 0xdeadbeef, now_s(), 0x333333);
    REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value());
    n = recv_within(*sock, in, 2000);
    REQUIRE(n.has_value());
    m = channel::open(plain, fex::bytes{in.data(), *n}, k);
    REQUIRE(m.has_value());
    mh = wire::read_mheader(fex::bytes{plain.data(), *m});
    REQUIRE(mh.has_value());
    CHECK(wire::mkind_of(*mh) == wire::mkind::head);
    CHECK(wire::mstatus_of(*mh) == wire::mstatus::not_found);
    const auto empty_head = wire::read_head(fex::bytes{plain.data(), *m});
    REQUIRE(empty_head.has_value());
    CHECK(empty_head->seq == 0);
    CHECK(empty_head->inv_size == 0);
    CHECK(std::all_of(empty_head->inv_hash, empty_head->inv_hash + 32,
                      [](u8 b) { return b == 0; }));

    // and another member's capsule, asked about over alice's own channel
    len = make_peek(out, k, id, carol_id, now_s(), 0x444444);
    REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value());
    n = recv_within(*sock, in, 2000);
    REQUIRE(n.has_value());
    m = channel::open(plain, fex::bytes{in.data(), *n}, k);
    REQUIRE(m.has_value());
    mh = wire::read_mheader(fex::bytes{plain.data(), *m});
    REQUIRE(mh.has_value());
    CHECK(wire::mstatus_of(*mh) == wire::mstatus::ok);
    CHECK(wire::request_id_of(*mh) == 0x444444);

    // get of an unknown hash -> chunk with not_found
    wire::get g{};
    g.chunk_no = 0;
    for (auto& b : g.file_hash)
        b = 0x42;
    std::array<fex::u8, wire::get_size> cmd;
    REQUIRE(wire::write_get(cmd, wire::mheader_of(wire::mkind::get, wire::mstatus::ok,
                                                  0x123456), g) == wire::get_size);
    const auto sealed = channel::seal(out, id, 0, fex::bytes{cmd}, k);
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

    // silent drops: a request from an address that never peeked
    {
        auto other = net::udp_socket::open(net::family::v4);
        REQUIRE(other.has_value());
        REQUIRE(other->connect(addr).has_value());
        REQUIRE(other->send(fex::bytes{out.data(), sealed}).has_value());
        CHECK(!recv_within(*other, in, 200).has_value());
    }
    // a bad version
    REQUIRE(sock->send(fex::bytes{out.data(), sealed}).has_value());
    REQUIRE(recv_within(*sock, in, 2000).has_value()); // (the same get still works)
    out[0] = 2;
    REQUIRE(sock->send(fex::bytes{out.data(), sealed}).has_value());
    CHECK(!recv_within(*sock, in, 200).has_value());
    out[0] = 1;
    // an id nobody registered
    {
        channel::key stranger{};
        REQUIRE(channel::derive(stranger, generate_identity().priv, relay_key.pub));
        len = make_peek(out, stranger, 0xdeadbeef, 0xdeadbeef, now_s(), 0x555555);
        REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value());
        CHECK(!recv_within(*sock, in, 200).has_value());
    }
    // a datagram too short to hold a prefix and a tag
    len = make_peek(out, k, id, id, now_s(), 0x666666);
    REQUIRE(sock->send(fex::bytes{out.data(), wire::min_datagram - 1}).has_value());
    CHECK(!recv_within(*sock, in, 200).has_value());
    // a peek naming a second relay: federation, which this stage does not route
    {
        std::array<fex::u8, wire::peek_size> pk;
        const auto pn = wire::write_peek(
            pk, wire::mheader_of(wire::mkind::peek, wire::mstatus::ok, 0x777777),
            wire::peek{now_s(), id});
        const auto forwarded = channel::seal(out, id, 0x99, fex::bytes{pk.data(), pn}, k);
        REQUIRE(sock->send(fex::bytes{out.data(), forwarded}).has_value());
        CHECK(!recv_within(*sock, in, 200).has_value());
    }
    // and a reply arriving from a member, which is not a thing a member sends
    {
        std::array<fex::u8, wire::head_size> hd{};
        const auto hn = wire::write_head(
            hd, wire::mheader_of(wire::mkind::head, wire::mstatus::ok, 0x888888),
            wire::head{});
        const auto backwards = channel::seal(out, id, 0, fex::bytes{hd.data(), hn}, k);
        REQUIRE(sock->send(fex::bytes{out.data(), backwards}).has_value());
        CHECK(!recv_within(*sock, in, 200).has_value());
    }

    // #3: removing a member's card cuts the channel and resets its address
    {
        auto bob_sock = net::udp_socket::open(net::family::v4);
        REQUIRE(bob_sock.has_value());
        REQUIRE(bob_sock->connect(addr).has_value());
        const auto bob = generate_identity();
        write_roster(root, {{"alice", alice.pub}, {"carol", carol.pub},
                            {"bob", bob.pub}});
        const auto bob_id = fingerprint(bob.pub);
        channel::key bk{};
        REQUIRE(channel::derive(bk, bob.priv, relay_key.pub));
        len = make_peek(out, bk, bob_id, bob_id, now_s(), 0x999999);
        REQUIRE(bob_sock->send(fex::bytes{out.data(), len}).has_value());
        REQUIRE(recv_within(*bob_sock, in, 2000).has_value()); // registered -> answered
        write_roster(root, {{"alice", alice.pub}, {"carol", carol.pub}});
        ::usleep(1'100'000); // past the registry's 1 s re-check period
        len = make_peek(out, bk, bob_id, bob_id, now_s(), 0xaaaaaa);
        REQUIRE(bob_sock->send(fex::bytes{out.data(), len}).has_value());
        CHECK(!recv_within(*bob_sock, in, 300).has_value()); // gone -> silence
    }

    srv.stop();
    runner.join();
    REQUIRE(fs::remove_tree(root).has_value());
}

SCENARIO("server: list -> roster, and the roster follows the registry") {
    using namespace fex;
    using namespace fex_server_test;
    char tmpl[] = "/tmp/fex-roster-XXXXXX";
    char* tmp = ::mkdtemp(tmpl);
    REQUIRE(tmp != nullptr);
    const std::string root{tmp};

    const auto relay_key = generate_identity();
    const auto alice = generate_identity();
    REQUIRE(write_new_file((root + "/node.dano").c_str(), to_dano(relay_key),
                           identity_mode).has_value());
    write_roster(root, {{"alice", alice.pub}});

    relay::server srv;
    relay::options opts;
    opts.root = root;
    opts.addr = "127.0.0.1:0";
    REQUIRE(srv.start(opts).has_value());
    const auto addr = srv.local_addr();
    std::thread runner{[&] { (void)srv.run(); }};

    const auto id = fingerprint(alice.pub);
    channel::key k{};
    REQUIRE(channel::derive(k, alice.priv, relay_key.pub));
    auto sock = net::udp_socket::open(net::family::v4);
    REQUIRE(sock.has_value());
    REQUIRE(sock->connect(addr).has_value());

    std::array<fex::u8, wire::datagram_max> out{};
    std::array<fex::u8, wire::datagram_max> in{};
    std::array<fex::u8, wire::max_command> plain{};

    // the address has to be confirmed before anything but a peek is answered
    auto len = make_peek(out, k, id, id, now_s(), 0x010101);
    REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value());
    REQUIRE(recv_within(*sock, in, 2000).has_value());

    // #5: list carries nothing but its prefix and comes back as a pointer
    const auto ask_list = [&](u64 req_id) -> std::optional<wire::roster> {
        std::array<fex::u8, wire::list_size> cmd;
        const auto n = wire::write_list(
            cmd, wire::mheader_of(wire::mkind::list, wire::mstatus::ok, req_id));
        const auto sealed = channel::seal(out, id, 0, fex::bytes{cmd.data(), n}, k);
        if (!sock->send(fex::bytes{out.data(), sealed}))
            return std::nullopt;
        const auto got = recv_within(*sock, in, 2000);
        if (!got)
            return std::nullopt;
        const auto m = channel::open(plain, fex::bytes{in.data(), *got}, k);
        if (!m)
            return std::nullopt;
        const auto mh = wire::read_mheader(fex::bytes{plain.data(), *m});
        if (!mh || wire::mkind_of(*mh) != wire::mkind::roster
            || wire::request_id_of(*mh) != req_id
            || wire::mstatus_of(*mh) != wire::mstatus::ok)
            return std::nullopt;
        return wire::read_roster(fex::bytes{plain.data(), *m});
    };

    // #6: the file it points at is an object like any other, and it holds the
    // registry as identity and nothing else
    const auto first = ask_list(0x111111);
    REQUIRE(first.has_value());
    CHECK(first->size != 0);
    hash256 rh;
    std::copy(first->hash, first->hash + 32, rh.begin());
    auto text = fs::read_file((root + "/objects/" + to_hex(fex::bytes{rh})).c_str());
    REQUIRE(text.has_value());
    CHECK(text->size() == first->size);
    CHECK(crypto::ascon::hash256(fex::bytes{*text}) == rh);
    auto parsed = roster::parse(std::string_view{
        reinterpret_cast<const char*>(text->data()), text->size()});
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->records.size() == 1);
    CHECK(parsed->records[0].name == "alice");
    CHECK(parsed->records[0].what() == roster::kind::member);
    CHECK(parsed->records[0].pub == alice.pub);
    // identity only: an address never appears here (#6)
    CHECK(std::string_view{reinterpret_cast<const char*>(text->data()), text->size()}
              .find(":addr") == std::string_view::npos);

    // asking twice without a registration between says the same thing
    const auto again = ask_list(0x222222);
    REQUIRE(again.has_value());
    CHECK(again->size == first->size);
    CHECK(std::equal(again->hash, again->hash + 32, first->hash));

    // #6: registering a member rebuilds it, and only that rebuilds it
    const auto dave = generate_identity();
    write_roster(root, {{"alice", alice.pub}, {"dave", dave.pub}});
    ::usleep(1'100'000); // past the registry's re-check period
    len = make_peek(out, k, id, id, now_s(), 0x030303);
    REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value()); // any datagram will do
    REQUIRE(recv_within(*sock, in, 2000).has_value());
    const auto grown = ask_list(0x444444);
    REQUIRE(grown.has_value());
    CHECK(grown->size > first->size);
    std::copy(grown->hash, grown->hash + 32, rh.begin());
    text = fs::read_file((root + "/objects/" + to_hex(fex::bytes{rh})).c_str());
    REQUIRE(text.has_value());
    parsed = roster::parse(std::string_view{
        reinterpret_cast<const char*>(text->data()), text->size()});
    REQUIRE(parsed.has_value());
    CHECK(parsed->records.size() == 2);
    CHECK(roster::find(*parsed, "alice") != nullptr);
    CHECK(roster::find(*parsed, "dave") != nullptr);
    // sorted bytewise by name (#6), so alice comes first
    CHECK(parsed->records[0].name == "alice");

    srv.stop();
    runner.join();
    REQUIRE(fs::remove_tree(root).has_value());
}

SCENARIO("server: a roster it cannot read stops it before the port is opened") {
    using namespace fex;
    using namespace fex_server_test;
    char tmpl[] = "/tmp/fex-badroster-XXXXXX";
    char* tmp = ::mkdtemp(tmpl);
    REQUIRE(tmp != nullptr);
    const std::string root{tmp};

    const auto relay_key = generate_identity();
    const auto alice = generate_identity();
    REQUIRE(write_new_file((root + "/node.dano").c_str(), to_dano(relay_key),
                           identity_mode).has_value());

    // #6 refuses a roster whole, and #8 refuses the name: one bad line is all it
    // takes, which is what a half-finished hand edit leaves behind
    const std::string bad = "{:kind \"id_card\" :name \"BOB\" :pub \"zz\"}\n";
    REQUIRE(fs::write_file_atomic(
                root + "/roster.danl",
                fex::bytes{reinterpret_cast<const u8*>(bad.data()), bad.size()})
                .has_value());

    relay::server srv;
    relay::options opts;
    opts.root = root;
    opts.addr = "127.0.0.1:0";
    const auto started = srv.start(opts);
    REQUIRE_FALSE(started.has_value());
    CHECK(started.error() == std::errc::invalid_argument);
    // which of the things it reads was the bad one, for the operator
    CHECK(srv.failed_at().find("roster") != std::string_view::npos);
    // and it never reached the socket: a relay serving nobody would look alive
    CHECK_FALSE(srv.local_addr().valid());

    // the same root, once the roster reads, comes up
    write_roster(root, {{"alice", alice.pub}});
    relay::server good;
    REQUIRE(good.start(opts).has_value());
    CHECK(good.members() == 1);
    CHECK(good.local_addr().valid());

    REQUIRE(fs::remove_tree(root).has_value());
}

}

#endif
