// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#define FEX_WITH_TESTS

// Both frontends, so every header's inline tests land in this one binary.
#include <fex/client.hpp>
#include <fex/relay.hpp>

// The end-to-end scenario exercises the client against a live relay, so it
// belongs to neither frontend: this is the only translation unit holding both.

#include <cstdlib>
#include <thread>

TEST_SUITE("fex") {

namespace fex_e2e_test {

inline std::vector<fex::u8> pattern(std::size_t n, fex::u8 salt = 0) {
    std::vector<fex::u8> data(n);
    for (std::size_t i = 0; i != n; ++i)
        data[i] = static_cast<fex::u8>((i * 131 + salt) & 0xff);
    return data;
}

inline void put_file(const std::string& path, const std::vector<fex::u8>& data) {
    REQUIRE(fex::fs::ensure_dirs(fex::fs::dir_of(path)).has_value());
    REQUIRE(fex::fs::write_file_atomic(path, fex::bytes{data}).has_value());
}

// both trees, canonicalized through the same inventory writer
inline std::string tree_fingerprint(const std::string& dir) {
    auto inv = fex::client::snapshot(dir);
    REQUIRE(inv.has_value());
    return fex::inventory::to_danl(*inv);
}

// registration (#3), as an operator does it: a member line in the relay's
// roster.danl, which is the registry and the published directory at once (#6)
inline void write_roster(
    const std::string& relay_root,
    const std::vector<std::pair<std::string, fex::crypto::x25519::public_key>>& who) {
    fex::roster::file r;
    for (const auto& [name, pub] : who)
        r.records.push_back({.name = name, .pub = pub});
    const auto text = fex::roster::to_danl(r);
    REQUIRE(fex::fs::ensure_dirs(relay_root).has_value());
    REQUIRE(fex::fs::write_file_atomic(
                relay_root + "/roster.danl",
                fex::bytes{reinterpret_cast<const fex::u8*>(text.data()), text.size()})
                .has_value());
}

// #6: the relay keeps content under the hash of its own bytes, and nowhere else
inline std::string object_path(const std::string& objects, const fex::hash256& h) {
    return objects + '/' + fex::to_hex(fex::bytes{h});
}

// every record of an inventory resolves to an object holding exactly its bytes
inline bool objects_resolve(const std::string& objects,
                            const fex::inventory::file& inv) {
    for (const auto& e : inv.entries) {
        if (e.size == 0)
            continue; // a record of size zero names no object (#9 step 4)
        auto data = fex::fs::read_file(object_path(objects, e.hash).c_str());
        if (!data || data->size() != e.size
            || fex::crypto::ascon::hash256(fex::bytes{*data}) != e.hash)
            return false;
    }
    return true;
}

// every entry of a listing, fetched into the capsule it belongs to
inline void fetch_all(fex::client::requester& r, const fex::client::published& state,
                      const std::string& files_dir, const std::string& state_dir) {
    for (const auto& e : state.inventory.entries) {
        const auto got = fex::client::fetch(r, e, files_dir, state_dir);
        REQUIRE(got.has_value());
        CHECK(*got); // nothing was there before, so every one is a download
    }
}

inline bool names(const fex::inventory::file& inv, std::string_view path) {
    for (const auto& e : inv.entries)
        if (e.path == path) return true;
    return false;
}

inline const fex::inventory::entry& record(const fex::inventory::file& inv,
                                           std::string_view path) {
    for (const auto& e : inv.entries)
        if (e.path == path) return e;
    REQUIRE(false);
    return inv.entries.front();
}

inline std::size_t files_in(const std::string& dir) {
    std::size_t n = 0;
    (void)fex::fs::walk(dir.c_str(),
        [&](std::string_view, const fex::fs::info& st) -> std::expected<void, std::errc> {
            if (st.kind == fex::fs::entry_kind::file) ++n;
            return {};
        });
    return n;
}

} // namespace fex_e2e_test

SCENARIO("end to end: publish, list, fetch, mutate, converge") {
    using namespace fex;
    using namespace fex_e2e_test;
    char tmpl[] = "/tmp/fex-e2e-XXXXXX";
    char* tmp = ::mkdtemp(tmpl);
    REQUIRE(tmp != nullptr);
    const std::string base{tmp};
    const auto relay_root = base + "/relay";
    const auto root_a = base + "/a"; // publisher
    const auto root_b = base + "/b"; // reader

    // identities and cards (#3)
    const auto relay_id = generate_identity();
    const auto alice = generate_identity();
    REQUIRE(fs::ensure_dirs(relay_root).has_value());
    REQUIRE(write_new_file((relay_root + "/node.dano").c_str(), to_dano(relay_id),
                           identity_mode).has_value());
    write_roster(relay_root, {{"alice", alice.pub}});

    relay::server srv;
    relay::options srv_opts;
    srv_opts.root = relay_root;
    srv_opts.addr = "127.0.0.1:0";
    REQUIRE(srv.start(srv_opts).has_value());
    const auto addr = srv.local_addr().to_string();
    std::thread runner{[&] { (void)srv.run(); }};

    for (const auto& root : {root_a, root_b}) {
        REQUIRE(fs::ensure_dirs(root + "/keys").has_value());
        REQUIRE(write_new_file((root + "/keys/node.dano").c_str(), to_dano(alice),
                               identity_mode).has_value());
        REQUIRE(write_new_file((root + "/keys/hub.relay.danl").c_str(),
                               to_danl(card_of(relay_id, "hub", addr)),
                               identity_card_mode).has_value());
    }

    // a capsule with nested dirs, an empty file, duplicate content, > 1 MiB
    const auto capsule_a = root_a + "/self/mine@hub/files";
    const auto state_a = root_a + "/self/mine@hub/state";
    const auto big = pattern(1024 * 1024 + 137, 1);
    const auto small = pattern(2048 + 100, 2);
    put_file(capsule_a + "/docs/x.txt", {'h', 'e', 'l', 'l', 'o'});
    put_file(capsule_a + "/empty.bin", {});
    put_file(capsule_a + "/copy1.bin", small);
    put_file(capsule_a + "/deep/copy2.bin", small);
    put_file(capsule_a + "/big.bin", big);

    auto cfg_a = client::load_config(root_a, "", "");
    REQUIRE(cfg_a.has_value());
    auto req_a = client::requester::connect(cfg_a->self, cfg_a->relay);
    REQUIRE(req_a.has_value());

    // publish -> seq 1, and every file of the capsule is now an object
    auto published = client::publish(*req_a, cfg_a->files_dir);
    REQUIRE(published.has_value());
    CHECK(published->seq == 1);
    CHECK(!published->unchanged);
    // #6: the relay lays nothing out by path. What it holds is content under
    // the hash of its own bytes, and a head naming the inventory that lists it.
    const auto objects = relay_root + "/objects";
    CHECK(objects_resolve(objects, *client::snapshot(capsule_a)));
    CHECK(*fs::read_file(
              object_path(objects, crypto::ascon::hash256(fex::bytes{big})).c_str())
          == big);
    CHECK(fs::stat_of((relay_root + "/capsules/alice/tree").c_str()).kind
          == fs::entry_kind::missing);
    CHECK(fs::stat_of((relay_root + "/capsules/alice/inventory.danl").c_str()).kind
          == fs::entry_kind::missing);
    CHECK(fs::stat_of((relay_root + "/capsules/alice/head.dano").c_str()).kind
          == fs::entry_kind::file);
    // the inventory of this commit, kept for the check after the next one
    const auto inv1_text = tree_fingerprint(capsule_a);
    const auto inv1_hash = crypto::ascon::hash256(
        fex::bytes{reinterpret_cast<const u8*>(inv1_text.data()), inv1_text.size()});
    CHECK(fs::stat_of(object_path(objects, inv1_hash).c_str()).kind
          == fs::entry_kind::file);

    // publishing left the inventory where the member can read it, and it is not a
    // record of the capsule it describes
    const auto inv_a = client::inventory_path(cfg_a->files_dir);
    CHECK(fs::stat_of(inv_a.c_str()).kind == fs::entry_kind::file);
    CHECK(tree_fingerprint(capsule_a) == inventory::to_danl(*client::snapshot(capsule_a)));
    CHECK(std::string{reinterpret_cast<const char*>(fs::read_file(inv_a.c_str())->data()),
                      fs::read_file(inv_a.c_str())->size()}
          == tree_fingerprint(capsule_a));

    // list from a fresh root: the head, then the inventory it names
    auto cfg_b = client::load_config(root_b, "", "mine");
    REQUIRE(cfg_b.has_value());
    auto req_b = client::requester::connect(cfg_b->self, cfg_b->relay);
    REQUIRE(req_b.has_value());
    auto state = client::refresh_inventory(*req_b, cfg_b->files_dir, cfg_b->state_dir);
    REQUIRE(state.has_value());
    CHECK(state->seq == 1);
    CHECK(inventory::to_danl(state->inventory) == tree_fingerprint(capsule_a));
    CHECK(*fs::read_file(client::inventory_path(cfg_b->files_dir).c_str())
          == *fs::read_file(inv_a.c_str()));

    // and fetch: every record into the place the inventory names
    fetch_all(*req_b, *state, cfg_b->files_dir, cfg_b->state_dir);
    CHECK(tree_fingerprint(cfg_b->files_dir) == tree_fingerprint(capsule_a));
    CHECK(files_in(client::staging_dir(cfg_b->state_dir)) == 0);

    // a second fetch of the same record downloads nothing
    {
        const auto again = client::fetch(*req_b, record(state->inventory, "big.bin"),
                                         cfg_b->files_dir, cfg_b->state_dir);
        REQUIRE(again.has_value());
        CHECK(!*again);
    }

    // listing again keeps the inventory already on disk (same hash, no transfer)
    {
        const auto before = fs::stat_of(client::inventory_path(cfg_b->files_dir).c_str());
        auto second = client::refresh_inventory(*req_b, cfg_b->files_dir, cfg_b->state_dir);
        REQUIRE(second.has_value());
        const auto after = fs::stat_of(client::inventory_path(cfg_b->files_dir).c_str());
        CHECK(before.mtime_ns == after.mtime_ns);
    }

    // unchanged re-publish exits early on the matching inventory hash
    published = client::publish(*req_a, cfg_a->files_dir);
    REQUIRE(published.has_value());
    CHECK(published->unchanged);
    CHECK(published->seq == 1);

    // mutate: edit, delete, add, rename (same content, new path)
    put_file(capsule_a + "/docs/x.txt", {'w', 'o', 'r', 'l', 'd', '!'});
    REQUIRE(::unlink((capsule_a + "/deep/copy2.bin").c_str()) == 0);
    REQUIRE(::rmdir((capsule_a + "/deep").c_str()) == 0);
    put_file(capsule_a + "/new/nested/y.txt", {'y'});
    REQUIRE(::rename((capsule_a + "/big.bin").c_str(),
                     (capsule_a + "/moved.bin").c_str()) == 0);

    published = client::publish(*req_a, cfg_a->files_dir);
    REQUIRE(published.has_value());
    CHECK(published->seq == 2);
    CHECK(objects_resolve(objects, *client::snapshot(capsule_a)));
    // #9: a commit takes nothing away. The inventory the head named a moment
    // ago is still an object -- no head points at it now, but collection has
    // its own clock (#6) -- so a get that raced this commit still finds what it
    // was told to ask for.
    CHECK(fs::stat_of(object_path(objects, inv1_hash).c_str()).kind
          == fs::entry_kind::file);

    // the reader sees seq 2: the paths that went are gone from the listing, the new
    // ones are in it, and what it fetches is what the publisher has
    state = client::refresh_inventory(*req_b, cfg_b->files_dir, cfg_b->state_dir);
    REQUIRE(state.has_value());
    CHECK(state->seq == 2);
    CHECK(!names(state->inventory, "big.bin"));
    CHECK(!names(state->inventory, "deep/copy2.bin"));
    CHECK(names(state->inventory, "moved.bin"));
    CHECK(names(state->inventory, "new/nested/y.txt"));

    {
        const auto got = client::fetch(*req_b, record(state->inventory, "moved.bin"),
                                       cfg_b->files_dir, cfg_b->state_dir);
        REQUIRE(got.has_value());
        CHECK(*got);
        CHECK(*fs::read_file((cfg_b->files_dir + "/moved.bin").c_str()) == big);
    }
    {
        const auto got = client::fetch(*req_b, record(state->inventory, "docs/x.txt"),
                                       cfg_b->files_dir, cfg_b->state_dir);
        REQUIRE(got.has_value());
        CHECK(*got); // the file there holds "hello", the relay has "world!"
        const std::vector<u8> edited{'w', 'o', 'r', 'l', 'd', '!'};
        CHECK(*fs::read_file((cfg_b->files_dir + "/docs/x.txt").c_str()) == edited);
    }

    // fetch deletes nothing: what left the inventory is still standing locally
    CHECK(fs::stat_of((cfg_b->files_dir + "/big.bin").c_str()).kind
          == fs::entry_kind::file);

    // a record of size zero must carry the hash of nothing at all
    {
        inventory::entry forged = record(state->inventory, "empty.bin");
        forged.hash[0] ^= 0xff;
        forged.path = "forged.bin";
        const auto refused = client::fetch(*req_b, forged, cfg_b->files_dir,
                                           cfg_b->state_dir);
        REQUIRE(!refused.has_value());
        CHECK(refused.error() == std::errc::bad_message);
    }

    // a hash the relay does not hold is refused, and leaves no staging file behind
    {
        inventory::entry absent = record(state->inventory, "moved.bin");
        absent.hash[0] ^= 0xff;
        absent.path = "absent.bin";
        const auto refused = client::fetch(*req_b, absent, cfg_b->files_dir,
                                           cfg_b->state_dir);
        REQUIRE(!refused.has_value());
        CHECK(refused.error() == std::errc::no_such_file_or_directory);
        CHECK(files_in(client::staging_dir(cfg_b->state_dir)) == 0);
    }

    srv.stop();
    runner.join();
    REQUIRE(fs::remove_tree(base).has_value());
}


// Several members on one relay (#1): one capsule each, and one object store
// under all of them. #1 draws the line where revision 9 drew it differently --
// "reading covers all capsules of the own relay", writing covers only one's own
// -- so what follows is the second member reaching for the first one's capsule
// by every means the protocol gives them, and the line showing up in what does
// and does not move.

namespace fex_tenancy_test {

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

// get(hash) chunk 0, reporting only the status the relay answered with
inline fex::wire::mstatus get_status(fex::client::requester& r, const fex::hash256& h) {
    using namespace fex;
    wire::get g{};
    g.chunk_no = 0;
    std::copy(h.begin(), h.end(), g.file_hash);
    std::array<u8, wire::get_size> cmd;
    const auto n = wire::write_get(
        cmd, wire::mheader_of(wire::mkind::get, wire::mstatus::ok,
                              client::fresh_req_id()), g);
    std::array<u8, wire::max_command> reply;
    const auto got = r.call(fex::bytes{cmd.data(), n}, reply);
    REQUIRE(got.has_value());
    const auto mh = wire::read_mheader(fex::bytes{reply.data(), *got});
    REQUIRE(mh.has_value());
    REQUIRE(wire::mkind_of(*mh) == wire::mkind::chunk);
    return wire::mstatus_of(*mh);
}

inline fex::wire::mstatus poll_status(fex::client::requester& r, const fex::hash256& h) {
    using namespace fex;
    wire::poll p{};
    std::copy(h.begin(), h.end(), p.file_hash);
    std::array<u8, wire::poll_size> cmd;
    const auto n = wire::write_poll(
        cmd, wire::mheader_of(wire::mkind::poll, wire::mstatus::ok,
                              client::fresh_req_id()), p);
    std::array<u8, wire::max_command> reply;
    const auto got = r.call(fex::bytes{cmd.data(), n}, reply);
    REQUIRE(got.has_value());
    const auto mh = wire::read_mheader(fex::bytes{reply.data(), *got});
    REQUIRE(mh.has_value());
    REQUIRE(wire::mkind_of(*mh) == wire::mkind::gaps);
    return wire::mstatus_of(*mh);
}

// a direct peek as a member sends one (#4, #5): sealed, timestamped, naming the
// capsule it asks about
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

inline fex::hash256 head_hash(const fex::wire::head& h) {
    fex::hash256 out{};
    std::copy(h.inv_hash, h.inv_hash + 32, out.begin());
    return out;
}

} // namespace fex_tenancy_test

SCENARIO("two members, one relay: separate capsules, one object store") {
    using namespace fex;
    using namespace fex_e2e_test;
    using namespace fex_tenancy_test;
    char tmpl[] = "/tmp/fex-multi-XXXXXX";
    char* tmp = ::mkdtemp(tmpl);
    REQUIRE(tmp != nullptr);
    const std::string base{tmp};
    const auto relay_root = base + "/relay";

    // one relay, two registered members (#3)
    const auto relay_id = generate_identity();
    const auto alice = generate_identity();
    const auto bob = generate_identity();
    REQUIRE(fs::ensure_dirs(relay_root).has_value());
    REQUIRE(write_new_file((relay_root + "/node.dano").c_str(), to_dano(relay_id),
                           identity_mode).has_value());
    write_roster(relay_root, {{"alice", alice.pub}, {"bob", bob.pub}});

    relay::server srv;
    relay::options srv_opts;
    srv_opts.root = relay_root;
    srv_opts.addr = "127.0.0.1:0";
    REQUIRE(srv.start(srv_opts).has_value());
    const auto addr = srv.local_addr().to_string();
    std::thread runner{[&] { (void)srv.run(); }};

    const auto root_a = base + "/a";
    const auto root_b = base + "/b";
    for (const auto& [root, who] : {std::pair{root_a, alice}, std::pair{root_b, bob}}) {
        REQUIRE(fs::ensure_dirs(root + "/keys").has_value());
        REQUIRE(write_new_file((root + "/keys/node.dano").c_str(), to_dano(who),
                               identity_mode).has_value());
        REQUIRE(write_new_file((root + "/keys/hub.relay.danl").c_str(),
                               to_danl(card_of(relay_id, "hub", addr)),
                               identity_card_mode).has_value());
    }

    const auto files_a = root_a + "/self/mine@hub/files";
    const auto files_b = root_b + "/self/mine@hub/files";
    const auto secret = pattern(3000, 11);   // spans several chunks
    const auto notes = pattern(1500, 22);
    put_file(files_a + "/docs/secret.bin", secret);
    put_file(files_b + "/notes.bin", notes);

    auto cfg_a = client::load_config(root_a, "", "");
    auto cfg_b = client::load_config(root_b, "", "");
    REQUIRE(cfg_a.has_value());
    REQUIRE(cfg_b.has_value());
    auto req_a = client::requester::connect(cfg_a->self, cfg_a->relay);
    auto req_b = client::requester::connect(cfg_b->self, cfg_b->relay);
    REQUIRE(req_a.has_value());
    REQUIRE(req_b.has_value());

    // both publish over the same socket on the relay, each into their own capsule
    auto pub_a = client::publish(*req_a, cfg_a->files_dir);
    REQUIRE(pub_a.has_value());
    CHECK(pub_a->seq == 1);
    auto pub_b = client::publish(*req_b, cfg_b->files_dir);
    REQUIRE(pub_b.has_value());
    CHECK(pub_b->seq == 1);

    // #6: a capsule is a head and nothing else; the content of both of them is
    // in one store, since a hash is a hash whoever uploaded it
    const auto objects = relay_root + "/objects";
    CHECK(objects_resolve(objects, *client::snapshot(cfg_a->files_dir)));
    CHECK(objects_resolve(objects, *client::snapshot(cfg_b->files_dir)));
    CHECK(fs::stat_of((relay_root + "/capsules/alice/head.dano").c_str()).kind
          == fs::entry_kind::file);
    CHECK(fs::stat_of((relay_root + "/capsules/bob/head.dano").c_str()).kind
          == fs::entry_kind::file);
    CHECK(fs::stat_of((relay_root + "/capsules/alice/tree").c_str()).kind
          == fs::entry_kind::missing);

    // #10.2 discovery: list says where the relay's directory stands, the file
    // comes over by get like anything else, and what it holds is both members --
    // a name and a key each, and nothing about how to reach them (#6).
    {
        const auto peer_a = client::peer_dir(cfg_a->peers_dir, cfg_a->relay_name);
        const auto where = client::list(*req_a);
        REQUIRE(where.has_value());
        CHECK(where->size != 0);

        const auto seen = client::refresh_roster(*req_a, peer_a);
        REQUIRE(seen.has_value());
        CHECK(seen->fetched);
        CHECK(seen->size == where->size);
        REQUIRE(seen->directory.records.size() == 2);
        CHECK(roster::find(seen->directory, "alice") != nullptr);
        CHECK(roster::find(seen->directory, "bob") != nullptr);

        // #10.3: it lands under the relay it was read from, and it is the file
        // the relay named -- verified before the rename put it there
        const auto path = client::roster_path(peer_a);
        REQUIRE(fs::stat_of(path.c_str()).kind == fs::entry_kind::file);
        hash256 listed_hash;
        std::copy(where->hash, where->hash + 32, listed_hash.begin());
        CHECK(*fs::hash_file(path.c_str()) == listed_hash);

        // step 4: the id in a record is what a read of that capsule is
        // addressed by -- the same id peek already answers for
        const auto* his = roster::find(seen->directory, "bob");
        REQUIRE(his != nullptr);
        CHECK(fingerprint(his->pub) == fingerprint(bob.pub));

        // asking again costs a list and a local hash, not a transfer, and
        // staging is left clean either way (#10.3)
        const auto twice = client::refresh_roster(*req_a, peer_a);
        REQUIRE(twice.has_value());
        CHECK(!twice->fetched);
        CHECK(twice->directory == seen->directory);
        CHECK(files_in(client::staging_dir(client::peer_state_dir(peer_a))) == 0);

        // and bob's own client reads the same directory off the same relay
        const auto peer_b = client::peer_dir(cfg_b->peers_dir, cfg_b->relay_name);
        const auto his_view = client::refresh_roster(*req_b, peer_b);
        REQUIRE(his_view.has_value());
        CHECK(his_view->directory == seen->directory);
    }

    // the head each of them sees is their own capsule's
    const auto head_a = req_a->peek();
    const auto head_b = req_b->peek();
    REQUIRE(head_a.has_value());
    REQUIRE(head_b.has_value());
    CHECK(head_a->seq == 1);
    CHECK(head_b->seq == 1);
    CHECK(head_hash(*head_a) != head_hash(*head_b));
    CHECK(head_a->inv_size != head_b->inv_size);

    const auto snap_a = client::snapshot(cfg_a->files_dir);
    const auto snap_b = client::snapshot(cfg_b->files_dir);
    REQUIRE(snap_a.has_value());
    REQUIRE(snap_b.has_value());
    const auto secret_hash = record(*snap_a, "docs/secret.bin").hash;
    const auto notes_hash = record(*snap_b, "notes.bin").hash;

    // Reading across is the model and not a leak (#1): get is served from the
    // store for any member, so a hash resolves whoever asks. It is a hash that
    // has to be come by -- from an inventory, which is come by from a head --
    // and #5 hands a head to anyone who peeks, so on one relay every member can
    // read every capsule. That is what "reading covers all capsules of the own
    // relay" means, spelled out.
    CHECK(get_status(*req_a, secret_hash) == wire::mstatus::ok);
    CHECK(get_status(*req_b, secret_hash) == wire::mstatus::ok);
    CHECK(get_status(*req_b, notes_hash) == wire::mstatus::ok);
    CHECK(get_status(*req_a, notes_hash) == wire::mstatus::ok);
    CHECK(poll_status(*req_b, secret_hash) == wire::mstatus::ok);
    CHECK(poll_status(*req_a, notes_hash) == wire::mstatus::ok);

    // the inventories too, which is how the hashes above would be come by
    CHECK(get_status(*req_a, head_hash(*head_a)) == wire::mstatus::ok);
    CHECK(get_status(*req_b, head_hash(*head_a)) == wire::mstatus::ok);
    CHECK(get_status(*req_a, head_hash(*head_b)) == wire::mstatus::ok);
    // and a hash nobody ever uploaded is still nothing at all
    CHECK(get_status(*req_a, crypto::ascon::hash256(fex::bytes{pattern(9, 99)}))
          == wire::mstatus::not_found);

    // An upload in flight is nobody's yet. The assembly area is the sender's
    // own, so bob's poll finds it and alice's does not; and nothing at all can
    // get it, bob included, because get is served from the store and an
    // assembled file only becomes an object when a commit says so (#6, #9).
    {
        const auto draft = pattern(4096, 33);
        const auto draft_hash = crypto::ascon::hash256(fex::bytes{draft});
        REQUIRE(client::detail::upload_file(*req_b, draft_hash,
                                            fex::bytes{draft}).has_value());
        CHECK(poll_status(*req_b, draft_hash) == wire::mstatus::ok);
        CHECK(poll_status(*req_a, draft_hash) == wire::mstatus::not_found);
        CHECK(get_status(*req_b, draft_hash) == wire::mstatus::not_found);
        CHECK(get_status(*req_a, draft_hash) == wire::mstatus::not_found);
        CHECK(fs::stat_of((relay_root + "/capsules/bob/assembly/"
                           + to_hex(fex::bytes{draft_hash})).c_str()).kind
              == fs::entry_kind::file);
        CHECK(fs::stat_of((relay_root + "/capsules/alice/assembly/"
                           + to_hex(fex::bytes{draft_hash})).c_str()).kind
              == fs::entry_kind::missing);
    }

    // Writing across: bob commits an inventory naming alice's file. Step 4 of #9
    // asks only that the content be in objects/, and it is -- so the commit is
    // accepted, and what bob has published is a second name for bytes the store
    // was already keeping. There is no field in commit that could name another
    // capsule: it lands on the sender's own, always.
    {
        inventory::file forged;
        forged.entries.push_back(record(*snap_b, "notes.bin"));
        forged.entries.push_back(
            inventory::entry{secret_hash, "stolen.bin", record(*snap_a, "docs/secret.bin").size});
        const auto text = inventory::to_danl(forged);
        const fex::bytes body{reinterpret_cast<const u8*>(text.data()), text.size()};
        const auto ih = crypto::ascon::hash256(body);
        REQUIRE(client::detail::upload_file(*req_b, ih, body).has_value());
        const auto status = client::detail::send_commit(*req_b, 2, ih);
        REQUIRE(status.has_value());
        CHECK(*status == wire::mstatus::ok);
        CHECK(*client::detail::send_commit(*req_b, 2, ih) == wire::mstatus::ok);
    }

    // and this is the line: bob's head moved, alice's did not. Her inventory is
    // the one she published, naming the paths she chose; the bytes bob's
    // inventory now also names were never hers to lose -- one object, two
    // records, in two capsules that answer to different keys.
    {
        const auto his = req_b->peek();
        REQUIRE(his.has_value());
        CHECK(his->seq == 2);

        const auto again = req_a->peek();
        REQUIRE(again.has_value());
        CHECK(again->seq == 1);
        CHECK(head_hash(*again) == head_hash(*head_a));
        CHECK(objects_resolve(objects, *client::snapshot(cfg_a->files_dir)));
        CHECK(*fs::read_file(object_path(objects, secret_hash).c_str()) == secret);
    }

    // and alice publishes over her own capsule as if none of it had happened
    {
        put_file(files_a + "/more.bin", pattern(700, 44));
        const auto second = client::publish(*req_a, cfg_a->files_dir);
        REQUIRE(second.has_value());
        CHECK(second->seq == 2);
        CHECK(objects_resolve(objects, *client::snapshot(cfg_a->files_dir)));
        const auto hers = req_a->peek();
        REQUIRE(hers.has_value());
        CHECK(hers->seq == 2);
        // bob's head is his own and stayed where his own commit left it
        const auto his = req_b->peek();
        REQUIRE(his.has_value());
        CHECK(his->seq == 2);
        CHECK(head_hash(*his) != head_hash(*hers));
    }

    // the channel itself: a peek is sealed now, so bob's key under alice's id is
    // not a peek at all. The relay looks her up, opens it with her key, fails,
    // and says nothing.
    {
        auto sock = net::udp_socket::open(net::family::v4);
        REQUIRE(sock.has_value());
        const auto ep = net::endpoint::parse(addr);
        REQUIRE(ep.has_value());
        REQUIRE(sock->connect(*ep).has_value());

        const auto alice_id = fingerprint(alice.pub);
        channel::key kb{};
        REQUIRE(channel::derive(kb, bob.priv, relay_id.pub));

        std::array<u8, wire::datagram_max> out{};
        std::array<u8, 2048> in{};
        const auto len = make_peek(out, kb, alice_id, alice_id, now_s(), 0x1234);
        REQUIRE(len != 0);
        REQUIRE(sock->send(fex::bytes{out.data(), len}).has_value());
        CHECK(!recv_within(*sock, in, 300).has_value());

        // and a command sealed with his key under her id is not a command at all:
        // the relay opens it with hers, fails, and drops it (#4)
        wire::get g{};
        std::copy(secret_hash.begin(), secret_hash.end(), g.file_hash);
        std::array<u8, wire::get_size> cmd;
        const auto n = wire::write_get(
            cmd, wire::mheader_of(wire::mkind::get, wire::mstatus::ok, 0x99), g);
        const auto sealed = channel::seal(out, alice_id, 0,
                                          fex::bytes{cmd.data(), n}, kb);
        REQUIRE(sealed != 0);
        REQUIRE(sock->send(fex::bytes{out.data(), sealed}).has_value());
        CHECK(!recv_within(*sock, in, 300).has_value());
    }

    // Revision 9 recorded a hole here: peek carried no proof of identity, so
    // anyone who knew a member's id -- it is the hash of a public card -- could
    // move the relay's cached address for that member and have their next
    // request dropped. Revision 10 seals the peek, stamps it with the instant it
    // was made and remembers its nonce, which closes that path both ways: an
    // outsider cannot forge one, and cannot replay one they watched go by.
    {
        channel::key ka{};
        REQUIRE(channel::derive(ka, alice.priv, relay_id.pub));
        const auto alice_id = fingerprint(alice.pub);

        auto hers = net::udp_socket::open(net::family::v4);
        auto theirs = net::udp_socket::open(net::family::v4);
        REQUIRE(hers.has_value());
        REQUIRE(theirs.has_value());
        const auto ep = net::endpoint::parse(addr);
        REQUIRE(ep.has_value());
        REQUIRE(hers->connect(*ep).has_value());
        REQUIRE(theirs->connect(*ep).has_value());

        std::array<u8, wire::datagram_max> out{};
        std::array<u8, 2048> in{};
        wire::get g{};
        std::copy(secret_hash.begin(), secret_hash.end(), g.file_hash);
        std::array<u8, wire::get_size> cmd;
        const auto len = wire::write_get(
            cmd, wire::mheader_of(wire::mkind::get, wire::mstatus::ok, 0x77), g);

        // her address is confirmed, so her request is served
        auto peeked = make_peek(out, ka, alice_id, alice_id, now_s(), 0x0101);
        REQUIRE(hers->send(fex::bytes{out.data(), peeked}).has_value());
        REQUIRE(recv_within(*hers, in, 2000).has_value());
        auto sealed = channel::seal(out, alice_id, 0, fex::bytes{cmd.data(), len}, ka);
        REQUIRE(sealed != 0);
        REQUIRE(hers->send(fex::bytes{out.data(), sealed}).has_value());
        REQUIRE(recv_within(*hers, in, 2000).has_value());

        // a stranger's peek naming her id is not sealed to her channel: silence,
        // and the cache does not move
        {
            channel::key stranger{};
            REQUIRE(channel::derive(stranger, generate_identity().priv, relay_id.pub));
            const auto forged = make_peek(out, stranger, alice_id, alice_id,
                                          now_s(), 0x0202);
            REQUIRE(theirs->send(fex::bytes{out.data(), forged}).has_value());
            CHECK(!recv_within(*theirs, in, 300).has_value());
        }
        sealed = channel::seal(out, alice_id, 0, fex::bytes{cmd.data(), len}, ka);
        REQUIRE(hers->send(fex::bytes{out.data(), sealed}).has_value());
        CHECK(recv_within(*hers, in, 2000).has_value()); // still served

        // nor can a peek she really made be replayed from somewhere else: the
        // relay answered it once and will not answer its twin
        peeked = make_peek(out, ka, alice_id, alice_id, now_s(), 0x0303);
        REQUIRE(hers->send(fex::bytes{out.data(), peeked}).has_value());
        REQUIRE(recv_within(*hers, in, 2000).has_value());
        REQUIRE(theirs->send(fex::bytes{out.data(), peeked}).has_value());
        CHECK(!recv_within(*theirs, in, 300).has_value());
        sealed = channel::seal(out, alice_id, 0, fex::bytes{cmd.data(), len}, ka);
        REQUIRE(hers->send(fex::bytes{out.data(), sealed}).has_value());
        CHECK(recv_within(*hers, in, 2000).has_value()); // hers throughout
    }

    srv.stop();
    runner.join();
    REQUIRE(fs::remove_tree(base).has_value());
}

}
