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
    REQUIRE(fs::ensure_dirs(relay_root + "/members").has_value());
    REQUIRE(write_new_file((relay_root + "/node.dano").c_str(), to_dano(relay_id),
                           identity_mode).has_value());
    REQUIRE(write_new_file((relay_root + "/members/alice.dano").c_str(),
                           to_dano(card_of(alice)), identity_card_mode).has_value());

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
        REQUIRE(write_new_file((root + "/keys/hub.relay.dano").c_str(),
                               to_dano(card_of(relay_id, addr)),
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

    // publish -> seq 1, tree on the relay is byte-identical
    auto published = client::publish(*req_a, cfg_a->files_dir);
    REQUIRE(published.has_value());
    CHECK(published->seq == 1);
    CHECK(!published->unchanged);
    const auto relay_tree = relay_root + "/capsules/alice/tree";
    CHECK(tree_fingerprint(relay_tree) == tree_fingerprint(capsule_a));
    CHECK(*fs::read_file((relay_tree + "/big.bin").c_str()) == big);

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
    CHECK(tree_fingerprint(relay_tree) == tree_fingerprint(capsule_a));
    CHECK(fs::stat_of((relay_tree + "/big.bin").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((relay_tree + "/deep").c_str()).kind == fs::entry_kind::missing);

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

}
