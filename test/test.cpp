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

} // namespace fex_e2e_test

SCENARIO("end to end: publish, restore, mutate, converge") {
    using namespace fex;
    using namespace fex_e2e_test;
    char tmpl[] = "/tmp/fex-e2e-XXXXXX";
    char* tmp = ::mkdtemp(tmpl);
    REQUIRE(tmp != nullptr);
    const std::string base{tmp};
    const auto relay_root = base + "/relay";
    const auto root_a = base + "/a"; // publisher
    const auto root_b = base + "/b"; // restorer

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
    const auto capsule_a = root_a + "/self/mine@hub";
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
    auto published = client::publish(*req_a, cfg_a->capsule_dir);
    REQUIRE(published.has_value());
    CHECK(published->seq == 1);
    CHECK(!published->unchanged);
    const auto relay_tree = relay_root + "/capsules/alice/tree";
    CHECK(tree_fingerprint(relay_tree) == tree_fingerprint(capsule_a));
    CHECK(*fs::read_file((relay_tree + "/big.bin").c_str()) == big);

    // restore into a fresh root -> byte-identical
    auto cfg_b = client::load_config(root_b, "", "mine");
    REQUIRE(cfg_b.has_value());
    auto req_b = client::requester::connect(cfg_b->self, cfg_b->relay);
    REQUIRE(req_b.has_value());
    REQUIRE(client::restore(*req_b, cfg_b->capsule_dir, cfg_b->tmp_dir).has_value());
    CHECK(tree_fingerprint(cfg_b->capsule_dir) == tree_fingerprint(capsule_a));

    // unchanged re-publish exits early on the matching inventory hash
    published = client::publish(*req_a, cfg_a->capsule_dir);
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

    published = client::publish(*req_a, cfg_a->capsule_dir);
    REQUIRE(published.has_value());
    CHECK(published->seq == 2);
    CHECK(tree_fingerprint(relay_tree) == tree_fingerprint(capsule_a));
    CHECK(fs::stat_of((relay_tree + "/big.bin").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((relay_tree + "/deep").c_str()).kind == fs::entry_kind::missing);

    // the stale replica converges, deletions included; the rename arrives as a
    // local copy, not a download
    REQUIRE(client::restore(*req_b, cfg_b->capsule_dir, cfg_b->tmp_dir).has_value());
    CHECK(tree_fingerprint(cfg_b->capsule_dir) == tree_fingerprint(capsule_a));
    CHECK(fs::stat_of((cfg_b->capsule_dir + "/deep").c_str()).kind
          == fs::entry_kind::missing);
    CHECK(*fs::read_file((cfg_b->capsule_dir + "/moved.bin").c_str()) == big);

    // restoring right over an up-to-date tree is a no-op that still succeeds
    REQUIRE(client::restore(*req_b, cfg_b->capsule_dir, cfg_b->tmp_dir).has_value());

    srv.stop();
    runner.join();
    REQUIRE(fs::remove_tree(base).has_value());
}

}
