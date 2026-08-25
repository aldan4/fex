// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Member registry (#3): the id -> member map built from members/*.dano and
// rebuilt when the directory changes. Two cards with one public key -- error.

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/path.hpp>
#include <fex/types.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::relay {

struct member {
    std::string name; // file stem, obeys #8 segment rules
    crypto::x25519::public_key pub;
    u64 id;
}; // member

class registry {
    hash_map<u64, member> by_id_;
    u64 dir_mtime_ns_ = 0;

public:

    [[nodiscard]] static std::expected<registry, std::errc>
    load(const std::string& members_dir) noexcept {
        registry reg;
        reg.dir_mtime_ns_ = fs::stat_of(members_dir.c_str()).mtime_ns;
        hash_set<std::string> pubs_seen;
        DIR* const dir = ::opendir(members_dir.c_str());
        if (dir == nullptr)
            return fs::failure();
        while (const auto* e = ::readdir(dir)) {
            const std::string_view name = e->d_name;
            if (!name.ends_with(".dano"))
                continue;
            const auto stem = name.substr(0, name.size() - 5);
            if (!is_valid_segment(stem)) {
                ::closedir(dir);
                return std::unexpected(std::errc::invalid_argument);
            }
            const auto path = members_dir + '/' + std::string{name};
            auto card = read_identity_card(path.c_str());
            if (!card) {
                ::closedir(dir);
                return std::unexpected(card.error());
            }
            if (!pubs_seen.emplace(to_hex(fex::bytes{card->pub})).second) {
                ::closedir(dir); // two cards with one public key
                return std::unexpected(std::errc::invalid_argument);
            }
            member m;
            m.name = stem;
            m.pub = card->pub;
            m.id = fingerprint(card->pub);
            if (!reg.by_id_.emplace(m.id, std::move(m)).second) {
                ::closedir(dir); // fingerprint collision counts as a registry error too
                return std::unexpected(std::errc::invalid_argument);
            }
        }
        ::closedir(dir);
        return reg;
    }

    [[nodiscard]] const member* find(u64 id) const noexcept {
        const auto it = by_id_.find(id);
        return it == by_id_.end() ? nullptr : &it->second;
    }

    [[nodiscard]] std::size_t size() const noexcept {
        return by_id_.size();
    }

    [[nodiscard]] bool changed_on_disk(const std::string& members_dir) const noexcept {
        return fs::stat_of(members_dir.c_str()).mtime_ns != dir_mtime_ns_;
    }

    // rescan when the directory mtime moved; returns true when the registry was
    // rebuilt (the caller resets its address cache accordingly); a rescan that
    // fails keeps the old registry and reports the error
    [[nodiscard]] std::expected<bool, std::errc>
    maybe_reload(const std::string& members_dir) noexcept {
        if (!changed_on_disk(members_dir))
            return false;
        auto fresh = load(members_dir);
        if (!fresh)
            return std::unexpected(fresh.error());
        *this = std::move(*fresh);
        return true;
    }
}; // registry

} // namespace fex::relay

#ifdef FEX_WITH_TESTS

#include <cstdlib>

TEST_SUITE("fex::relay") {

SCENARIO("registry load, duplicates, reload") {
    using namespace fex;
    char tmpl[] = "/tmp/fex-reg-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir{root};

    const auto alice = generate_identity();
    const auto bob = generate_identity();
    REQUIRE(write_new_file((dir + "/alice.dano").c_str(),
                           to_dano(card_of(alice)), identity_card_mode).has_value());
    REQUIRE(write_new_file((dir + "/bob.dano").c_str(),
                           to_dano(card_of(bob)), identity_card_mode).has_value());

    auto reg = relay::registry::load(dir);
    REQUIRE(reg.has_value());
    CHECK(reg->size() == 2);
    const auto* m = reg->find(fingerprint(alice.pub));
    REQUIRE(m != nullptr);
    CHECK(m->name == "alice");
    CHECK(m->pub == alice.pub);
    CHECK(reg->find(0xdeadbeefull) == nullptr);

    // duplicate public key under another name -> registry error
    REQUIRE(write_new_file((dir + "/alice2.dano").c_str(),
                           to_dano(card_of(alice)), identity_card_mode).has_value());
    CHECK(!relay::registry::load(dir).has_value());
    REQUIRE(::unlink((dir + "/alice2.dano").c_str()) == 0);

    // invalid member name -> registry error
    REQUIRE(write_new_file((dir + "/BAD.dano").c_str(),
                           to_dano(card_of(bob)), identity_card_mode).has_value());
    CHECK(!relay::registry::load(dir).has_value());
    REQUIRE(::unlink((dir + "/BAD.dano").c_str()) == 0);

    // removal is picked up by maybe_reload
    auto reg2 = relay::registry::load(dir);
    REQUIRE(reg2.has_value());
    REQUIRE(::unlink((dir + "/bob.dano").c_str()) == 0);
    const auto reloaded = reg2->maybe_reload(dir);
    REQUIRE(reloaded.has_value());
    CHECK(*reloaded);
    CHECK(reg2->size() == 1);
    CHECK(reg2->find(fingerprint(bob.pub)) == nullptr);

    REQUIRE(fs::remove_tree(dir).has_value());
}

}

#endif
