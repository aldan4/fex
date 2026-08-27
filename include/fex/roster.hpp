// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// The roster (#6): a relay's published directory, identity only. One record
// per registry line -- a member for every member, a relay for every federate --
// carrying the name the relay assigned and the public key it goes with, and
// nothing else. `:addr` never appears here: where a node can be reached is the
// registering side's business, not the directory's.
//
// It is a danl stream like the inventory, written canonically and read
// strictly, and it travels the same way: the relay writes it as an object,
// list (#5) hands over its size and hash, and get fetches it.

#include <algorithm>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include <dano/dano.hpp>

#include <fex/crypto.hpp>
#include <fex/identity.hpp>
#include <fex/inventory.hpp>
#include <fex/path.hpp>
#include <fex/types.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::roster {

enum struct kind : u8 { member, relay }; // kind

[[nodiscard]] inline constexpr std::string_view name_of(kind k) noexcept {
    return k == kind::member ? "member" : "relay";
}

struct record {
    kind what;
    std::string name;
    crypto::x25519::public_key pub;

    bool operator==(const record&) const = default;
}; // record

struct file {
    std::vector<record> records;

    bool operator==(const file&) const = default;
}; // file

// canonical form: key order :kind :name :pub, single spaces, lowercase hex,
// records sorted by name bytewise, '\n' after every line including the last.
//
// The kind leads because it is what decides whether a record is a capsule to
// read or a relay to ask (#10.2), and a reader scanning the file wants that
// before it wants the name.
[[nodiscard]] inline std::string to_danl(file r) {
    std::ranges::sort(r.records, [](const record& a, const record& b) {
        return a.name < b.name; // #8 names are lowercase ascii: char order is bytewise
    });
    std::string out;
    for (const auto& e : r.records) {
        out += "{:kind \"";
        out += name_of(e.what);
        out += "\" :name \"";
        out += e.name;
        out += "\" :pub \"";
        out += to_hex(fex::bytes{e.pub});
        out += "\"}\n";
    }
    return out;
}

// strict reader (#6): the whole roster is rejected on a syntax error, a missing
// required key, a duplicate name or pub, invalid hex, or a name that breaks the
// segment rules of #8. A record whose kind this node does not know is skipped
// whole -- a later revision may publish kinds this one has never heard of, and
// that is not a corrupt file.
[[nodiscard]] inline std::expected<file, std::errc> parse(std::string_view danl) noexcept {
    auto reader = ::danl::reader::from_text(danl);
    if (!reader)
        return std::unexpected(std::errc::invalid_argument);
    file out;
    hash_set<std::string> names_seen, pubs_seen;
    auto records = reader->records();
    while (records.has_next()) {
        auto rec = records.next();
        if (!rec)
            return std::unexpected(std::errc::invalid_argument);
        auto map = rec->map();
        if (!map)
            return std::unexpected(std::errc::invalid_argument);
        std::string_view kind_text, name_text, pub_text;
        while (map->has_next()) {
            auto pair = map->next();
            if (!pair)
                return std::unexpected(std::errc::invalid_argument);
            auto& [key, value] = *pair;
            if (key == "kind" || key == "name" || key == "pub") {
                auto text = value.string();
                if (!text)
                    return std::unexpected(std::errc::invalid_argument);
                if (key == "kind")
                    kind_text = *text;
                else if (key == "name")
                    name_text = *text;
                else
                    pub_text = *text;
            }
            // unknown keys are skipped by the map iterator itself
        }
        if (kind_text.empty() || name_text.empty() || pub_text.empty())
            return std::unexpected(std::errc::invalid_argument);
        record e;
        if (kind_text == "member")
            e.what = kind::member;
        else if (kind_text == "relay")
            e.what = kind::relay;
        else
            continue; // a kind this revision does not know: ignored as a whole
        if (!is_valid_segment(name_text))
            return std::unexpected(std::errc::invalid_argument);
        if (pub_text.size() != 64 || !inventory::is_lower_hex(pub_text)
            || !from_hex(e.pub, pub_text))
            return std::unexpected(std::errc::invalid_argument);
        if (!names_seen.emplace(name_text).second)
            return std::unexpected(std::errc::invalid_argument);
        if (!pubs_seen.emplace(pub_text).second)
            return std::unexpected(std::errc::invalid_argument);
        e.name = name_text;
        out.records.push_back(std::move(e));
    }
    return out;
}

// the record naming this node, if the roster has one
[[nodiscard]] inline const record* find(const file& r, std::string_view name) noexcept {
    for (const auto& e : r.records)
        if (e.name == name)
            return &e;
    return nullptr;
}

} // namespace fex::roster

#ifdef FEX_WITH_TESTS

TEST_SUITE("fex::roster") {

SCENARIO("canonical output") {
    using namespace fex;
    roster::file r;
    crypto::x25519::public_key pa{}, pb{};
    REQUIRE(from_hex(pa, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    REQUIRE(from_hex(pb, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
    r.records.push_back({roster::kind::relay, "r2", pb});
    r.records.push_back({roster::kind::member, "bob", pa});
    const auto text = roster::to_danl(r);
    CHECK(text ==
          "{:kind \"member\" :name \"bob\" :pub "
          "\"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a\"}\n"
          "{:kind \"relay\" :name \"r2\" :pub "
          "\"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f\"}\n");
    // and it round-trips: sorted by name, both kinds preserved
    auto back = roster::parse(text);
    REQUIRE(back.has_value());
    REQUIRE(back->records.size() == 2);
    CHECK(back->records[0].name == "bob");
    CHECK(back->records[0].what == roster::kind::member);
    CHECK(back->records[1].name == "r2");
    CHECK(back->records[1].what == roster::kind::relay);
    CHECK(roster::to_danl(*back) == text);
    // an empty roster is no bytes at all
    CHECK(roster::to_danl(roster::file{}).empty());
    CHECK(roster::parse("")->records.empty());

    // the fixture tools/fexcheck/fexref.py publishes, so this canonical form is
    // one three implementations agree on rather than one this file asserts
    roster::file kat;
    kat.records.push_back({roster::kind::relay, "r2", pb});
    kat.records.push_back({roster::kind::member, "alice", pa});
    const auto kat_text = roster::to_danl(kat);
    CHECK(kat_text.size() == 202);
    CHECK(to_hex(fex::bytes{crypto::ascon::hash256(
              fex::bytes{reinterpret_cast<const u8*>(kat_text.data()), kat_text.size()})})
          == "29ef87f8a0f9f09692b600778284464e45a212ebd851c7432319b96ebd6e497a");
}

SCENARIO("the reader is strict about everything but what it has not heard of") {
    using namespace fex;
    const std::string_view good_pub =
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const std::string_view other_pub =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const auto line = [](std::string_view kind, std::string_view name,
                         std::string_view pub) {
        return std::string{"{:kind \""} + std::string{kind} + "\" :name \""
             + std::string{name} + "\" :pub \"" + std::string{pub} + "\"}\n";
    };

    // keys in any order, unknown keys ignored
    auto ok = roster::parse("{:pub \"" + std::string{good_pub}
                            + "\" :intro \"whatever\" :name \"bob\" :kind \"member\"}\n");
    REQUIRE(ok.has_value());
    CHECK(ok->records.size() == 1);
    CHECK(ok->records[0].name == "bob");

    // a kind nobody here knows is skipped, and the rest of the file still reads
    auto mixed = roster::parse(line("wombat", "zed", other_pub)
                               + line("member", "bob", good_pub));
    REQUIRE(mixed.has_value());
    CHECK(mixed->records.size() == 1);
    CHECK(mixed->records[0].name == "bob");

    // and everything else rejects the file whole
    CHECK(!roster::parse(line("member", "bob", good_pub)
                         + line("relay", "bob", other_pub)).has_value()); // dup name
    CHECK(!roster::parse(line("member", "bob", good_pub)
                         + line("relay", "r2", good_pub)).has_value());   // dup pub
    CHECK(!roster::parse(line("member", "Bob", good_pub)).has_value());   // #8: lowercase
    CHECK(!roster::parse(line("member", "a/b", good_pub)).has_value());   // #8: a segment
    CHECK(!roster::parse(line("member", "con", good_pub)).has_value());   // #8: reserved
    CHECK(!roster::parse(line("member", "bob", "00ff")).has_value());     // short hex
    CHECK(!roster::parse(line("member", "bob", std::string(64, 'Z'))).has_value());
    CHECK(!roster::parse("{:kind \"member\" :name \"bob\"}\n").has_value()); // no pub
    CHECK(!roster::parse("{:name \"bob\" :pub \"" + std::string{good_pub}
                         + "\"}\n").has_value());                          // no kind
    CHECK(!roster::parse("{:kind \"member\" :name \"bob\" :pub}\n").has_value());
    CHECK(!roster::parse("not a record\n").has_value());
}

SCENARIO("find names a record") {
    using namespace fex;
    roster::file r;
    crypto::x25519::public_key p{};
    r.records.push_back({roster::kind::member, "bob", p});
    CHECK(roster::find(r, "bob") != nullptr);
    CHECK(roster::find(r, "alice") == nullptr);
}

}

#endif
