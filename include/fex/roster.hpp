// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// The roster (#6): a relay's published directory. One record per registry line,
// and the record is a card (#3), unchanged. Registering someone is their card
// appended to this file, so what a node published about itself is what the
// directory carries: the name, the intro it wrote, the algorithm and the key.
//
// There is no member/relay kind to write down. Every line is a card, and a card
// with an `:addr` is a relay's -- the same thing `--addr` decides at generation.
//
// A record carrying `:priv` is refused, roster and all: an identity pasted where
// a card was meant is a mistake this file must never publish.
//
// It is a danl stream like the inventory, written canonically and read strictly,
// and it travels the same way: the relay writes it as an object, list (#5) hands
// over its size and hash, and get fetches it.

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

// what a record turns out to be, read off its addr rather than written down
enum struct kind : u8 { member, relay }; // kind

struct record {
    std::string name;
    std::string intro;                  // what the node said about itself, or empty
    std::string addr;                   // a relay answers here; empty for a member
    crypto::x25519::public_key pub;

    [[nodiscard]] kind what() const noexcept {
        return addr.empty() ? kind::member : kind::relay;
    }

    bool operator==(const record&) const = default;
}; // record

[[nodiscard]] inline identity_card card_of(const record& e) {
    return identity_card{.pub = e.pub, .name = e.name, .addr = e.addr, .intro = e.intro};
}

struct file {
    std::vector<record> records;

    bool operator==(const file&) const = default;
}; // file

// canonical form: every line is a card, written by the one writer there is
// (#3), records sorted by name bytewise, '\n' after every line including the
// last. A canonical roster line and a card are not merely alike -- they are the
// same text, produced by the same code.
[[nodiscard]] inline std::string to_danl(file r) {
    std::ranges::sort(r.records, [](const record& a, const record& b) {
        return a.name < b.name; // #8 names are lowercase ascii: char order is bytewise
    });
    std::string out;
    for (const auto& e : r.records)
        out += fex::to_danl(card_of(e));
    return out;
}

// strict reader (#6): the whole roster is rejected on a syntax error, a missing
// required key, a `:priv` where a card was meant, invalid hex, an unusable
// `:addr`, or a name that breaks the segment rules of #8. A record whose kind
// this node does not know is skipped whole -- a later revision may publish kinds
// this one has never heard of, and that is not a corrupt file.
//
// Duplicate names and keys are refused here too, though #6 asks that of the
// registry rather than of a reader: this reader holds the whole file anyway --
// it is the one a relay loads its registry with (#3) -- so the check is free.
// A reader that walks a served roster instead need not keep the memory it
// takes, and nothing it would miss can reach it from a conforming relay.
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
        std::string_view kind_text, name_text, intro_text, addr_text, pub_text;
        while (map->has_next()) {
            auto pair = map->next();
            if (!pair)
                return std::unexpected(std::errc::invalid_argument);
            auto& [key, value] = *pair;
            // an identity has a :priv and a card has not: the difference between
            // registering someone and publishing their secret to every member
            if (key == "priv")
                return std::unexpected(std::errc::invalid_argument);
            if (key == "kind" || key == "name" || key == "intro" || key == "addr"
                || key == "pub") {
                auto text = value.string();
                if (!text)
                    return std::unexpected(std::errc::invalid_argument);
                if (key == "kind")
                    kind_text = *text;
                else if (key == "name")
                    name_text = *text;
                else if (key == "intro")
                    intro_text = *text;
                else if (key == "addr")
                    addr_text = *text;
                else
                    pub_text = *text;
            }
            // other keys are skipped by the map iterator itself
        }
        if (kind_text.empty() || name_text.empty() || pub_text.empty())
            return std::unexpected(std::errc::invalid_argument);
        if (kind_text != identity_card_kind)
            continue; // a kind this revision does not know: ignored as a whole
        record e;
        if (!is_valid_segment(name_text))
            return std::unexpected(std::errc::invalid_argument);
        if (!is_writable_string(intro_text))
            return std::unexpected(std::errc::invalid_argument);
        if (!addr_text.empty() && !is_valid_addr(addr_text))
            return std::unexpected(std::errc::invalid_argument);
        if (pub_text.size() != 64 || !inventory::is_lower_hex(pub_text)
            || !from_hex(e.pub, pub_text))
            return std::unexpected(std::errc::invalid_argument);
        if (!names_seen.emplace(name_text).second)
            return std::unexpected(std::errc::invalid_argument);
        if (!pubs_seen.emplace(pub_text).second)
            return std::unexpected(std::errc::invalid_argument);
        e.name = name_text;
        e.intro = intro_text;
        e.addr = addr_text;
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
    r.records.push_back({.name = "r2", .addr = "r2.example.net:4444", .pub = pb});
    r.records.push_back({.name = "bob", .pub = pa});
    const auto text = roster::to_danl(r);
    CHECK(text ==
          "{:kind \"id_card\" :name \"bob\" :algo \"x25519\" :pub "
          "\"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a\"}\n"
          "{:kind \"id_card\" :name \"r2\" :addr \"r2.example.net:4444\" "
          ":algo \"x25519\" :pub "
          "\"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f\"}\n");
    // and it round-trips: sorted by name, and what each record is survives it
    auto back = roster::parse(text);
    REQUIRE(back.has_value());
    REQUIRE(back->records.size() == 2);
    CHECK(back->records[0].name == "bob");
    CHECK(back->records[0].what() == roster::kind::member);
    CHECK(back->records[1].name == "r2");
    CHECK(back->records[1].what() == roster::kind::relay);
    CHECK(roster::to_danl(*back) == text);
    // an empty roster is no bytes at all
    CHECK(roster::to_danl(roster::file{}).empty());
    CHECK(roster::parse("")->records.empty());

    // the fixture tools/fexcheck/fexref.py publishes, so this canonical form is
    // one three implementations agree on rather than one this file asserts
    roster::file kat;
    kat.records.push_back({.name = "r2", .addr = "r2.example.net:4444", .pub = pb});
    kat.records.push_back({.name = "alice", .pub = pa});
    const auto kat_text = roster::to_danl(kat);
    CHECK(kat_text.size() == 263);
    CHECK(to_hex(fex::bytes{crypto::ascon::hash256(
              fex::bytes{reinterpret_cast<const u8*>(kat_text.data()), kat_text.size()})})
          == "176f30cbd19fd4b772ae0878ff5d870cfc458d284157398273b84b03b63f1fd1");
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
                            + "\" :intro \"whatever\" :name \"bob\" :kind \"id_card\"}\n");
    REQUIRE(ok.has_value());
    CHECK(ok->records.size() == 1);
    CHECK(ok->records[0].name == "bob");

    // a kind nobody here knows is skipped, and the rest of the file still reads
    auto mixed = roster::parse(line("wombat", "zed", other_pub)
                               + line("id_card", "bob", good_pub));
    REQUIRE(mixed.has_value());
    CHECK(mixed->records.size() == 1);
    CHECK(mixed->records[0].name == "bob");

    // and everything else rejects the file whole
    CHECK(!roster::parse(line("id_card", "bob", good_pub)
                         + line("id_card", "bob", other_pub)).has_value()); // dup name
    CHECK(!roster::parse(line("id_card", "bob", good_pub)
                         + line("id_card", "r2", good_pub)).has_value());   // dup pub
    CHECK(!roster::parse(line("id_card", "Bob", good_pub)).has_value());   // #8: lowercase
    CHECK(!roster::parse(line("id_card", "a/b", good_pub)).has_value());   // #8: a segment
    CHECK(!roster::parse(line("id_card", "con", good_pub)).has_value());   // #8: reserved
    CHECK(!roster::parse(line("id_card", "bob", "00ff")).has_value());     // short hex
    CHECK(!roster::parse(line("id_card", "bob", std::string(64, 'Z'))).has_value());
    CHECK(!roster::parse("{:kind \"id_card\" :name \"bob\"}\n").has_value()); // no pub
    CHECK(!roster::parse("{:name \"bob\" :pub \"" + std::string{good_pub}
                         + "\"}\n").has_value());                          // no kind
    // an identity is refused outright rather than skipped as an unknown kind: its
    // :priv must never reach a published directory (#6)
    CHECK(!roster::parse("{:kind \"id\" :name \"bob\" :pub \"" + std::string{good_pub}
                         + "\" :priv \"" + std::string{other_pub}
                         + "\"}\n").has_value());
    CHECK(!roster::parse("{:kind \"id_card\" :name \"bob\" :pub}\n").has_value());
    CHECK(!roster::parse("not a record\n").has_value());
}

SCENARIO("a card is a roster line, appended as it stands (#6)") {
    using namespace fex;
    const auto alice = generate_identity();
    const auto hub = generate_identity();
    const auto alice_card = to_danl(card_of(alice, "alice", {}, "family photos"));
    const auto hub_card = to_danl(card_of(hub, "hub", "hub.example.net:4444"));

    // registration is `cat alice.card.danl >> roster.danl`, and nothing else
    const auto text = alice_card + hub_card;
    const auto r = roster::parse(text);
    REQUIRE(r.has_value());
    REQUIRE(r->records.size() == 2);
    CHECK(r->records[0].name == "alice");
    CHECK(r->records[0].intro == "family photos");
    CHECK(r->records[0].what() == roster::kind::member);
    CHECK(r->records[1].name == "hub");
    CHECK(r->records[1].addr == "hub.example.net:4444");
    CHECK(r->records[1].what() == roster::kind::relay); // an addr is what makes one

    // and the canonical form is the same text, sorted: one writer, no translation
    CHECK(roster::to_danl(*r) == alice_card + hub_card);

    // an identity pasted where a card was meant never reaches the directory: it is
    // not a record at all (unbraced), and its :priv is refused besides
    CHECK_FALSE(roster::parse(to_dano(alice)).has_value());
    CHECK_FALSE(roster::parse("{:kind \"id_card\" :name \"alice\" :algo \"x25519\" :pub \""
                              + to_hex(fex::bytes{alice.pub}) + "\" :priv \""
                              + to_hex(fex::bytes{alice.priv}) + "\"}\n").has_value());
}

SCENARIO("find names a record") {
    using namespace fex;
    roster::file r;
    crypto::x25519::public_key p{};
    r.records.push_back({.name = "bob", .pub = p});
    CHECK(roster::find(r, "bob") != nullptr);
    CHECK(roster::find(r, "alice") == nullptr);
}

}

#endif
