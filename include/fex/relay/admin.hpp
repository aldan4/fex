// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Registry management (#3): who is on this relay. A registry line is a card
// (#3, #6), so including someone is their card added to roster.danl and
// excluding them is that line taken out again -- and both are the whole file
// written at once, so a relay reading it mid-change reads one state or the
// other.
//
// The uniqueness rules of #3 live here because this is where the whole file is
// in hand: no two records may carry one name or one key.

#include <expected>
#include <string>
#include <string_view>
#include <system_error>

#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/roster.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::relay::admin {

inline constexpr ::mode_t roster_mode = 0644;

[[nodiscard]] inline std::string roster_path(std::string_view root) {
    return std::string{root} + "/roster.danl";
}

namespace detail {

// A roster carrying records this build cannot represent is left alone rather
// than rewritten: #6 lets a later revision publish kinds this one has never
// heard of, and rewriting the file canonically would drop them silently. The
// count of what danl holds against the count of what the roster reader kept is
// what tells the two apart.
[[nodiscard]] inline std::expected<std::size_t, std::errc>
record_count(std::string_view text) noexcept {
    auto reader = ::danl::reader::from_text(text);
    if (!reader)
        return std::unexpected(std::errc::invalid_argument);
    std::size_t n = 0;
    auto records = reader->records();
    while (records.has_next()) {
        if (!records.next())
            return std::unexpected(std::errc::invalid_argument);
        ++n;
    }
    return n;
}

[[nodiscard]] inline std::expected<roster::file, std::errc>
load(std::string_view root) noexcept {
    const auto path = roster_path(root);
    const auto st = fs::stat_of(path.c_str());
    if (st.kind == fs::entry_kind::missing)
        return roster::file{}; // a relay nobody is on yet
    auto data = fs::read_file(path.c_str());
    if (!data)
        return std::unexpected(data.error());
    const std::string_view text{reinterpret_cast<const char*>(data->data()), data->size()};
    auto parsed = roster::parse(text);
    if (!parsed)
        return std::unexpected(parsed.error());
    const auto held = record_count(text);
    if (!held)
        return std::unexpected(held.error());
    if (*held != parsed->records.size())
        return std::unexpected(std::errc::not_supported);
    return *parsed;
}

[[nodiscard]] inline std::expected<void, std::errc>
store(std::string_view root, roster::file r) noexcept {
    const auto text = roster::to_danl(std::move(r));
    return fs::write_file_atomic(
        roster_path(root),
        fex::bytes{reinterpret_cast<const u8*>(text.data()), text.size()}, roster_mode);
}

} // namespace detail

// The card at `card_path`, added to the registry under the name it carries.
// `file_exists` means that name is taken, `address_in_use` that the key is --
// two names for one node would be two capsules for one member.
[[nodiscard]] inline std::expected<identity_card, std::errc>
include(std::string_view root, const char* card_path) noexcept {
    auto card = read_identity_card(card_path);
    if (!card)
        return std::unexpected(card.error());
    auto reg = detail::load(root);
    if (!reg)
        return std::unexpected(reg.error());
    for (const auto& e : reg->records) {
        if (e.name == card->name)
            return std::unexpected(std::errc::file_exists);
        if (e.pub == card->pub)
            return std::unexpected(std::errc::address_in_use);
    }
    reg->records.push_back({.name = card->name, .intro = card->intro,
                            .addr = card->addr, .pub = card->pub});
    if (auto written = detail::store(root, std::move(*reg)); !written)
        return std::unexpected(written.error());
    return *card;
}

// And out again. The capsule stays on disk: what a member published is theirs,
// and this command is about the registry, not about deleting anybody's files.
[[nodiscard]] inline std::expected<void, std::errc>
exclude(std::string_view root, std::string_view name) noexcept {
    auto reg = detail::load(root);
    if (!reg)
        return std::unexpected(reg.error());
    const auto before = reg->records.size();
    std::erase_if(reg->records, [name](const roster::record& e) { return e.name == name; });
    if (reg->records.size() == before)
        return std::unexpected(std::errc::no_such_file_or_directory);
    return detail::store(root, std::move(*reg));
}

[[nodiscard]] inline std::expected<roster::file, std::errc>
list(std::string_view root) noexcept {
    return detail::load(root);
}

} // namespace fex::relay::admin

// ---- Tests -----------------------------------------------------------------

#ifdef FEX_WITH_TESTS

#include <cstdlib>
#include <unistd.h>

TEST_SUITE("fex::relay::admin") {

SCENARIO("include and exclude are the registry, and the card is the line") {
    using namespace fex;
    char tmpl[] = "/tmp/fex-admin-XXXXXX";
    char* tmp = ::mkdtemp(tmpl);
    REQUIRE(tmp != nullptr);
    const std::string root{tmp};

    const auto alice = generate_identity();
    const auto bob = generate_identity();
    const auto alice_card = to_danl(card_of(alice, "alice", {}, "family photos"));
    const auto bob_card = to_danl(card_of(bob, "bob"));
    const auto write = [&](const std::string& name, const std::string& text) {
        const auto path = root + "/" + name;
        REQUIRE(fs::write_file_atomic(
                    path, fex::bytes{reinterpret_cast<const u8*>(text.data()), text.size()})
                    .has_value());
        return path;
    };
    const auto alice_path = write("alice.card.danl", alice_card);
    const auto bob_path = write("bob.card.danl", bob_card);

    // a relay nobody is on yet takes the first member
    auto first = relay::admin::include(root, alice_path.c_str());
    REQUIRE(first.has_value());
    CHECK(first->name == "alice");

    // and the line it wrote is the card, unchanged
    const auto text = fs::read_file(relay::admin::roster_path(root).c_str());
    REQUIRE(text.has_value());
    CHECK(std::string_view{reinterpret_cast<const char*>(text->data()), text->size()}
          == alice_card);

    REQUIRE(relay::admin::include(root, bob_path.c_str()).has_value());
    auto reg = relay::admin::list(root);
    REQUIRE(reg.has_value());
    REQUIRE(reg->records.size() == 2);
    CHECK(reg->records[0].name == "alice");
    CHECK(reg->records[0].intro == "family photos");
    CHECK(reg->records[1].name == "bob");

    // the same name twice, and the same key under another name, are both #3's
    // uniqueness rule and are refused before anything is written
    CHECK(relay::admin::include(root, alice_path.c_str()).error() == std::errc::file_exists);
    const auto twice = write("again.card.danl", to_danl(card_of(alice, "alicia")));
    CHECK(relay::admin::include(root, twice.c_str()).error() == std::errc::address_in_use);
    CHECK(relay::admin::list(root)->records.size() == 2);

    // an identity is not a card, so it cannot be included by renaming it
    const auto secret = write("secret.danl", to_dano(alice));
    CHECK_FALSE(relay::admin::include(root, secret.c_str()).has_value());

    // out again, by name
    REQUIRE(relay::admin::exclude(root, "alice").has_value());
    reg = relay::admin::list(root);
    REQUIRE(reg.has_value());
    REQUIRE(reg->records.size() == 1);
    CHECK(reg->records[0].name == "bob");
    CHECK(relay::admin::exclude(root, "alice").error()
          == std::errc::no_such_file_or_directory);

    // a roster carrying a record this build does not know is left alone rather
    // than rewritten without it (#6)
    const auto kept = std::string{"{:kind \"wombat\" :name \"zed\" :pub \""}
                    + to_hex(fex::bytes{alice.pub}) + "\"}\n";
    write("roster.danl", kept + to_danl(card_of(bob, "bob")));
    CHECK(relay::admin::include(root, alice_path.c_str()).error() == std::errc::not_supported);
    CHECK(relay::admin::exclude(root, "bob").error() == std::errc::not_supported);

    REQUIRE(fs::remove_tree(root).has_value());
}

} // TEST_SUITE

#endif
