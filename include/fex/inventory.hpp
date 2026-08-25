// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Inventory (#7): one danl record per file. The writer emits the canonical
// form; the reader is strict but accepts non-canonical formatting -- the
// inventory hash is always taken over the exact bytes, so canonicalization
// is purely the writer's duty.

#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include <dano/dano.hpp>

#include <fex/crypto.hpp>
#include <fex/identity.hpp>
#include <fex/path.hpp>
#include <fex/types.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::inventory {

struct entry {
    hash256 hash;
    std::string path;
    u64 size;

    bool operator==(const entry&) const = default;
}; // entry

struct file {
    std::vector<entry> entries;

    bool operator==(const file&) const = default;
}; // file

[[nodiscard]] inline bool is_lower_hex(std::string_view s) noexcept {
    for (const char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    return true;
}

// canonical form: key order :hash :path :size, single spaces, lowercase hex,
// entries sorted by path bytewise, '\n' after every line including the last
[[nodiscard]] inline std::string to_danl(file inv) {
    std::ranges::sort(inv.entries, [](const entry& a, const entry& b) {
        return a.path < b.path; // lowercase ascii, so char compare is bytewise
    });
    std::string out;
    for (const auto& e : inv.entries) {
        out += "{:hash \"";
        out += to_hex(fex::bytes{e.hash});
        out += "\" :path \"";
        out += e.path;
        out += "\" :size ";
        out += std::to_string(e.size);
        out += "}\n";
    }
    return out;
}

// strict reader: the whole inventory is rejected on a syntax error, a missing
// required key, a duplicate path, invalid hex, or an invalid path (#8)
[[nodiscard]] inline std::expected<file, std::errc> parse(std::string_view danl) noexcept {
    auto reader = ::danl::reader::from_text(danl);
    if (!reader)
        return std::unexpected(std::errc::invalid_argument);
    file inv;
    hash_set<std::string> seen;
    auto records = reader->records();
    while (records.has_next()) {
        auto record = records.next();
        if (!record)
            return std::unexpected(std::errc::invalid_argument);
        auto map = record->map();
        if (!map)
            return std::unexpected(std::errc::invalid_argument);
        std::string_view hash_text, path_text;
        bool has_size = false;
        u64 size = 0;
        while (map->has_next()) {
            auto pair = map->next();
            if (!pair)
                return std::unexpected(std::errc::invalid_argument);
            auto& [key, value] = *pair;
            if (key == "hash") {
                auto text = value.string();
                if (!text)
                    return std::unexpected(std::errc::invalid_argument);
                hash_text = *text;
            } else if (key == "path") {
                auto text = value.string();
                if (!text)
                    return std::unexpected(std::errc::invalid_argument);
                path_text = *text;
            } else if (key == "size") {
                auto n = value.u64(); // negatives and non-integers fail here
                if (!n)
                    return std::unexpected(std::errc::invalid_argument);
                size = *n;
                has_size = true;
            }
            // unknown keys are skipped by the map iterator itself
        }
        entry e;
        if (hash_text.size() != 64 || !is_lower_hex(hash_text)
            || !from_hex(e.hash, hash_text))
            return std::unexpected(std::errc::invalid_argument);
        if (!has_size || path_text.empty() || !is_valid_path(path_text))
            return std::unexpected(std::errc::invalid_argument);
        if (!seen.emplace(path_text).second) // duplicate path
            return std::unexpected(std::errc::invalid_argument);
        e.path = path_text;
        e.size = size;
        inv.entries.push_back(std::move(e));
    }
    return inv;
}

[[nodiscard]] inline u64 total_size(const file& inv) noexcept {
    u64 sum = 0;
    for (const auto& e : inv.entries)
        sum += e.size;
    return sum;
}

} // namespace fex::inventory

#ifdef FEX_WITH_TESTS

TEST_SUITE("fex::inventory") {

namespace fex_inventory_test {

inline fex::hash256 hash_of(char fill) {
    fex::hash256 h;
    h.fill(static_cast<fex::u8>(fill));
    return h;
}

} // namespace fex_inventory_test

SCENARIO("canonical output") {
    using namespace fex;
    using fex_inventory_test::hash_of;
    inventory::file inv;
    inv.entries.push_back({hash_of(0xab), "docs/z.txt", 10});
    inv.entries.push_back({hash_of(0x01), "a.txt", 0});
    const auto text = inventory::to_danl(inv);
    const std::string expected =
        "{:hash \"0101010101010101010101010101010101010101010101010101010101010101\""
        " :path \"a.txt\" :size 0}\n"
        "{:hash \"abababababababababababababababababababababababababababababababab\""
        " :path \"docs/z.txt\" :size 10}\n";
    CHECK(text == expected);
    // empty inventory maps to empty text
    CHECK(inventory::to_danl({}) == "");
    const auto empty = inventory::parse("");
    REQUIRE(empty.has_value());
    CHECK(empty->entries.empty());
}

SCENARIO("bytewise sort order") {
    using namespace fex;
    using fex_inventory_test::hash_of;
    inventory::file inv;
    inv.entries.push_back({hash_of(1), "a-b", 1});
    inv.entries.push_back({hash_of(2), "a/b", 1});
    inv.entries.push_back({hash_of(3), "a.b", 1});
    const auto text = inventory::to_danl(inv);
    // '.' (0x2e) < '-' (0x2d)? no: '-' 0x2d < '.' 0x2e < '/' 0x2f
    const auto p1 = text.find("a-b");
    const auto p2 = text.find("a.b");
    const auto p3 = text.find("a/b");
    CHECK(p1 < p2);
    CHECK(p2 < p3);
}

SCENARIO("to_danl then parse is identity") {
    using namespace fex;
    using fex_inventory_test::hash_of;
    inventory::file inv;
    inv.entries.push_back({hash_of(0x2c), "a.txt", 42});
    inv.entries.push_back({hash_of(0x9f), "docs/b.bin", 1024 * 1024});
    const auto text = inventory::to_danl(inv);
    const auto back = inventory::parse(text);
    REQUIRE(back.has_value());
    CHECK(*back == inv);
    CHECK(inventory::total_size(*back) == 42 + 1024 * 1024);
}

SCENARIO("non-canonical but well-formed input is accepted") {
    using namespace fex;
    // reordered keys, extra spaces, unknown key, comment line
    const auto parsed = inventory::parse(
        "-- comment\n"
        "{:size 5  :path \"b.txt\" :note \"x\" "
        ":hash \"1111111111111111111111111111111111111111111111111111111111111111\"}\n");
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->entries.size() == 1);
    CHECK(parsed->entries[0].path == "b.txt");
    CHECK(parsed->entries[0].size == 5);
}

SCENARIO("rejection matrix") {
    using namespace fex;
    const std::string good_hash =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const auto line = [&](std::string_view hash, std::string_view path,
                          std::string_view size) {
        std::string s = "{:hash \"";
        s += hash;
        s += "\" :path \"";
        s += path;
        s += "\" :size ";
        s += size;
        s += "}\n";
        return s;
    };
    // syntax error
    CHECK(!inventory::parse("{:hash \"zz\"").has_value());
    // non-map record
    CHECK(!inventory::parse("42\n").has_value());
    // missing keys
    CHECK(!inventory::parse("{:path \"a\" :size 1}\n").has_value());
    CHECK(!inventory::parse("{:hash \"" + good_hash + "\" :size 1}\n").has_value());
    CHECK(!inventory::parse("{:hash \"" + good_hash + "\" :path \"a\"}\n").has_value());
    // duplicate path
    CHECK(!inventory::parse(line(good_hash, "a.txt", "1")
                          + line(good_hash, "a.txt", "2")).has_value());
    // negative size
    CHECK(!inventory::parse(line(good_hash, "a.txt", "-1")).has_value());
    // invalid hex: wrong length, uppercase, non-hex
    CHECK(!inventory::parse(line(good_hash.substr(0, 63), "a.txt", "1")).has_value());
    CHECK(!inventory::parse(line(
        "222222222222222222222222222222222222222222222222222222222222222F",
        "a.txt", "1")).has_value());
    CHECK(!inventory::parse(line(
        "22222222222222222222222222222222222222222222222222222222222222gg",
        "a.txt", "1")).has_value());
    // invalid path (#8)
    CHECK(!inventory::parse(line(good_hash, "A.txt", "1")).has_value());
    CHECK(!inventory::parse(line(good_hash, "a//b", "1")).has_value());
    CHECK(!inventory::parse(line(good_hash, "../a", "1")).has_value());
    CHECK(!inventory::parse(line(good_hash, "con", "1")).has_value());
    // good line still parses (sanity of the harness)
    CHECK(inventory::parse(line(good_hash, "a.txt", "1")).has_value());
}

}

#endif
