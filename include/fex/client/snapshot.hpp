// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// #10.1 step 1: fix the inventory of a capsule folder in one pass. A symlink,
// a special file, or an unrepresentable name refuses the whole publication.

#include <expected>
#include <string>
#include <string_view>

#include <fex/crypto.hpp>
#include <fex/fs.hpp>
#include <fex/inventory.hpp>
#include <fex/path.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::client {

// `offending`, when given, receives the path that refused the publication
[[nodiscard]] inline std::expected<inventory::file, std::errc>
snapshot(const std::string& capsule_dir, std::string* offending = nullptr) noexcept {
    inventory::file inv;
    std::errc verdict{};
    const auto walked = fs::walk(capsule_dir.c_str(),
        [&](std::string_view rel, const fs::info& st) -> std::expected<void, std::errc> {
            if (st.kind == fs::entry_kind::dir) {
                if (!is_valid_path(rel)) {
                    if (offending != nullptr)
                        *offending = rel;
                    verdict = std::errc::invalid_argument;
                    return std::unexpected(verdict);
                }
                return {};
            }
            if (st.kind != fs::entry_kind::file || !is_valid_path(rel)) {
                if (offending != nullptr)
                    *offending = rel;
                verdict = std::errc::invalid_argument;
                return std::unexpected(verdict);
            }
            // whole-file hashing in memory: a stage-1 simplification that also
            // bounds every later re-read check to the same code path
            auto data = fs::read_file((capsule_dir + '/' + std::string{rel}).c_str());
            if (!data) {
                if (offending != nullptr)
                    *offending = rel;
                verdict = data.error();
                return std::unexpected(verdict);
            }
            inventory::entry e;
            e.hash = crypto::ascon::hash256(fex::bytes{*data});
            e.path = rel;
            e.size = data->size();
            inv.entries.push_back(std::move(e));
            return {};
        });
    if (!walked)
        return std::unexpected(verdict != std::errc{} ? verdict : walked.error());
    return inv;
}

} // namespace fex::client

#ifdef FEX_WITH_TESTS

#include <cstdlib>

TEST_SUITE("fex::client") {

SCENARIO("snapshot: hashes files, refuses symlinks and bad names") {
    using namespace fex;
    char tmpl[] = "/tmp/fex-snap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir{root};

    const std::array<fex::u8, 4> data{'a', 'b', 'c', 'd'};
    REQUIRE(fs::ensure_dirs(dir + "/docs").has_value());
    REQUIRE(fs::write_file_atomic(dir + "/docs/a.txt", fex::bytes{data}).has_value());
    REQUIRE(fs::write_file_atomic(dir + "/empty.bin", {}).has_value());

    auto inv = client::snapshot(dir);
    REQUIRE(inv.has_value());
    REQUIRE(inv->entries.size() == 2);
    const auto text = inventory::to_danl(*inv);
    CHECK(text.find("docs/a.txt") != std::string::npos);
    CHECK(text.find(":size 4") != std::string::npos);
    CHECK(text.find(":size 0") != std::string::npos);

    // a symlink refuses the whole publication, and names the culprit
    REQUIRE(::symlink("docs/a.txt", (dir + "/link").c_str()) == 0);
    std::string offending;
    auto refused = client::snapshot(dir, &offending);
    REQUIRE(!refused.has_value());
    CHECK(refused.error() == std::errc::invalid_argument);
    CHECK(offending == "link");
    REQUIRE(::unlink((dir + "/link").c_str()) == 0);

    // an uppercase name refuses it too (#8)
    REQUIRE(fs::write_file_atomic(dir + "/BAD.txt", fex::bytes{data}).has_value());
    refused = client::snapshot(dir, &offending);
    REQUIRE(!refused.has_value());
    CHECK(offending == "BAD.txt");

    REQUIRE(fs::remove_tree(dir).has_value());
}

}

#endif
