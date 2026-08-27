// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Path rules from doc/fex_spec.md #8. The spec asks for a single validator used in two
// places -- when a capsule is published and before an inventory is laid out on disk --
// so everything that has to agree on what a name may look like comes through here.
// Node names are single segments and follow the same rules (#3).

#include <cstddef>
#include <string_view>

#if defined(FEX_WITH_TESTS) || defined(FEX_WITH_BENCHS)
#include <doctest/doctest.h>
#endif

namespace fex {

inline constexpr std::size_t max_segment_bytes = 255;
inline constexpr std::size_t max_path_bytes = 1024;

// The client keeps the relay's inventory at the root of the capsule under this name
// (#10.3). It is reserved rather than merely skipped: an inventory cannot hold a
// record of itself -- that record would carry the hash of a file containing it -- so
// a relay refuses one naming it, and no capsule can overwrite a client's own copy.
inline constexpr std::string_view inventory_name = "inventory.danl";

// And the relay's published directory, which the client keeps beside the
// capsules it reads (#6, #10.3). Reserved for the same reason: these two names
// belong to the service layer, and capsule content cannot claim them (#8).
inline constexpr std::string_view roster_name = "roster.danl";

namespace detail {

// con, nul, prn, aux, com1-com9, lpt1-lpt9 are reserved on Windows with any extension,
// so the check runs on the stem -- everything before the first dot.
[[nodiscard]] inline bool is_reserved_stem(std::string_view stem) noexcept {
    if (stem == "con" || stem == "nul" || stem == "prn" || stem == "aux") return true;
    if (stem.size() != 4) return false;
    if (!stem.starts_with("com") && !stem.starts_with("lpt")) return false;
    return stem[3] >= '1' && stem[3] <= '9';
}

} // namespace detail

// [a-z0-9._-]+, at most 255 bytes, not made of dots alone (which rules out "." and
// ".."), not starting with "-", not a reserved Windows name.
[[nodiscard]] inline bool is_valid_segment(std::string_view s) noexcept {
    if (s.empty() || s.size() > max_segment_bytes) return false;
    if (s.front() == '-') return false;
    bool dots_only = true;
    for (const char c : s) {
        const bool allowed = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                          || c == '.' || c == '_' || c == '-';
        if (!allowed) return false;
        if (c != '.') dots_only = false;
    }
    if (dots_only) return false;
    return !detail::is_reserved_stem(s.substr(0, s.find('.')));
}

// Segments joined by "/", at most 1024 bytes. A leading, trailing or doubled "/" leaves
// an empty segment behind, which is_valid_segment already refuses.
[[nodiscard]] inline bool is_valid_path(std::string_view p) noexcept {
    if (p.empty() || p.size() > max_path_bytes) return false;
    if (p == inventory_name || p == roster_name) return false;
    std::size_t at = 0;
    for (;;) {
        const auto slash = p.find('/', at);
        const auto segment = p.substr(at, slash == std::string_view::npos ? slash : slash - at);
        if (!is_valid_segment(segment)) return false;
        if (slash == std::string_view::npos) return true;
        at = slash + 1;
    }
}

} // namespace fex

#ifdef FEX_WITH_TESTS

#include <string>

TEST_CASE("segment rules follow spec section 8") {
    using fex::is_valid_segment;

    REQUIRE(is_valid_segment("a"));
    REQUIRE(is_valid_segment("docs"));
    REQUIRE(is_valid_segment("a.txt"));
    REQUIRE(is_valid_segment("_x-1.tar.gz"));
    REQUIRE(is_valid_segment(std::string(255, 'a')));

    REQUIRE_FALSE(is_valid_segment(""));
    REQUIRE_FALSE(is_valid_segment(std::string(256, 'a')));
    REQUIRE_FALSE(is_valid_segment("Docs"));      // uppercase
    REQUIRE_FALSE(is_valid_segment("a b"));       // space
    REQUIRE_FALSE(is_valid_segment("a/b"));       // separator is not part of a segment
    REQUIRE_FALSE(is_valid_segment("-a"));        // leading dash
    REQUIRE_FALSE(is_valid_segment("."));
    REQUIRE_FALSE(is_valid_segment(".."));
    REQUIRE_FALSE(is_valid_segment("..."));       // dots alone
    REQUIRE(is_valid_segment(".a"));              // a dot is fine elsewhere

    // Windows reserved names, bare and with any extension.
    for (const auto* name : {"con", "nul", "prn", "aux", "com1", "com9", "lpt1", "lpt9"}) {
        REQUIRE_FALSE(is_valid_segment(name));
        REQUIRE_FALSE(is_valid_segment(std::string(name) + ".txt"));
    }
    REQUIRE(is_valid_segment("com0"));
    REQUIRE(is_valid_segment("console"));
}

TEST_CASE("path rules follow spec section 8") {
    using fex::is_valid_path;

    REQUIRE(is_valid_path("a.txt"));
    REQUIRE(is_valid_path("docs/a.txt"));
    REQUIRE(is_valid_path("a/b/c/d.bin"));

    REQUIRE_FALSE(is_valid_path(""));
    REQUIRE_FALSE(is_valid_path("/a"));
    REQUIRE_FALSE(is_valid_path("a/"));
    REQUIRE_FALSE(is_valid_path("a//b"));
    REQUIRE_FALSE(is_valid_path("a/../b"));
    REQUIRE_FALSE(is_valid_path("a/con/b"));
    // The client's own copy of the inventory, reserved at the root of the capsule
    // and nowhere else.
    REQUIRE_FALSE(is_valid_path("inventory.danl"));
    REQUIRE_FALSE(is_valid_path("roster.danl"));
    REQUIRE(is_valid_path("docs/inventory.danl"));
    REQUIRE(is_valid_path("docs/roster.danl"));
    // Four maximal segments fit in 1023 bytes; a fifth pushes the path over the limit.
    const std::string seg(255, 'a');
    REQUIRE(is_valid_path(seg + "/" + seg + "/" + seg + "/" + seg));
    REQUIRE_FALSE(is_valid_path(seg + "/" + seg + "/" + seg + "/" + seg + "/" + seg));
}

#endif // FEX_WITH_TESTS
