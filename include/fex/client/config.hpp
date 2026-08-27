// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Client layout discovery (#10.3):
//   <root>/keys/node.dano                    the node identity
//   <root>/keys/<relay>.relay.dano           the relay's card
//   <root>/self/<name>@<relay>/files/        the capsule: content only
//   <root>/self/<name>@<relay>/files/inventory.danl
//                                            the relay's inventory as last known
//   <root>/self/<name>@<relay>/state/staging/  downloads in progress
//
// A capsule is still discovered by its <name>@<relay> directory; files/ and state/
// live inside it, which is what puts a download on the same filesystem as the place
// it is renamed to.

#include <cstdlib>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>

#include <fex/fs.hpp>
#include <fex/identity.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::client {

inline constexpr std::string_view staging_name = "staging";

struct config {
    std::string root;
    identity self;
    identity_card relay;
    std::string relay_name;
    std::string capsule_name;
    std::string files_dir; // <root>/self/<name>@<relay>/files
    std::string state_dir; // <root>/self/<name>@<relay>/state
    std::string peers_dir; // <root>/peers
}; // config

// Where a download is written before it is renamed into place, and where the
// client keeps the relay's inventory. Both are spelled once, here, so a second
// capsule -- another member's, when the protocol grows one -- needs no new rule.
[[nodiscard]] inline std::string staging_dir(std::string_view state_dir) {
    return std::string{state_dir} + '/' + std::string{staging_name};
}

[[nodiscard]] inline std::string inventory_path(std::string_view files_dir) {
    return std::string{files_dir} + '/' + std::string{inventory_name};
}

// #10.3: everything read from a relay lives under the name that relay is known
// by -- one's own and, when federation arrives, the federated ones, uniformly.
[[nodiscard]] inline std::string peer_dir(std::string_view peers_dir,
                                          std::string_view relay_name) {
    return std::string{peers_dir} + '/' + std::string{relay_name};
}

[[nodiscard]] inline std::string peer_state_dir(std::string_view peer_dir) {
    return std::string{peer_dir} + "/state";
}

[[nodiscard]] inline std::string roster_path(std::string_view peer_dir) {
    return std::string{peer_dir} + '/' + std::string{roster_name};
}

namespace detail {

[[nodiscard]] inline std::vector<std::string>
names_with_suffix(const std::string& dir, std::string_view suffix) noexcept {
    std::vector<std::string> found;
    DIR* const d = ::opendir(dir.c_str());
    if (d == nullptr)
        return found;
    while (const auto* e = ::readdir(d)) {
        const std::string_view name = e->d_name;
        if (name.size() > suffix.size() && name.ends_with(suffix))
            found.emplace_back(name.substr(0, name.size() - suffix.size()));
    }
    ::closedir(d);
    return found;
}

} // namespace detail

// root: the flag, else $FEX_ROOT, else the current directory. The relay is
// picked by --relay when several cards exist; the capsule name by --name when
// self/ does not already hold exactly one <name>@<relay> folder.
[[nodiscard]] inline std::expected<config, std::errc>
load_config(std::string_view root_flag, std::string_view relay_flag,
            std::string_view name_flag) noexcept {
    config cfg;
    if (!root_flag.empty()) {
        cfg.root = root_flag;
    } else if (const char* env = std::getenv("FEX_ROOT"); env != nullptr && *env != '\0') {
        cfg.root = env;
    } else {
        cfg.root = ".";
    }
    while (cfg.root.size() > 1 && cfg.root.back() == '/')
        cfg.root.pop_back();

    auto self = read_identity((cfg.root + "/keys/node.dano").c_str());
    if (!self)
        return std::unexpected(self.error());
    cfg.self = *self;

    const auto keys_dir = cfg.root + "/keys";
    if (!relay_flag.empty()) {
        cfg.relay_name = relay_flag;
    } else {
        auto relays = detail::names_with_suffix(keys_dir, ".relay.dano");
        if (relays.size() != 1) // none, or several without --relay
            return std::unexpected(std::errc::no_such_file_or_directory);
        cfg.relay_name = std::move(relays.front());
    }
    auto card = read_identity_card(
        (keys_dir + '/' + cfg.relay_name + ".relay.dano").c_str(), true);
    if (!card)
        return std::unexpected(card.error());
    cfg.relay = std::move(*card);

    if (!name_flag.empty()) {
        cfg.capsule_name = name_flag;
    } else {
        auto capsules = detail::names_with_suffix(cfg.root + "/self",
                                                  "@" + cfg.relay_name);
        if (capsules.size() != 1)
            return std::unexpected(std::errc::no_such_file_or_directory);
        cfg.capsule_name = std::move(capsules.front());
    }
    if (!is_valid_segment(cfg.capsule_name))
        return std::unexpected(std::errc::invalid_argument);
    const auto capsule = cfg.root + "/self/" + cfg.capsule_name + '@' + cfg.relay_name;
    cfg.files_dir = capsule + "/files";
    cfg.state_dir = capsule + "/state";
    cfg.peers_dir = cfg.root + "/peers";
    return cfg;
}

} // namespace fex::client

#ifdef FEX_WITH_TESTS

TEST_SUITE("fex::client") {

SCENARIO("config discovery") {
    using namespace fex;
    char tmpl[] = "/tmp/fex-cfg-XXXXXX";
    char* tmp = ::mkdtemp(tmpl);
    REQUIRE(tmp != nullptr);
    const std::string root{tmp};

    // nothing there yet
    CHECK(!client::load_config(root, "", "").has_value());

    const auto self = generate_identity();
    const auto relay = generate_identity();
    REQUIRE(fs::ensure_dirs(root + "/keys").has_value());
    REQUIRE(write_new_file((root + "/keys/node.dano").c_str(), to_dano(self),
                           identity_mode).has_value());
    REQUIRE(write_new_file((root + "/keys/hub.relay.dano").c_str(),
                           to_dano(card_of(relay, "127.0.0.1:4444")),
                           identity_card_mode).has_value());
    REQUIRE(fs::ensure_dirs(root + "/self/mine@hub/files").has_value());

    auto cfg = client::load_config(root, "", "");
    REQUIRE(cfg.has_value());
    CHECK(cfg->relay_name == "hub");
    CHECK(cfg->capsule_name == "mine");
    CHECK(cfg->files_dir == root + "/self/mine@hub/files");
    CHECK(cfg->state_dir == root + "/self/mine@hub/state");
    CHECK(cfg->peers_dir == root + "/peers");
    CHECK(client::peer_dir(cfg->peers_dir, cfg->relay_name) == root + "/peers/hub");
    CHECK(client::roster_path(client::peer_dir(cfg->peers_dir, cfg->relay_name))
          == root + "/peers/hub/roster.danl");
    CHECK(client::staging_dir(cfg->state_dir) == root + "/self/mine@hub/state/staging");
    CHECK(client::inventory_path(cfg->files_dir)
          == root + "/self/mine@hub/files/inventory.danl");
    CHECK(cfg->relay.addr == "127.0.0.1:4444");
    CHECK(cfg->self.pub == self.pub);

    // a second relay card forces --relay
    REQUIRE(write_new_file((root + "/keys/other.relay.dano").c_str(),
                           to_dano(card_of(generate_identity(), "127.0.0.1:5555")),
                           identity_card_mode).has_value());
    CHECK(!client::load_config(root, "", "").has_value());
    auto picked = client::load_config(root, "hub", "");
    REQUIRE(picked.has_value());
    CHECK(picked->capsule_name == "mine");

    // --name overrides discovery
    auto named = client::load_config(root, "hub", "fresh");
    REQUIRE(named.has_value());
    CHECK(named->files_dir == root + "/self/fresh@hub/files");

    REQUIRE(fs::remove_tree(root).has_value());
}

}

#endif
