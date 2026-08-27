// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// fex roster -- who is on the relay (#6, #10.2).

#pragma once

#include <string>
#include <string_view>

#include <fex/commands/common.hpp>

namespace fex::commands::roster {

inline constexpr std::string_view name = "roster";
inline constexpr std::string_view synopsis =
    "  fex roster [--root <path>] [--relay <name>] [--name <name>]\n";
inline constexpr std::string_view summary =
    "  roster                  print the relay's directory: who is on it\n";

// list gives a size and a hash; the file is fetched like anything else and
// validated whole before a word of it is printed. The fingerprint is shown
// beside each name because that is what a read of someone else's capsule is
// addressed by (#10.2), and because it is the value two people compare out of
// band before either trusts a card (#3).
inline int run(const flags::args& args) {
    auto cfg = configure(args);
    if (!cfg)
        return cfg.error();
    auto req = client::requester::connect(cfg->self, cfg->relay);
    if (!req)
        return fail("cannot reach relay '{}' at {}: {}", cfg->relay_name,
                    cfg->relay.addr, message(req.error()));
    const auto peer = client::peer_dir(cfg->peers_dir, cfg->relay_name);
    const auto got = client::refresh_roster(*req, peer);
    if (!got)
        return fail("cannot read the roster of '{}': {}", cfg->relay_name,
                    message(got.error()));
    std::println("relay {}, {} record(s){}", cfg->relay_name,
                 got->directory.records.size(),
                 got->fetched ? "" : " (already up to date)");
    for (const auto& e : got->directory.records)
        std::println("{:<6}  {}  {}", fex::roster::name_of(e.what), e.name,
                     fingerprint_hex(e.pub));
    return exit_ok;
}

} // namespace fex::commands::roster
