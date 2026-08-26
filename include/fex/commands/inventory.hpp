// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// fex inventory -- what the relay holds, read out (#10.2).

#pragma once

#include <string>
#include <string_view>

#include <fex/commands/common.hpp>

namespace fex::commands::inventory {

inline constexpr std::string_view name = "inventory";
inline constexpr std::string_view synopsis =
    "  fex inventory [--root <path>] [--relay <name>] [--name <name>]\n";
inline constexpr std::string_view summary =
    "  inventory               print what the relay holds: path and size\n";

// The same refresh `fetch` does, with the file read out instead of reported. The
// records are already sorted by path (#7), so this walks them in the order they
// were written and prints the two fields a member needs to decide what to fetch;
// the hashes are in the file itself, for anyone who wants them.
inline int run(const flags::args& args) {
    auto cfg = configure(args);
    if (!cfg)
        return cfg.error();
    auto req = client::requester::connect(cfg->self, cfg->relay);
    if (!req)
        return fail("cannot reach relay '{}' at {}: {}", cfg->relay_name,
                    cfg->relay.addr, message(req.error()));
    const auto state = fex::client::refresh_inventory(*req, cfg->files_dir, cfg->state_dir);
    if (!state) {
        if (state.error() == std::errc::no_message)
            return fail("nothing to show: the capsule was never published");
        return fail("cannot read the inventory: {}", message(state.error()));
    }
    std::println("seq {}, {} files", state->seq, state->inventory.entries.size());
    for (const auto& e : state->inventory.entries)
        std::println("{}  {}", e.path, e.size);
    return exit_ok;
}

} // namespace fex::commands::inventory
