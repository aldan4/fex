// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// fex fetch <path> -- read one file of the capsule back from the relay (#10.2).
//
// The capsule's own inventory is fetched by name like anything else. It is the one
// path addressed by the head rather than by a record -- an inventory cannot carry a
// record of itself -- which is why it is reserved (#8) and why fetching it is the
// refresh every command does anyway, reported rather than repeated.

#pragma once

#include <string>
#include <string_view>

#include <fex/commands/common.hpp>

namespace fex::commands::fetch {

inline constexpr std::string_view name = "fetch";
inline constexpr std::string_view synopsis =
    "  fex fetch <path> [--root <path>] [--relay <name>] [--name <name>]\n";
inline constexpr std::string_view summary =
    "  fetch <path>            fetch one file of the capsule from the relay\n";

inline int run(const flags::args& args) {
    const auto path = args.get<std::string>(std::size_t{1});
    if (!path)
        return fail("fetch needs a path inside the capsule: fex fetch <path>");
    const bool want_inventory = *path == inventory_name;
    if (!want_inventory && !is_valid_path(*path))
        return fail("'{}' is not a capsule path: lowercase [a-z0-9._-] segments joined "
                    "by '/', at most 1024 bytes",
                    *path);
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
            return fail("nothing to fetch: the capsule was never published");
        return fail("fetch failed: {}", message(state.error()));
    }
    if (want_inventory) {
        // refresh_inventory has already done it: it is the head's hash that names the
        // inventory, so there is nothing here to look up and nothing to fetch twice
        if (state->fetched)
            std::println("fetched {} ({} bytes) into {}", *path, state->inv_size,
                         cfg->files_dir);
        else
            std::println("{} is already up to date", *path);
        return exit_ok;
    }
    const auto& entries = state->inventory.entries;
    const auto found = std::ranges::find(entries, *path, &fex::inventory::entry::path);
    if (found == entries.end())
        return fail("'{}' is not in the capsule as of seq {}", *path, state->seq);
    const auto got = fex::client::fetch(*req, *found, cfg->files_dir, cfg->state_dir);
    if (!got)
        return fail("cannot fetch {}: {}", *path, message(got.error()));
    if (*got)
        std::println("fetched {} ({} bytes) into {}", *path, found->size, cfg->files_dir);
    else
        std::println("{} is already up to date", *path);
    return exit_ok;
}

} // namespace fex::commands::fetch
