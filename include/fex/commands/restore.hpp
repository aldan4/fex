// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// fex restore -- bring the capsule back from the relay (#10.2).

#include <string_view>

#include <fex/commands/common.hpp>

namespace fex::commands::restore {

inline constexpr std::string_view name = "restore";
inline constexpr std::string_view synopsis =
    "  fex restore [--root <path>] [--relay <name>] [--name <name>]\n";
inline constexpr std::string_view summary =
    "  restore                 restore the capsule from the relay\n";

inline int run(const flags::args& args) {
    auto cfg = configure(args);
    if (!cfg)
        return cfg.error();
    auto req = client::requester::connect(cfg->self, cfg->relay);
    if (!req)
        return fail("cannot reach relay '{}' at {}: {}", cfg->relay_name,
                    cfg->relay.addr, message(req.error()));
    const auto restored = fex::client::restore(*req, cfg->capsule_dir, cfg->tmp_dir);
    if (!restored) {
        if (restored.error() == std::errc::no_message)
            return fail("nothing to restore: the capsule was never published");
        return fail("restore failed: {}", message(restored.error()));
    }
    std::println("restored {} from {}", cfg->capsule_dir, cfg->relay_name);
    return exit_ok;
}

} // namespace fex::commands::restore
