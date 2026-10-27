// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// fex publish -- send the capsule to the relay (#10.1).

#include <string>
#include <string_view>

#include <fex/commands/common.hpp>

namespace fex::commands::publish {

inline constexpr std::string_view name = "publish";
inline constexpr std::string_view synopsis =
    "  fex publish [--root <path>] [--relay <name>] [--name <name>]\n";
inline constexpr std::string_view summary =
    "  publish                 publish the capsule to the relay\n";

inline int run(const flags::args& args) {
    auto cfg = configure(args);
    if (!cfg)
        return cfg.error();
    if (const auto made = fs::ensure_dirs(cfg->files_dir); !made)
        return fail("cannot create {}: {}", cfg->files_dir, message(made.error()));
    auto req = client::requester::connect(cfg->self, cfg->relay);
    if (!req)
        return fail("cannot reach relay '{}' at {}: {}", cfg->relay_name,
                    cfg->relay.addr, message(req.error()));
    std::string offending;
    const auto report = fex::client::publish(
        *req, cfg->files_dir, &offending, [](const client::uploaded& u) {
            std::println("uploaded {} ({} bytes, {})", u.path, u.size,
                         rate(u.size, u.elapsed_ns));
        });

    if (!report) {
        if (report.error() == client::publish_conflict)
            return fail("publish refused: the capsule moved on '{}' while this was "
                        "uploading (another device published first); fetch what it "
                        "sent, then publish again", cfg->relay_name);
        if (!offending.empty())
            return fail("publication refused by '{}': {}", offending,
                        message(report.error()));
        return fail("publish failed: {}", message(report.error()));
    }
    if (report->unchanged)
        std::println("{} is already published as seq {}", cfg->files_dir, report->seq);
    else
        std::println("published {} to {} as seq {}", cfg->files_dir,
                     cfg->relay_name, report->seq);
    return exit_ok;
}

} // namespace fex::commands::publish
