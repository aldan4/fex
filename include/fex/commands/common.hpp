// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Shared plumbing for the client's commands: how a failure is reported and
// how the client root (#10.3) is resolved from the command line.

#include <expected>
#include <format>
#include <print>
#include <string>
#include <string_view>
#include <system_error>

#include <flags.h>

#include <fex/client.hpp>

namespace fex::commands {

// every command returns a process exit code: 0 done, 1 failed, 2 misused
inline constexpr int exit_ok = 0;
inline constexpr int exit_failed = 1;
inline constexpr int exit_misused = 2;

template <typename... Args>
int fail(std::format_string<Args...> format, Args&&... args) {
    std::print(stderr, "fex: ");
    std::println(stderr, format, std::forward<Args>(args)...);
    return exit_failed;
}

inline std::string message(std::errc code) {
    return std::make_error_code(code).message();
}

// --root/--relay/--name, with the discovery rules of #10.3 behind them
inline std::expected<client::config, int> configure(const flags::args& args) {
    const auto root = args.get<std::string>("root", "r").value_or(std::string{});
    const auto relay = args.get<std::string>("relay").value_or(std::string{});
    const auto name = args.get<std::string>("name").value_or(std::string{});
    auto cfg = client::load_config(root, relay, name);
    if (!cfg)
        return std::unexpected(fail(
            "cannot read the client root '{}': {}\n"
            "expected keys/node.dano and exactly one keys/<relay>.relay.danl (or "
            "--relay), and one self/<name>@<relay>/ capsule (or --name)",
            root.empty() ? "." : root, message(cfg.error())));
    return *cfg;
}

// the option block every command that talks to a relay shares
inline constexpr std::string_view relay_options =
    "  -r, --root <path>       client root (default: $FEX_ROOT, then current);\n"
    "                          holds keys/ and self/\n"
    "      --relay <name>      relay to use when keys/ has several *.relay.danl\n"
    "      --name <name>       capsule name when self/ does not pin one\n";

} // namespace fex::commands
