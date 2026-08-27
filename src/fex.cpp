// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// fex -- the capsule client. Verb goes first: fex <command> [options].

#include <fex/commands/fetch.hpp>
#include <fex/commands/generate.hpp>
#include <fex/commands/inventory.hpp>
#include <fex/commands/publish.hpp>
#include <fex/commands/roster.hpp>

#include <flags.h>

#include <cstdio>
#include <print>
#include <string>
#include <string_view>

namespace {

using namespace fex::commands;

// Each command owns its own synopsis and option text, so the two never drift.
std::string usage() {
    std::string text = "fex -- capsule client\n\nusage:\n";
    text += generate::synopsis;
    text += publish::synopsis;
    text += inventory::synopsis;
    text += fetch::synopsis;
    text += roster::synopsis;
    text += "  fex help | version\n\ncommands:\n";
    text += generate::summary;
    text += publish::summary;
    text += inventory::summary;
    text += fetch::summary;
    text += roster::summary;
    text += "  help                    this text\n"
            "  version                 print the version\n";
    text += "\noptions:\n";
    text += generate::options;
    text += relay_options;
    return text;
}

} // namespace

int main(int argc, char** argv) {
    const flags::args args(argc, argv);
    const auto command = args.get<std::string_view>(std::size_t{0}).value_or("");

    if (command == "help") {
        std::print("{}", usage());
        return exit_ok;
    }
    if (command == "version") {
        std::println("fex {}", fex::version);
        return exit_ok;
    }
    if (command.empty()) {
        std::print(stderr, "{}", usage());
        return exit_misused;
    }

    if (command == generate::name) return generate::run(args);
    if (command == publish::name) return publish::run(args);
    if (command == inventory::name) return inventory::run(args);
    if (command == fetch::name) return fetch::run(args);
    if (command == roster::name) return roster::run(args);

    fail("unknown command '{}'", command);
    std::print(stderr, "{}", usage());
    return exit_misused;
}
