// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// fex generate <name> -- create an identity and its card (#3).

#include <string>
#include <string_view>

#include <unistd.h>

#include <fex/commands/common.hpp>

namespace fex::commands::generate {

inline constexpr std::string_view name = "generate";
inline constexpr std::string_view synopsis =
    "  fex generate <name> [--dir <path>] [--addr <host:port>] [--intro <text>]\n";
inline constexpr std::string_view summary =
    "  generate <name>         create an x25519 identity <name>.dano and its\n"
    "                          card <name>.card.dano\n";
inline constexpr std::string_view options =
    "  -d, --dir <path>        directory to write into (default: current)\n"
    "  -a, --addr <host:port>  relay address to record in the card, which makes\n"
    "                          it a relay's card\n"
    "  -i, --intro <text>      public self-description to record in the card;\n"
    "                          fex never reads it, people do\n";

namespace detail {

inline std::string join(std::string_view dir, std::string_view file) {
    if (dir.empty() || dir == ".") return std::string{file};
    std::string path{dir};
    while (path.size() > 1 && path.back() == '/') path.pop_back();
    path += '/';
    path += file;
    return path;
}

// Write the identity and its card. Both files are new or nothing is: if the card
// cannot be written, the identity it belongs to is taken back out again, so that a
// re-run starts from a clean directory rather than tripping over a half-made pair.
inline int write_identity_pair(std::string_view node, std::string_view dir,
                               std::string_view addr, std::string_view intro) {
    if (!is_valid_segment(node))
        return fail("'{}' is not a usable node name: lowercase [a-z0-9._-], at most 255 "
                    "bytes, not starting with '-', not a reserved windows name",
                    node);
    if (!addr.empty() && !is_valid_addr(addr))
        return fail("'{}' is not a usable relay address: expected <host>:<port>", addr);
    // dano strings carry no escapes, so a quote or a control character would
    // produce a card that no longer parses
    if (!is_writable_string(intro))
        return fail("--intro may not contain quotes or control characters");

    const auto identity_path = join(dir, std::string{node} + ".dano");
    const auto card_path = join(dir, std::string{node} + ".card.dano");

    const auto id = generate_identity();
    const auto card = card_of(id, addr, intro);

    if (const auto written = write_new_file(identity_path.c_str(), to_dano(id),
                                            identity_mode);
        !written)
        return fail("cannot write {}: {}", identity_path, message(written.error()));

    if (const auto written = write_new_file(card_path.c_str(), to_dano(card),
                                            identity_card_mode);
        !written) {
        ::unlink(identity_path.c_str());
        return fail("cannot write {}: {}", card_path, message(written.error()));
    }

    std::println("{}  identity, 0600 -- keep it on this node and nowhere else",
                 identity_path);
    std::println("{}  {} card -- hand it over on a channel that preserves integrity",
                 card_path, addr.empty() ? "member" : "relay");
    std::println("fingerprint {} -- compare it over an independent channel",
                 fingerprint_hex(id.pub));
    return exit_ok;
}

} // namespace detail

inline int run(const flags::args& args) {
    const auto node = args.get<std::string>(std::size_t{1});
    if (!node)
        return fail("generate needs a node name: fex generate <name>");
    const auto dir = args.get<std::string>("dir", "d").value_or(std::string{});
    const auto addr = args.get<std::string>("addr", "a").value_or(std::string{});
    const auto intro = args.get<std::string>("intro", "i").value_or(std::string{});
    if (args.get<bool>("addr", "a").has_value() && addr.empty())
        return fail("--addr needs a <host>:<port>");
    if (args.get<bool>("dir", "d").has_value() && dir.empty())
        return fail("--dir needs a path");
    if (args.get<bool>("intro", "i").has_value() && intro.empty())
        return fail("--intro needs a text");
    return detail::write_identity_pair(*node, dir, addr, intro);
}

} // namespace fex::commands::generate
