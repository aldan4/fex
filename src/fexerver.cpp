// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// fexerver -- the capsule relay: serving it, and saying who is on it.

#include <fex/relay.hpp>
#include <fex/relay/admin.hpp>

#include <flags.h>

#include <csignal>
#include <cstdio>
#include <print>
#include <string>
#include <string_view>
#include <system_error>

namespace {

constexpr std::string_view usage =
    "fexerver -- capsule relay\n"
    "\n"
    "usage:\n"
    "  fexerver serve [--root <path>] [--key <path>] [--addr <ip:port>]\n"
    "                 [--window <seconds>]\n"
    "  fexerver include <card.danl> [--root <path>]\n"
    "  fexerver exclude <name> [--root <path>]\n"
    "  fexerver roster [--root <path>]\n"
    "  fexerver help | version\n"
    "\n"
    "commands:\n"
    "  serve                 serve the relay until stopped\n"
    "  include <card.danl>   register the member whose card that is, under the\n"
    "                        name the card carries\n"
    "  exclude <name>        take that member out of the registry; the capsule\n"
    "                        they published stays on disk\n"
    "  roster                who is registered\n"
    "  help                  this text\n"
    "  version               print the version\n"
    "\n"
    "options:\n"
    "  -r, --root <path>     relay root: roster.danl, objects/ and capsules/\n"
    "                        live here. roster.danl is the registry and the\n"
    "                        published directory at once: one card per member\n"
    "                        (default: current directory)\n"
    "  -k, --key <path>      node identity file (default: <root>/node.dano)\n"
    "  -a, --addr <ip:port>  address to listen on (default: 0.0.0.0:4444)\n"
    "  -w, --window <secs>   how far a direct peek's timestamp may stand from\n"
    "                        this clock, and how long its nonce is remembered\n"
    "                        against replay (default: 120)\n";

constexpr int exit_ok = 0;
constexpr int exit_failed = 1;
constexpr int exit_misused = 2;

template <typename... Args>
int fail(std::format_string<Args...> format, Args&&... args) {
    std::print(stderr, "fexerver: ");
    std::println(stderr, format, std::forward<Args>(args)...);
    return exit_failed;
}

std::string message(std::errc code) {
    return std::make_error_code(code).message();
}

std::string root_of(const flags::args& args) {
    return args.get<std::string>("root", "r").value_or(std::string{"."});
}

fex::relay::server the_server;

void on_signal(int) {
    the_server.stop();
}

int serve(const flags::args& args) {
    fex::relay::options opts;
    opts.root = root_of(args);
    opts.key_path = args.get<std::string>("key", "k").value_or(std::string{});
    opts.addr = args.get<std::string>("addr", "a").value_or(std::string{"0.0.0.0:4444"});
    opts.peek_window_s = args.get<fex::u64>("window", "w").value_or(opts.peek_window_s);
    if (opts.peek_window_s == 0)
        return fail("--window must be at least one second");

    if (const auto started = the_server.start(opts); !started)
        return fail("cannot start: {}: {}", the_server.failed_at(),
                    message(started.error()));

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::println("fexerver {} listening on {}, root {}, {} member(s), peek window {}s",
                 fex::version, the_server.local_addr().to_string(), opts.root,
                 the_server.members(), opts.peek_window_s);
    // Under a service manager stdout is a pipe, not a tty, so it is fully
    // buffered: without this the only line the relay ever says would sit in the
    // buffer until it stopped.
    std::fflush(stdout);
    // #6: the startup invariant. Nothing can bring a lost object back, so this
    // is said out loud rather than silently tolerated.
    if (const auto gone = the_server.missing_objects(); gone != 0)
        std::println(stderr, "fexerver: warning: {} pinned object(s) missing from {}/objects",
                     gone, opts.root);
    if (const auto ran = the_server.run(); !ran)
        return fail("stopped: {}", message(ran.error()));
    return exit_ok;
}

// #3: registration is the member's card added to the registry. The relay picks
// the change up on the next request it serves -- there is nothing to restart
// and no signal to send.
int include(const flags::args& args) {
    const auto card = args.get<std::string>(std::size_t{1});
    if (!card)
        return fail("include needs a card: fexerver include <card.danl>");
    const auto root = root_of(args);
    const auto added = fex::relay::admin::include(root, card->c_str());
    if (!added) {
        switch (added.error()) {
        case std::errc::file_exists:
            return fail("that name is already registered on {}", root);
        case std::errc::address_in_use:
            return fail("that key is already registered on {} under another name", root);
        case std::errc::not_supported:
            return fail("{}/roster.danl holds a record this build does not know;\n"
                        "edit it by hand rather than let this rewrite it without", root);
        default:
            return fail("cannot register {}: {}", *card, message(added.error()));
        }
    }
    std::println("registered {}{}", added->name,
                 added->is_relay() ? " (a relay's card: it grants nothing yet)" : "");
    return exit_ok;
}

int exclude(const flags::args& args) {
    const auto name = args.get<std::string>(std::size_t{1});
    if (!name)
        return fail("exclude needs a name: fexerver exclude <name>");
    const auto root = root_of(args);
    const auto gone = fex::relay::admin::exclude(root, *name);
    if (!gone) {
        switch (gone.error()) {
        case std::errc::no_such_file_or_directory:
            return fail("'{}' is not registered on {}", *name, root);
        case std::errc::not_supported:
            return fail("{}/roster.danl holds a record this build does not know;\n"
                        "edit it by hand rather than let this rewrite it without", root);
        default:
            return fail("cannot remove '{}': {}", *name, message(gone.error()));
        }
    }
    std::println("removed {} -- capsules/{} is still on disk", *name, *name);
    return exit_ok;
}

int roster(const flags::args& args) {
    const auto root = root_of(args);
    const auto reg = fex::relay::admin::list(root);
    if (!reg)
        return fail("cannot read {}/roster.danl: {}", root, message(reg.error()));
    if (reg->records.empty()) {
        std::println("nobody is registered on {}", root);
        return exit_ok;
    }
    // the same fingerprint the client prints and the same one a card is verified
    // by (#3), so one member reads as one member whichever end you are at
    for (const auto& e : reg->records)
        std::println("{}  {}{}{}", e.name, fex::fingerprint_hex(e.pub),
                     e.addr.empty() ? std::string{} : "  " + e.addr,
                     e.intro.empty() ? std::string{} : "  " + e.intro);
    return exit_ok;
}

} // namespace

int main(int argc, char** argv) {
    const flags::args args(argc, argv);
    const auto command = args.get<std::string_view>(std::size_t{0}).value_or("");

    if (command == "help") {
        std::print("{}", usage);
        return exit_ok;
    }
    if (command == "version") {
        std::println("fexerver {}", fex::version);
        return exit_ok;
    }
    if (command.empty()) {
        std::print(stderr, "{}", usage);
        return exit_misused;
    }

    if (command == "serve") return serve(args);
    if (command == "include") return include(args);
    if (command == "exclude") return exclude(args);
    if (command == "roster") return roster(args);

    fail("unknown command '{}'", command);
    std::print(stderr, "{}", usage);
    return exit_misused;
}
