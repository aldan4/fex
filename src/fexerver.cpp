// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// fexerver -- the capsule relay.

#include <fex/relay.hpp>

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
    "  fexerver [--root <path>] [--key <path>] [--addr <ip:port>]\n"
    "           [--window <seconds>]\n"
    "  fexerver --help | --version\n"
    "\n"
    "options:\n"
    "  -r, --root <path>     relay root: roster.danl, objects/ and capsules/\n"
    "                        live here. roster.danl is the registry and the\n"
    "                        published directory at once: one member line per\n"
    "                        member, {:kind \"member\" :name .. :pub ..}\n"
    "                        (default: current directory)\n"
    "  -k, --key <path>      node identity file (default: <root>/node.dano)\n"
    "  -a, --addr <ip:port>  address to listen on (default: 0.0.0.0:4444)\n"
    "  -w, --window <secs>   how far a direct peek's timestamp may stand from\n"
    "                        this clock, and how long its nonce is remembered\n"
    "                        against replay (default: 120)\n"
    "  -h, --help            this text\n"
    "  -v, --version         print the version\n";

template <typename... Args>
int fail(std::format_string<Args...> format, Args&&... args) {
    std::print(stderr, "fexerver: ");
    std::println(stderr, format, std::forward<Args>(args)...);
    return 1;
}

std::string message(std::errc code) {
    return std::make_error_code(code).message();
}

fex::relay::server the_server;

void on_signal(int) {
    the_server.stop();
}

} // namespace

int main(int argc, char** argv) {
    const flags::args args(argc, argv);

    if (args.get<bool>("help", "h").value_or(false)) {
        std::print("{}", usage);
        return 0;
    }
    if (args.get<bool>("version", "v").value_or(false)) {
        std::println("fexerver {}", fex::version);
        return 0;
    }
    if (!args.positional().empty())
        return fail("unexpected argument '{}'", args.positional().front());

    fex::relay::options opts;
    opts.root = args.get<std::string>("root", "r").value_or(std::string{"."});
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
    return 0;
}
