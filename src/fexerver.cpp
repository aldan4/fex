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
    "  fexerver --help | --version\n"
    "\n"
    "options:\n"
    "  -r, --root <path>     relay root: members/ and capsules/ live here\n"
    "                        (default: current directory)\n"
    "  -k, --key <path>      node identity file (default: <root>/node.dano)\n"
    "  -a, --addr <ip:port>  address to listen on (default: 0.0.0.0:4444)\n"
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

    if (const auto started = the_server.start(opts); !started)
        return fail("cannot start on {} with root {}: {}", opts.addr, opts.root,
                    message(started.error()));

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::println("fexerver {} listening on {}, root {}", fex::version,
                 the_server.local_addr().to_string(), opts.root);
    if (const auto ran = the_server.run(); !ran)
        return fail("stopped: {}", message(ran.error()));
    return 0;
}
