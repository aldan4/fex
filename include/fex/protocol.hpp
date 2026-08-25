// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// The fex protocol: everything both sides of the wire agree on. The relay
// frontend (relay.hpp) and the client frontend (client.hpp) both build on it.

#include <string_view>

#include <fex/channel.hpp>
#include <fex/crypto.hpp>
#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/inventory.hpp>
#include <fex/net/poller.hpp>
#include <fex/net/socket.hpp>
#include <fex/path.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#if defined(FEX_WITH_TESTS) || defined(FEX_WITH_BENCHS)
#include <doctest/doctest.h>
#endif

#ifdef FEX_WITH_BENCHS
#include <nanobench.h>
#endif

namespace fex {

inline constexpr std::string_view version = "0.1.0";

} // namespace fex

#ifdef FEX_WITH_BENCHS

TEST_SUITE("fex") {

SCENARIO("bench: fex::version comparison") {
    ankerl::nanobench::Bench().run("fex::version == \"0.1.0\"", [] {
        ankerl::nanobench::doNotOptimizeAway(fex::version == "0.1.0");
    });
}

}

#endif
