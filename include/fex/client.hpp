// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// The client side of fex: publication (#10.1), reading a capsule back and
// discovering who else is on the relay (#10.2), over a channel to one relay.

#include <fex/client/config.hpp>
#include <fex/client/discover.hpp>
#include <fex/client/publish.hpp>
#include <fex/client/requester.hpp>
#include <fex/client/fetch.hpp>
#include <fex/client/snapshot.hpp>
#include <fex/protocol.hpp>
