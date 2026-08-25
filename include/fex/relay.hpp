// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// The relay side of fex: the member registry (#3), capsule storage with its
// commit transaction (#6, #9), and the event loop that serves them (#4).

#include <fex/protocol.hpp>
#include <fex/relay/assembly.hpp>
#include <fex/relay/capsule.hpp>
#include <fex/relay/registry.hpp>
#include <fex/relay/server.hpp>
