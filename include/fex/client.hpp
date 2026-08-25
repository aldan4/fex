// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// The client side of fex: publication (#10.1) and restoration (#10.2) of the
// capsule this node owns, over a channel to one relay.

#include <fex/client/config.hpp>
#include <fex/client/publish.hpp>
#include <fex/client/requester.hpp>
#include <fex/client/restore.hpp>
#include <fex/client/snapshot.hpp>
#include <fex/protocol.hpp>
