// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Discovery (#10.2): who is on a relay.
//
// `list` asks where the serving relay's roster stands -- its size and hash --
// and `refresh_roster` brings the local copy level with that answer, the same
// way `refresh_inventory` brings a capsule's inventory level with its head. The
// roster is an object like any other, so it travels by get, is verified against
// the hash that named it, and is renamed into place only once it is whole.
//
// What a member does with it is #10.2 steps 2-4: the member records name the
// capsules that can be read on this relay -- an id is hash(pub)[0:8] of the
// record -- and the relay records name the federated relays to ask next. This
// node does the first half; the second waits on federation.

#include <algorithm>
#include <expected>
#include <string>

#include <unistd.h>

#include <fex/client/config.hpp>
#include <fex/client/fetch.hpp>
#include <fex/client/requester.hpp>
#include <fex/crypto.hpp>
#include <fex/fs.hpp>
#include <fex/roster.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::client {

// The relay's directory as this node last saw it.
struct listed {
    u64 size = 0;         // the roster's own size, as list gives it
    bool fetched = false; // whether it travelled, or the local copy was already it
    fex::roster::file directory;
}; // listed

// #5 list -> roster: a pointer, not the file
[[nodiscard]] inline std::expected<wire::roster, std::errc> list(requester& r) noexcept {
    std::array<u8, wire::list_size> cmd;
    const auto n = wire::write_list(
        cmd, wire::mheader_of(wire::mkind::list, wire::mstatus::ok, fresh_req_id()));
    std::array<u8, wire::max_command> reply;
    const auto got = r.call(fex::bytes{cmd.data(), n}, reply);
    if (!got)
        return std::unexpected(got.error());
    const auto mh = wire::read_mheader(fex::bytes{reply.data(), *got});
    if (!mh || wire::mkind_of(*mh) != wire::mkind::roster)
        return std::unexpected(std::errc::protocol_error);
    if (wire::mstatus_of(*mh) != wire::mstatus::ok)
        return std::unexpected(std::errc::protocol_error);
    const auto m = wire::read_roster(fex::bytes{reply.data(), *got});
    if (!m)
        return std::unexpected(std::errc::protocol_error);
    return *m;
}

// #10.2 step 1: peers/<relay>/roster.danl, brought level with what the relay
// publishes and validated whole (#6). A second call in a row costs a list and a
// local hash rather than a transfer.
[[nodiscard]] inline std::expected<listed, std::errc>
refresh_roster(requester& r, const std::string& peer) noexcept {
    const auto state = peer_state_dir(peer);
    const auto staging = staging_dir(state);
    if (auto c = fs::remove_tree(staging); !c) // #10.3: cleaned at the start
        return std::unexpected(c.error());
    if (auto c = fs::ensure_dirs(staging); !c)
        return std::unexpected(c.error());

    const auto where = list(r);
    if (!where)
        return std::unexpected(where.error());
    hash256 h;
    std::copy(where->hash, where->hash + 32, h.begin());
    const auto path = roster_path(peer);

    if (where->size == 0) {
        // a relay with nobody on it: no bytes at all, and it must say so
        if (h != crypto::ascon::hash256({}))
            return std::unexpected(std::errc::protocol_error);
        const bool had = fs::stat_of(path.c_str()).kind == fs::entry_kind::file;
        if (auto w = fs::write_file_atomic(path, {}); !w)
            return std::unexpected(w.error());
        return listed{0, !had, fex::roster::file{}};
    }

    bool fetched = false;
    const auto local = fs::hash_file(path.c_str());
    if (!local || *local != h) {
        const auto stage = detail::stage_path(state, h);
        if (auto got = detail::download(r, h, where->size, stage); !got)
            return std::unexpected(got.error());
        if (::rename(stage.c_str(), path.c_str()) != 0) {
            const auto e = fs::last_errc();
            ::unlink(stage.c_str());
            return std::unexpected(e);
        }
        fetched = true;
    }
    auto text = fs::read_file(path.c_str());
    if (!text)
        return std::unexpected(text.error());
    auto parsed = fex::roster::parse(std::string_view{
        reinterpret_cast<const char*>(text->data()), text->size()});
    if (!parsed)
        return std::unexpected(parsed.error());
    return listed{where->size, fetched, std::move(*parsed)};
}

} // namespace fex::client
