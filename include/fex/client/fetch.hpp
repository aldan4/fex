// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Reading a capsule back (#10.2): peek -> head -> the inventory -> one file at a
// time, by hash, into the place the inventory names.
//
// Two things live here, and a future third is their sum. `refresh_inventory` brings
// files/inventory.danl level with the head the relay answered and hands back what it
// says; `fetch` puts one of its records on disk. Converging a whole directory is
// those two in a loop plus the deletions, which is a command this client does not
// have -- and does not need in order to have these.
//
// The inventory is fetched by the same primitive as everything else, and its hash
// comes from the head rather than from a record -- an inventory cannot name itself.
// That is why refreshing it says whether it actually travelled: `fex fetch
// inventory.danl` is this call, and it has to be able to report what it did.
//
// **Nothing here holds a file.** A download is written to state/staging/<hash> as the
// chunks arrive and hashed as it is written, so the memory a fetch costs is one
// datagram whether the file is a kilobyte or a gigabyte. The staging file becomes the
// real one by rename, which is why state/ sits beside files/ rather than under the
// root: one filesystem, one atomic step, and a fetch that dies leaves nothing behind
// that the next command does not sweep away.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include <unistd.h>

#include <fex/client/config.hpp>
#include <fex/client/requester.hpp>
#include <fex/fs.hpp>
#include <fex/inventory.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::client {

namespace detail {

[[nodiscard]] inline std::string stage_path(const std::string& state_dir,
                                            const hash256& h) {
    return staging_dir(state_dir) + '/' + to_hex(fex::bytes{h});
}

// One file by hash into `stage`, chunk by chunk. The caller knows the size from the
// inventory (or, for the inventory itself, from the head), and the hash that named
// the file is checked against what actually arrived before the file is of any use to
// anybody -- a relay that hands over the wrong bytes is refused here and not three
// steps later.
[[nodiscard]] inline std::expected<void, std::errc>
download(requester& r, const hash256& h, u64 size, const std::string& stage) noexcept {
    auto fd = fs::open_new(stage.c_str());
    if (!fd)
        return std::unexpected(fd.error());
    crypto::ascon::hash256_stream digest;
    std::array<u8, wire::get_size> cmd;
    std::array<u8, wire::max_command> reply;
    const auto fail = [&](std::errc e) -> std::expected<void, std::errc> {
        ::close(*fd);
        ::unlink(stage.c_str());
        return std::unexpected(e);
    };
    for (u64 no = 0; no != wire::chunk_count(size); ++no) {
        const auto z = *wire::chunk_len(size, no);
        wire::get g{};
        g.chunk_no = no;
        std::copy(h.begin(), h.end(), g.file_hash);
        const auto n = wire::write_get(
            cmd, wire::mheader_of(wire::mkind::get, wire::mstatus::ok, fresh_req_id()), g);
        bool got_chunk = false;
        for (int tries = 0; tries != 3 && !got_chunk; ++tries) {
            const auto got = r.call(fex::bytes{cmd.data(), n}, reply);
            if (!got)
                return fail(got.error());
            const auto mh = wire::read_mheader(fex::bytes{reply.data(), *got});
            if (!mh || wire::mkind_of(*mh) != wire::mkind::chunk)
                return fail(std::errc::protocol_error);
            if (wire::mstatus_of(*mh) == wire::mstatus::not_found) {
                // #9: a commit may be replacing the file right now -- retry
                if (const auto again = r.peek(); !again)
                    return fail(again.error());
                continue;
            }
            if (wire::mstatus_of(*mh) != wire::mstatus::ok)
                return fail(std::errc::protocol_error);
            const auto ch = wire::read_chunk(fex::bytes{reply.data(), *got});
            if (!ch || ch->data.size() != z)
                return fail(std::errc::protocol_error);
            if (const auto w = fs::write_all(*fd, ch->data); !w)
                return fail(w.error());
            digest.update(ch->data);
            got_chunk = true;
        }
        if (!got_chunk)
            return fail(std::errc::no_such_file_or_directory);
    }
    if (digest.final() != h)
        return fail(std::errc::bad_message);
    if (::fsync(*fd) != 0)
        return fail(fs::last_errc());
    if (::close(*fd) != 0) {
        ::unlink(stage.c_str());
        return fs::failure();
    }
    return {};
}

} // namespace detail

// Where the capsule stands on the relay, and what it holds.
struct published {
    u64 seq = 0;
    u64 inv_size = 0;    // the inventory's own size, as the head gives it
    bool fetched = false; // whether it travelled, or the local copy was already it
    inventory::file inventory;
}; // published

// #10.2 steps 1-3. The inventory is downloaded only when the copy on disk is not
// already the one the head names, so a second command in a row costs a peek and a
// local hash rather than a transfer.
//
// errc::no_message means the capsule has never been published, which is not a failure
// of anything and is the one answer a caller is expected to say something about.
[[nodiscard]] inline std::expected<published, std::errc>
refresh_inventory(requester& r, const std::string& files_dir,
                  const std::string& state_dir) noexcept {
    const auto staging = staging_dir(state_dir);
    if (auto c = fs::remove_tree(staging); !c) // #10.3: cleaned at the start
        return std::unexpected(c.error());
    if (auto c = fs::ensure_dirs(staging); !c)
        return std::unexpected(c.error());
    if (auto c = fs::ensure_dirs(files_dir); !c)
        return std::unexpected(c.error());

    const auto head = r.peek();
    if (!head)
        return std::unexpected(head.error());
    hash256 inv_hash;
    std::copy(head->inv_hash, head->inv_hash + 32, inv_hash.begin());
    if (head->seq == 0 && inv_hash == hash256{})
        return std::unexpected(std::errc::no_message); // never published

    const auto inv_path = inventory_path(files_dir);
    if (head->inv_size == 0) {
        // an empty capsule: no bytes at all, and the head must say so
        if (inv_hash != crypto::ascon::hash256({}))
            return std::unexpected(std::errc::protocol_error);
        const bool had = fs::stat_of(inv_path.c_str()).kind == fs::entry_kind::file;
        if (auto w = fs::write_file_atomic(inv_path, {}); !w)
            return std::unexpected(w.error());
        return published{head->seq, 0, !had, inventory::file{}};
    }
    bool fetched = false;
    const auto local = fs::hash_file(inv_path.c_str());
    if (!local || *local != inv_hash) {
        const auto stage = detail::stage_path(state_dir, inv_hash);
        if (auto got = detail::download(r, inv_hash, head->inv_size, stage); !got)
            return std::unexpected(got.error());
        if (::rename(stage.c_str(), inv_path.c_str()) != 0) {
            const auto e = fs::last_errc();
            ::unlink(stage.c_str());
            return std::unexpected(e);
        }
        fetched = true;
    }
    auto text = fs::read_file(inv_path.c_str());
    if (!text)
        return std::unexpected(text.error());
    auto inv = inventory::parse(std::string_view{
        reinterpret_cast<const char*>(text->data()), text->size()});
    if (!inv)
        return std::unexpected(inv.error());
    return published{head->seq, head->inv_size, fetched, std::move(*inv)};
}

// #10.2 steps 5-7: one record of the inventory into files/<path>. True when it was
// downloaded, false when the file already standing there is the one wanted -- which
// is what makes running this twice, or over a capsule half read back, cost nothing
// and mean the same thing.
[[nodiscard]] inline std::expected<bool, std::errc>
fetch(requester& r, const inventory::entry& e, const std::string& files_dir,
      const std::string& state_dir) noexcept {
    const auto dest = files_dir + '/' + e.path;
    if (const auto st = fs::stat_of(dest.c_str());
        st.kind == fs::entry_kind::file && st.size == e.size) {
        if (const auto have = fs::hash_file(dest.c_str()); have && *have == e.hash)
            return false;
    }
    if (auto c = fs::ensure_dirs(fs::dir_of(dest)); !c)
        return std::unexpected(c.error());
    if (e.size == 0) {
        // a record of size zero is assembled by definition and never travels (#9)
        if (e.hash != crypto::ascon::hash256({}))
            return std::unexpected(std::errc::bad_message);
        if (auto w = fs::write_file_atomic(dest, {}); !w)
            return std::unexpected(w.error());
        return true;
    }
    if (auto c = fs::ensure_dirs(staging_dir(state_dir)); !c)
        return std::unexpected(c.error());
    const auto stage = detail::stage_path(state_dir, e.hash);
    if (auto got = detail::download(r, e.hash, e.size, stage); !got)
        return std::unexpected(got.error());
    if (::rename(stage.c_str(), dest.c_str()) != 0) {
        const auto err = fs::last_errc();
        ::unlink(stage.c_str());
        return std::unexpected(err);
    }
    return true;
}

} // namespace fex::client
