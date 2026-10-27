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
// chunks arrive, each at its own offset, and hashed once whole, so the memory a fetch
// costs is a datagram and a bitmap of the chunks in flight whether the file is a
// kilobyte or a gigabyte. The staging file becomes the real one by rename, which is
// why state/ sits beside files/ rather than under the root: one filesystem, one
// atomic step, and a fetch that dies leaves nothing behind that the next command does
// not sweep away.

#include <algorithm>
#include <bitset>
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

// How many chunks a download keeps track of at once: the ones received ahead of the
// first one still missing. A round never asks past base + download_track, so a bit
// per chunk modulo this is enough and the bitmap -- half a kilobyte -- is all the
// state a download holds.
inline constexpr u64 download_track = 4096;

// One file by hash into `stage`, in rounds (#10.2 step 8, #5.3). A round asks for a
// window of chunks -- what the last round lost first, then fresh ones -- as range
// gets of at most get_burst_max each, all under one req_id, and collects the
// bursts that come back until every chunk asked for has arrived or the line has
// gone quiet. A burst arrives back to back, so a quarter of a round trip without a
// datagram means the rest of the round is not coming. Each chunk names its number,
// so it lands at its own offset whatever order it comes in, and a late one from an
// earlier round is as good as any. The window grows on a round that lost at most
// an eighth of what it asked for and halves on one that lost more: a scattered
// loss is the line, a lost tail is a queue that overflowed. A round that brings
// nothing at all is a lost request (#5): peek, back off, ask again.
//
// The caller knows the size from the inventory (or, for the inventory itself, from
// the head), and the hash that named the file is checked against what actually
// arrived before the file is of any use to anybody -- a relay that hands over the
// wrong bytes is refused here and not three steps later.
[[nodiscard]] inline std::expected<void, std::errc>
download(requester& r, const hash256& h, u64 size, const std::string& stage) noexcept {
    auto fd = fs::open_new(stage.c_str());
    if (!fd)
        return std::unexpected(fd.error());
    const auto fail = [&](std::errc e) -> std::expected<void, std::errc> {
        ::close(*fd);
        ::unlink(stage.c_str());
        return std::unexpected(e);
    };
    const auto& opts = r.options();
    const u64 count = wire::chunk_count(size);
    const u64 req_id = fresh_req_id(); // one for the whole file: chunks name themselves
    const u64 window_min = std::clamp<u64>(u64(std::max(opts.get_window_min, 1)), 1,
                                           download_track);
    const u64 window_max = std::clamp<u64>(u64(std::max(opts.get_window_max, 1)),
                                           window_min, download_track);
    std::array<u8, wire::get_size> cmd;
    std::array<u8, wire::max_command> reply;
    std::bitset<download_track> have; // chunk no is bit no % download_track
    u64 base = 0;     // the first chunk not yet received
    u64 frontier = 0; // the first chunk never asked for
    u64 window = window_min;
    u64 rtt_ns = 0;
    int timeout_ms = opts.request_timeout_ms;
    int stalls = 0;
    int absent = 0;

    // chunks from..to, inclusive, as gets of at most get_burst_max each
    const auto ask = [&](u64 from, u64 to) -> std::expected<void, std::errc> {
        for (u64 a = from; a <= to; a += wire::get_burst_max) {
            wire::get g{};
            g.from = a;
            g.to = std::min(to, a + (wire::get_burst_max - 1));
            std::copy(h.begin(), h.end(), g.file_hash);
            const auto n = wire::write_get(
                cmd, wire::mheader_of(wire::mkind::get, wire::mstatus::ok, req_id), g);
            if (auto c = r.cast(fex::bytes{cmd.data(), n}); !c)
                return std::unexpected(c.error());
        }
        return {};
    };

    while (base != count) {
        // what the last rounds lost, then what nobody has asked for yet
        u64 budget = window;
        u64 asked = 0;
        for (u64 no = base; no < frontier && budget != 0;) {
            if (have[no % download_track]) {
                ++no;
                continue;
            }
            u64 end = no;
            while (end + 1 < frontier && end + 1 - no < budget
                   && !have[(end + 1) % download_track])
                ++end;
            if (auto c = ask(no, end); !c)
                return fail(c.error());
            asked += end - no + 1;
            budget -= end - no + 1;
            no = end + 1;
        }
        const u64 limit = std::min(count, base + download_track);
        if (budget != 0 && frontier < limit) {
            const u64 end = std::min(limit, frontier + budget) - 1;
            if (auto c = ask(frontier, end); !c)
                return fail(c.error());
            asked += end - frontier + 1;
            frontier = end + 1;
        }

        // collect the bursts
        const u64 sent_ns = fs::now_ns();
        const u64 deadline = sent_ns + u64(timeout_ms) * 1'000'000;
        const u64 quiet_ns = std::max(rtt_ns / 4, u64(opts.get_quiet_min_ms) * 1'000'000);
        u64 last_ns = 0;
        u64 got = 0;
        bool gone = false;
        while (got < asked) {
            const u64 now = fs::now_ns();
            const u64 until = last_ns == 0 ? deadline
                                           : std::min(deadline, last_ns + quiet_ns);
            if (now >= until)
                break;
            const auto n = r.receive(req_id, reply,
                                     int((until - now + 999'999) / 1'000'000));
            if (!n)
                continue;
            const auto mh = wire::read_mheader(fex::bytes{reply.data(), *n});
            if (!mh || wire::mkind_of(*mh) != wire::mkind::chunk)
                return fail(std::errc::protocol_error);
            if (wire::mstatus_of(*mh) == wire::mstatus::not_found) {
                gone = true; // #9: a commit may be replacing the file right now
                break;
            }
            if (wire::mstatus_of(*mh) != wire::mstatus::ok)
                return fail(std::errc::protocol_error);
            const auto ch = wire::read_chunk(fex::bytes{reply.data(), *n});
            if (!ch)
                return fail(std::errc::protocol_error);
            const u64 no = ch->chunk_no;
            if (no < base || no >= frontier || have[no % download_track])
                continue; // a duplicate, or an answer to a round long settled
            if (ch->data.size() != *wire::chunk_len(size, no))
                return fail(std::errc::protocol_error);
            if (auto w = fs::write_all_at(*fd, ch->data, no * wire::chunk_data_size); !w)
                return fail(w.error());
            have.set(no % download_track);
            ++got;
            const u64 at = fs::now_ns();
            if (last_ns == 0) { // the first of a round: how long the line is
                const u64 sample = at - sent_ns;
                rtt_ns = rtt_ns == 0 ? sample : (7 * rtt_ns + sample) / 8;
            }
            last_ns = at;
        }

        if (gone) {
            if (++absent == 3)
                return fail(std::errc::no_such_file_or_directory);
            if (const auto again = r.peek(); !again)
                return fail(again.error());
            continue;
        }
        if (got == 0) { // #5: nothing came back -> peek, await head, ask again
            if (++stalls == opts.max_attempts)
                return fail(std::errc::timed_out);
            if (const auto again = r.peek(); !again)
                return fail(again.error());
            timeout_ms = std::min(timeout_ms * 2, opts.request_timeout_cap_ms);
            continue;
        }
        stalls = 0;
        absent = 0;
        timeout_ms = opts.request_timeout_ms;
        window = 8 * got >= 7 * asked ? std::min(window + window_min, window_max)
                                      : std::max(window / 2, window_min);

        while (base != frontier && have[base % download_track]) {
            have.reset(base % download_track);
            ++base;
        }
    }

    if (::fsync(*fd) != 0)
        return fail(fs::last_errc());
    if (::close(*fd) != 0) {
        ::unlink(stage.c_str());
        return fs::failure();
    }
    const auto digest = fs::hash_file(stage.c_str());
    if (!digest || *digest != h) {
        ::unlink(stage.c_str());
        return std::unexpected(digest ? std::errc::bad_message : digest.error());
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
