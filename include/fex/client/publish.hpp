// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Publication (#10.1): snapshot -> peek/head -> put/poll per file -> inventory ->
// commit -> write files/inventory.danl. Everything is uploaded strictly from the
// snapshot: a file that changes on disk mid-flight fails its hash check and restarts
// the run.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include <fex/client/config.hpp>
#include <fex/client/requester.hpp>
#include <fex/client/snapshot.hpp>
#include <fex/inventory.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::client {

struct publish_report {
    u64 seq = 0;
    bool unchanged = false;
}; // publish_report

namespace detail {

// put/poll rounds until the relay reports the file assembled (#5.2, #10.1);
// errc::bad_message = terminal hash mismatch (the caller restarts the run),
// errc::timed_out = stalled rounds
[[nodiscard]] inline std::expected<void, std::errc>
upload_file(requester& r, const hash256& h, fex::bytes data) noexcept {
    if (data.empty())
        return {}; // empty files are never uploaded (#10.1)
    const auto& opts = r.options();
    std::array<u8, wire::put_base + wire::chunk_data_size> put_buf;
    std::array<u8, wire::poll_size> poll_buf;
    std::array<u8, wire::max_command> reply;

    u64 last_missing = ~u64{0};
    int stalled = 0;
    bool first_round = true;
    for (;;) {
        // what is still missing?
        std::vector<wire::range> missing;
        if (first_round) {
            first_round = false;
            missing.push_back(wire::range{
                0, static_cast<std::uint32_t>(wire::chunk_count(data.size()) - 1)});
        } else {
            wire::poll p{};
            std::copy(h.begin(), h.end(), p.file_hash);
            const auto n = wire::write_poll(
                poll_buf, wire::mheader_of(wire::mkind::poll, wire::mstatus::ok,
                                           fresh_req_id()), p);
            const auto got = r.call(fex::bytes{poll_buf.data(), n}, reply);
            if (!got)
                return std::unexpected(got.error());
            const auto mh = wire::read_mheader(fex::bytes{reply.data(), *got});
            if (!mh || wire::mkind_of(*mh) != wire::mkind::gaps)
                return std::unexpected(std::errc::protocol_error);
            switch (wire::mstatus_of(*mh)) {
            case wire::mstatus::ok:
                break;
            case wire::mstatus::hash_mismatch:
                return std::unexpected(std::errc::bad_message); // terminal (#5.2)
            case wire::mstatus::not_found: // e.g. the relay restarted mid-upload
                missing.push_back(wire::range{
                    0, static_cast<std::uint32_t>(wire::chunk_count(data.size()) - 1)});
                break;
            default:
                return std::unexpected(std::errc::protocol_error);
            }
            if (missing.empty()) {
                const auto g = wire::read_gaps(fex::bytes{reply.data(), *got});
                if (!g)
                    return std::unexpected(std::errc::protocol_error);
                if (g->count == 0)
                    return {}; // assembled and verified
                missing.assign(g->ranges.begin(), g->ranges.begin() + g->count);
            }
        }

        u64 missing_total = 0;
        for (const auto& m : missing)
            missing_total += u64{m.to} - m.from + 1;
        if (missing_total >= last_missing) {
            if (++stalled >= opts.stall_rounds)
                return std::unexpected(std::errc::timed_out); // #10.1: no progress
        } else {
            stalled = 0;
        }
        last_missing = missing_total;

        // a window of puts over the missing ranges
        int sent = 0;
        for (const auto& m : missing) {
            for (u64 no = m.from; no <= m.to && sent != opts.put_window; ++no, ++sent) {
                wire::put p{};
                p.file_size = data.size();
                p.chunk_no = no;
                std::copy(h.begin(), h.end(), p.file_hash);
                p.data = data.subspan(no * wire::chunk_data_size,
                                      *wire::chunk_len(data.size(), no));
                const auto n = wire::write_put(
                    put_buf, wire::mheader_of(wire::mkind::put, wire::mstatus::ok, 0), p);
                if (auto c = r.cast(fex::bytes{put_buf.data(), n}); !c)
                    return std::unexpected(c.error());
            }
            if (sent == opts.put_window)
                break;
        }
    }
}

[[nodiscard]] inline std::expected<wire::mstatus, std::errc>
send_commit(requester& r, u64 seq, const hash256& h) noexcept {
    std::array<u8, wire::commit_size> cmd;
    std::array<u8, wire::max_command> reply;
    wire::commit c{};
    c.seq = seq;
    std::copy(h.begin(), h.end(), c.inv_hash);
    const auto n = wire::write_commit(
        cmd, wire::mheader_of(wire::mkind::commit, wire::mstatus::ok, fresh_req_id()), c);
    const auto got = r.call(fex::bytes{cmd.data(), n}, reply);
    if (!got)
        return std::unexpected(got.error());
    const auto mh = wire::read_mheader(fex::bytes{reply.data(), *got});
    if (!mh || wire::mkind_of(*mh) != wire::mkind::done)
        return std::unexpected(std::errc::protocol_error);
    return wire::mstatus_of(*mh);
}

} // namespace detail

[[nodiscard]] inline std::expected<publish_report, std::errc>
publish(requester& r, const std::string& files_dir,
        std::string* offending = nullptr) noexcept {
    // What the relay now holds, kept where the member can read it (#10.1 step 6).
    // The commit is what publishes; this is a record of it, so a failure to write it
    // is reported and does not unmake what the relay has already accepted.
    const auto keep_inventory =
        [&](fex::bytes inv_bytes) -> std::expected<void, std::errc> {
            return fs::write_file_atomic(inventory_path(files_dir), inv_bytes);
        };
    const int max_restarts = r.options().max_restarts;
    for (int attempt = 0; attempt != max_restarts; ++attempt) {
        // step 1: the snapshot fixes the whole inventory
        auto inv = snapshot(files_dir, offending);
        if (!inv)
            return std::unexpected(inv.error());
        const auto inv_text = inventory::to_danl(*inv);
        const std::vector<u8> inv_bytes{inv_text.begin(), inv_text.end()};
        const hash256 inv_hash = crypto::ascon::hash256(fex::bytes{inv_bytes});

        // step 2: peek -> head; nothing to do when the hash already matches
        auto head = r.peek();
        if (!head)
            return std::unexpected(head.error());
        hash256 remote;
        std::copy(head->inv_hash, head->inv_hash + 32, remote.begin());
        if (remote == inv_hash) {
            if (const auto kept = keep_inventory(fex::bytes{inv_bytes}); !kept)
                return std::unexpected(kept.error());
            return publish_report{head->seq, true};
        }

        // step 3: every new non-empty file, once per distinct hash
        bool restart = false;
        hash256_set done;
        for (const auto& e : inv->entries) {
            if (e.size == 0 || !done.emplace(e.hash).second)
                continue;
            auto data = fs::read_file((files_dir + '/' + e.path).c_str());
            if (!data
                || crypto::ascon::hash256(fex::bytes{*data}) != e.hash) {
                restart = true; // the folder moved under us: retake the snapshot
                break;
            }
            const auto up = detail::upload_file(r, e.hash, fex::bytes{*data});
            if (!up) {
                if (up.error() == std::errc::bad_message) {
                    restart = true;
                    break;
                }
                return std::unexpected(up.error());
            }
        }
        if (restart)
            continue;

        // step 4: the inventory file itself (never for the empty inventory)
        if (!inv_bytes.empty()) {
            const auto up = detail::upload_file(r, inv_hash, fex::bytes{inv_bytes});
            if (!up) {
                if (up.error() == std::errc::bad_message)
                    continue;
                return std::unexpected(up.error());
            }
        }

        // step 5: commit with the next seq; one refresh on stale_seq
        u64 seq = head->seq + 1;
        for (int tries = 0; tries != 2; ++tries) {
            const auto status = detail::send_commit(r, seq, inv_hash);
            if (!status)
                return std::unexpected(status.error());
            if (*status == wire::mstatus::ok) {
                if (const auto kept = keep_inventory(fex::bytes{inv_bytes}); !kept)
                    return std::unexpected(kept.error());
                return publish_report{seq, false};
            }
            if (*status == wire::mstatus::stale_seq && tries == 0) {
                const auto fresh = r.peek();
                if (!fresh)
                    return std::unexpected(fresh.error());
                seq = fresh->seq + 1;
                continue;
            }
            return std::unexpected(std::errc::protocol_error);
        }
    }
    return std::unexpected(std::errc::bad_message); // restarts exhausted
}

} // namespace fex::client
