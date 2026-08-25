// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Restoration (#10.2): peek -> head -> inventory -> diff by hash -> download the
// missing, copy the moved, delete the vanished -- strictly inside the capsule.

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include <fex/client/publish.hpp>
#include <fex/client/requester.hpp>
#include <fex/client/snapshot.hpp>
#include <fex/inventory.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::client {

namespace detail {

// downloads a whole file by hash; the caller knows its size from the inventory
[[nodiscard]] inline std::expected<std::vector<u8>, std::errc>
download(requester& r, const hash256& h, u64 size) noexcept {
    std::vector<u8> data(size);
    std::array<u8, wire::get_size> cmd;
    std::array<u8, wire::max_command> reply;
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
                return std::unexpected(got.error());
            const auto mh = wire::read_mheader(fex::bytes{reply.data(), *got});
            if (!mh || wire::mkind_of(*mh) != wire::mkind::chunk)
                return std::unexpected(std::errc::protocol_error);
            if (wire::mstatus_of(*mh) == wire::mstatus::not_found) {
                // #9: a commit may be replacing the file right now -- retry
                if (const auto again = r.peek(); !again)
                    return std::unexpected(again.error());
                continue;
            }
            if (wire::mstatus_of(*mh) != wire::mstatus::ok)
                return std::unexpected(std::errc::protocol_error);
            const auto ch = wire::read_chunk(fex::bytes{reply.data(), *got});
            if (!ch || ch->data.size() != z)
                return std::unexpected(std::errc::protocol_error);
            std::copy(ch->data.begin(), ch->data.end(),
                      data.begin() + static_cast<std::ptrdiff_t>(no * wire::chunk_data_size));
            got_chunk = true;
        }
        if (!got_chunk)
            return std::unexpected(std::errc::no_such_file_or_directory);
    }
    if (crypto::ascon::hash256(fex::bytes{data}) != h)
        return std::unexpected(std::errc::bad_message);
    return data;
}

} // namespace detail

[[nodiscard]] inline std::expected<void, std::errc>
restore(requester& r, const std::string& capsule_dir, const std::string& tmp_dir) noexcept {
    if (auto c = fs::remove_tree(tmp_dir); !c) // #10.3: tmp/ is cleaned at start
        return c;
    if (auto c = fs::ensure_dirs(tmp_dir); !c)
        return c;
    if (auto c = fs::ensure_dirs(capsule_dir); !c)
        return c;

    // steps 1-2: head -> inventory -> strict validation (#7, #8 via parse)
    const auto head = r.peek();
    if (!head)
        return std::unexpected(head.error());
    hash256 inv_hash;
    std::copy(head->inv_hash, head->inv_hash + 32, inv_hash.begin());
    if (head->seq == 0 && inv_hash == hash256{})
        return std::unexpected(std::errc::no_message); // never published
    std::vector<u8> inv_bytes;
    if (head->inv_size != 0) {
        auto data = detail::download(r, inv_hash, head->inv_size);
        if (!data)
            return std::unexpected(data.error());
        inv_bytes = std::move(*data);
    } else if (inv_hash != crypto::ascon::hash256({})) {
        return std::unexpected(std::errc::protocol_error);
    }
    const auto inv = inventory::parse(std::string_view{
        reinterpret_cast<const char*>(inv_bytes.data()), inv_bytes.size()});
    if (!inv)
        return std::unexpected(inv.error());

    // step 3: diff with the local state by hash
    auto local = snapshot(capsule_dir);
    if (!local)
        return std::unexpected(local.error());
    hash_map<std::string, hash256> local_by_path;
    hash256_map<std::string> local_by_hash;
    for (const auto& e : local->entries) {
        local_by_path.emplace(e.path, e.hash);
        local_by_hash.emplace(e.hash, e.path);
    }

    // step 4: fetch or copy what is missing, atomically into place
    for (const auto& e : inv->entries) {
        if (const auto it = local_by_path.find(e.path);
            it != local_by_path.end() && it->second == e.hash)
            continue; // already right
        const auto target = capsule_dir + '/' + e.path;
        if (auto c = fs::ensure_dirs(fs::dir_of(target)); !c)
            return c;
        if (e.size == 0) {
            if (e.hash != crypto::ascon::hash256({}))
                return std::unexpected(std::errc::bad_message);
            if (auto w = fs::write_file_atomic(target, {}); !w)
                return w;
            continue;
        }
        if (const auto same = local_by_hash.find(e.hash); same != local_by_hash.end()) {
            // #10.2: same hash under another path -- a local copy, no download
            auto data = fs::read_file((capsule_dir + '/' + same->second).c_str());
            if (data && crypto::ascon::hash256(fex::bytes{*data}) == e.hash) {
                if (auto w = fs::write_file_atomic(target, fex::bytes{*data}); !w)
                    return w;
                continue;
            }
            // the local copy changed since the walk: fall through to download
        }
        auto data = detail::download(r, e.hash, e.size);
        if (!data)
            return std::unexpected(data.error());
        if (auto w = fs::write_file_atomic(target, fex::bytes{*data}); !w)
            return w;
    }

    // step 5: paths gone from the inventory are deleted, strictly inside the
    // capsule tree; empty directories are unrepresentable, so prune them
    hash_set<std::string> keep;
    for (const auto& e : inv->entries)
        keep.emplace(e.path);
    std::vector<std::string> dirs;
    for (const auto& e : local->entries)
        if (!keep.contains(e.path))
            (void)::unlink((capsule_dir + '/' + e.path).c_str());
    if (auto walked = fs::walk(capsule_dir.c_str(),
            [&](std::string_view rel, const fs::info& st) -> std::expected<void, std::errc> {
                if (st.kind == fs::entry_kind::dir)
                    dirs.emplace_back(rel);
                return {};
            });
        !walked)
        return walked;
    std::ranges::sort(dirs, [](const std::string& a, const std::string& b) {
        return a.size() > b.size();
    });
    for (const auto& d : dirs)
        (void)::rmdir((capsule_dir + '/' + d).c_str());
    return {};
}

} // namespace fex::client
