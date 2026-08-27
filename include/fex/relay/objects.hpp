// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// The object store (#6): content addressed by the hash of its own bytes.
//
//   <root>/objects/<hex64>
//
// Every capsule file, every current inventory and the roster live here, and
// nowhere else. The store is relay-wide rather than per-capsule: identical
// content is kept once however many paths or capsules name it, and get(hash)
// is served from here for any member and any federate. A name says nothing
// about who uploaded it -- a hash is learned from an inventory, and an
// inventory is something a channel handed over.
//
// Objects arrive one way only: a commit moves them in from the sender's
// assembly area once it has verified them (#9 step 6). They leave one way
// only: garbage collection takes what no head and no staged commit names.

#include <algorithm>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <fex/crypto.hpp>
#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/inventory.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::relay {

[[nodiscard]] inline const hash256& empty_content_hash() noexcept {
    static const hash256 h = crypto::ascon::hash256({});
    return h;
}

class store {
    std::string dir_;
    hash256_map<u64> verified_ns_; // when each object was last read back whole

    // #6: neither collection nor verification touches anything younger than a
    // day. A fresh object is either an upload waiting for the commit that will
    // pin it, or one that commit has just verified.
    static constexpr u64 min_age_ns = 24ull * 3600 * 1'000'000'000;

public:

    store() = default;

    [[nodiscard]] static std::expected<store, std::errc>
    open(std::string_view dir) noexcept {
        store s;
        s.dir_.assign(dir);
        if (auto r = fs::ensure_dirs(s.dir_); !r)
            return std::unexpected(r.error());
        return s;
    }

    [[nodiscard]] const std::string& dir() const noexcept { return dir_; }

    [[nodiscard]] std::string path_of(const hash256& h) const {
        return dir_ + '/' + to_hex(fex::bytes{h});
    }

    [[nodiscard]] bool contains(const hash256& h) const noexcept {
        return fs::stat_of(path_of(h).c_str()).kind == fs::entry_kind::file;
    }

    [[nodiscard]] std::expected<std::vector<u8>, std::errc>
    read(const hash256& h) const noexcept {
        return fs::read_file(path_of(h).c_str());
    }

    // #9 step 6: take an assembled file in under its hash. An object already
    // present holds the same bytes by definition -- that is what naming content
    // by its hash means -- so the newcomer is simply dropped. Idempotent, which
    // is what lets a crash replay the step.
    [[nodiscard]] bool adopt(const std::string& from, const hash256& h) noexcept {
        const auto to = path_of(h);
        if (fs::stat_of(to.c_str()).kind == fs::entry_kind::file) {
            (void)::unlink(from.c_str());
            return true;
        }
        if (::rename(from.c_str(), to.c_str()) == 0)
            return true;
        // a root spanning two filesystems: copy it in, then drop the source
        auto data = fs::read_file(from.c_str());
        if (!data || crypto::ascon::hash256(fex::bytes{*data}) != h)
            return false;
        if (!fs::write_file_atomic(to, fex::bytes{*data}))
            return false;
        (void)::unlink(from.c_str());
        return true;
    }

    // content the relay itself produced (the roster of #6); uploads never come
    // this way
    [[nodiscard]] bool put(fex::bytes data, const hash256& h) noexcept {
        if (contains(h))
            return true;
        return fs::write_file_atomic(path_of(h), data).has_value();
    }

    // get (#5): one chunk of the object, or not_found -- which is every reason
    // at once, since a hash absent from here is simply not something this relay
    // holds (#6)
    [[nodiscard]] std::expected<std::size_t, wire::mstatus>
    get_chunk(const wire::get& g, std::span<u8> out, u64 now_ns) noexcept {
        hash256 h;
        std::copy(g.file_hash, g.file_hash + 32, h.begin());
        const auto path = path_of(h);
        const auto st = fs::stat_of(path.c_str());
        if (st.kind != fs::entry_kind::file)
            return std::unexpected(wire::mstatus::not_found);
        if (!verified(h, path, st, now_ns))
            return std::unexpected(wire::mstatus::not_found);
        const auto z = wire::chunk_len(st.size, g.chunk_no);
        if (!z || out.size() < *z)
            return std::unexpected(wire::mstatus::not_found);
        const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            return std::unexpected(wire::mstatus::not_found);
        std::size_t off = 0;
        while (off != *z) {
            const auto n = ::pread(fd, out.data() + off, *z - off,
                                   static_cast<off_t>(g.chunk_no * wire::chunk_data_size
                                                      + off));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) {
                ::close(fd);
                return std::unexpected(wire::mstatus::not_found);
            }
            off += static_cast<std::size_t>(n);
        }
        ::close(fd);
        return *z;
    }

    // #6: an object no head and no staged commit names is garbage. Returns how
    // many were taken.
    [[nodiscard]] std::size_t collect(const hash256_set& pinned, u64 now_ns) noexcept {
        std::size_t taken = 0;
        for (const auto& h : names()) {
            if (pinned.contains(h))
                continue;
            const auto path = path_of(h);
            const auto st = fs::stat_of(path.c_str());
            if (st.kind != fs::entry_kind::file || now_ns - st.mtime_ns < min_age_ns)
                continue;
            if (::unlink(path.c_str()) != 0)
                continue;
            verified_ns_.erase(h);
            ++taken;
        }
        return taken;
    }

    // #6: the invariant checked at startup -- every pinned object is here.
    // A missing one cannot be conjured back, so this reports rather than repairs.
    [[nodiscard]] std::size_t missing(const hash256_set& pinned) const noexcept {
        std::size_t gone = 0;
        for (const auto& h : pinned)
            if (h != empty_content_hash() && !contains(h))
                ++gone;
        return gone;
    }

    [[nodiscard]] std::vector<hash256> names() const noexcept {
        std::vector<hash256> out;
        DIR* const dir = ::opendir(dir_.c_str());
        if (dir == nullptr)
            return out;
        while (const auto* e = ::readdir(dir)) {
            const std::string_view name = e->d_name;
            if (name.size() != 64 || !inventory::is_lower_hex(name))
                continue;
            hash256 h;
            if (from_hex(h, name))
                out.push_back(h);
        }
        ::closedir(dir);
        return out;
    }

private:

    // #6: an object's name is the hash of its content, and that is checked
    // lazily -- when one nobody has looked at for a long time is served. An
    // object that is not what it claims to be is not served and not kept.
    [[nodiscard]] bool verified(const hash256& h, const std::string& path,
                                const fs::info& st, u64 now_ns) noexcept {
        if (now_ns - st.mtime_ns < min_age_ns)
            return true; // written by a commit that verified it already
        if (const auto it = verified_ns_.find(h);
            it != verified_ns_.end() && now_ns - it->second < min_age_ns)
            return true;
        const auto got = fs::hash_file(path.c_str());
        if (!got)
            return false;
        if (*got != h) {
            (void)::unlink(path.c_str());
            verified_ns_.erase(h);
            return false;
        }
        verified_ns_[h] = now_ns;
        return true;
    }
}; // store

} // namespace fex::relay
