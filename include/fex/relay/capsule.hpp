// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Capsule store (#6) and the commit transaction (#9).
//
// On top of the spec's layout one extra file exists during a commit:
// head.pending.dano -- the future head.dano written next to pending.danl.
// #9's recovery must replay steps 6-7 after a crash, and that needs the
// commit's seq, which lives nowhere else on disk mid-transaction. States:
//   pending.danl + head.pending.dano, hashes agree  -> replay steps 6-7
//   pending.danl alone                              -> commit never staged, drop it
//   head.pending.dano alone, inventory.danl matches -> finish: rename to head.dano
//   head.pending.dano alone, no match               -> stale leftover, drop it

#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <dano/dano.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <fex/crypto.hpp>
#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/inventory.hpp>
#include <fex/relay/assembly.hpp>
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

struct capsule_head {
    u64 seq = 0;
    hash256 hash{};
    u64 size = 0;
}; // capsule_head

[[nodiscard]] inline std::string to_dano(const capsule_head& h) {
    return std::format(":seq {} :hash \"{}\" :size {}\n",
                       h.seq, to_hex(fex::bytes{h.hash}), h.size);
}

[[nodiscard]] inline std::expected<capsule_head, std::errc>
parse_capsule_head(std::string_view text) noexcept {
    auto reader = dano::reader::from_text(text);
    if (!reader)
        return std::unexpected(std::errc::invalid_argument);
    auto doc = reader->root().map();
    if (!doc)
        return std::unexpected(std::errc::invalid_argument);
    capsule_head h;
    bool has_seq = false, has_hash = false, has_size = false;
    while (doc->has_next()) {
        auto pair = doc->next();
        if (!pair)
            return std::unexpected(std::errc::invalid_argument);
        auto& [key, value] = *pair;
        if (key == "seq") {
            auto n = value.u64();
            if (!n)
                return std::unexpected(std::errc::invalid_argument);
            h.seq = *n;
            has_seq = true;
        } else if (key == "hash") {
            auto text_value = value.string();
            if (!text_value || !from_hex(h.hash, *text_value))
                return std::unexpected(std::errc::invalid_argument);
            has_hash = true;
        } else if (key == "size") {
            auto n = value.u64();
            if (!n)
                return std::unexpected(std::errc::invalid_argument);
            h.size = *n;
            has_size = true;
        }
    }
    if (!has_seq || !has_hash || !has_size)
        return std::unexpected(std::errc::invalid_argument);
    return h;
}

class capsule {
    std::string dir_;
    capsule_head head_{}; // seq 0 + zero hash = never published (#6)
    inventory::file inv_;
    hash256_map<std::string> hash_to_path_;
    hash256_map<assembly> assemblies_;
    hash256_set failed_; // terminal mismatches
    u64 last_enforced_ns_ = 0;

    static constexpr u64 enforce_min_age_ns = 24ull * 3600 * 1'000'000'000;

public:

    struct gaps_reply {
        wire::mstatus status;
        std::size_t count;
        std::array<wire::range, wire::gaps_max_count> ranges;
    }; // gaps_reply

    [[nodiscard]] const capsule_head& head() const noexcept { return head_; }
    [[nodiscard]] const std::string& dir() const noexcept { return dir_; }

    [[nodiscard]] static std::expected<capsule, std::errc>
    open(std::string_view dir) noexcept {
        capsule c;
        c.dir_.assign(dir);
        if (auto r = fs::ensure_dirs(c.tree_dir()); !r)
            return std::unexpected(r.error());
        if (auto r = fs::ensure_dirs(c.assembly_dir()); !r)
            return std::unexpected(r.error());
        if (auto r = c.load_inventory(); !r)
            return std::unexpected(r.error());
        if (auto r = c.load_head(); !r)
            return std::unexpected(r.error());
        c.resume_assemblies();
        if (auto r = c.recover(); !r)
            return std::unexpected(r.error());
        if (auto r = c.enforce(fs::now_ns()); !r)
            return std::unexpected(r.error());
        return c;
    }

    [[nodiscard]] wire::head head_msg() const noexcept {
        wire::head m{};
        m.seq = head_.seq;
        m.inv_size = head_.size;
        std::copy(head_.hash.begin(), head_.hash.end(), m.inv_hash);
        return m;
    }

    // get (#5): reads chunk data into out (>= 1024 bytes); serves the tree, the
    // current inventory file by its hash, and assembled files awaiting commit
    [[nodiscard]] std::expected<std::size_t, wire::mstatus>
    get_chunk(const wire::get& g, std::span<u8> out) noexcept {
        hash256 h;
        std::copy(g.file_hash, g.file_hash + 32, h.begin());
        std::string path;
        if (h == head_.hash && head_.seq != 0)
            path = inventory_path();
        else if (const auto it = hash_to_path_.find(h); it != hash_to_path_.end())
            path = tree_dir() + '/' + it->second;
        else if (const auto ait = assemblies_.find(h);
                 ait != assemblies_.end() && ait->second.assembled())
            path = ait->second.data_path();
        else
            return std::unexpected(wire::mstatus::not_found);

        const auto st = fs::stat_of(path.c_str());
        if (st.kind != fs::entry_kind::file)
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
                                   static_cast<off_t>(g.chunk_no * wire::chunk_data_size + off));
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) { // error or mid-replace shrink: client retries (#9)
                ::close(fd);
                return std::unexpected(wire::mstatus::not_found);
            }
            off += static_cast<std::size_t>(n);
        }
        ::close(fd);
        return *z;
    }

    // put (#5.2): never answered; errors surface later through poll
    void put_chunk(const wire::put& p) noexcept {
        hash256 h;
        std::copy(p.file_hash, p.file_hash + 32, h.begin());
        if (hash_to_path_.contains(h))
            return; // content already in the tree
        failed_.erase(h); // a new put starts the file over after a mismatch
        auto it = assemblies_.find(h);
        if (it != assemblies_.end() && it->second.assembled())
            return; // already assembled, put is idempotent
        if (it != assemblies_.end() && it->second.file_size() != p.file_size) {
            it->second.discard(); // client changed its mind about the size
            assemblies_.erase(it);
            it = assemblies_.end();
        }
        if (it == assemblies_.end()) {
            auto fresh = assembly::start(assembly_dir(), h, p.file_size);
            if (!fresh)
                return; // disk trouble: poll will keep reporting gaps
            it = assemblies_.emplace(h, std::move(*fresh)).first;
        }
        const auto r = it->second.put(p.chunk_no, p.data);
        if (!r)
            return;
        if (*r == assembly::put_result::mismatch) {
            assemblies_.erase(it);
            failed_.insert(h);
        }
    }

    // poll -> gaps (#5.2)
    [[nodiscard]] gaps_reply poll_file(const wire::poll& p) noexcept {
        hash256 h;
        std::copy(p.file_hash, p.file_hash + 32, h.begin());
        gaps_reply reply{};
        if ((h == head_.hash && head_.seq != 0) || hash_to_path_.contains(h)) {
            reply.status = wire::mstatus::ok; // in the tree, verified
            return reply;
        }
        if (const auto it = assemblies_.find(h); it != assemblies_.end()) {
            reply.status = wire::mstatus::ok;
            if (!it->second.assembled()) {
                reply.count = it->second.gaps(reply.ranges);
                (void)it->second.persist_map(); // #6: the range map is durable
            }
            return reply;
        }
        if (failed_.contains(h)) {
            reply.status = wire::mstatus::hash_mismatch; // terminal until re-put
            return reply;
        }
        reply.status = wire::mstatus::not_found;
        return reply;
    }

    // commit transaction (#9); the returned status goes into done
    [[nodiscard]] wire::mstatus commit(const wire::commit& c) noexcept {
        hash256 h;
        std::copy(c.inv_hash, c.inv_hash + 32, h.begin());
        if (c.seq == head_.seq && h == head_.hash)
            return wire::mstatus::ok; // idempotent re-commit
        if (c.seq <= head_.seq)
            return wire::mstatus::stale_seq;

        // step 2: the inventory file must be assembled; the empty inventory is
        // assembled by definition (its content is the empty string)
        std::vector<u8> inv_bytes;
        if (h == empty_content_hash()) {
            // empty
        } else if (const auto it = assemblies_.find(h);
                   it != assemblies_.end() && it->second.assembled()) {
            auto data = fs::read_file(it->second.data_path().c_str());
            if (!data)
                return wire::mstatus::internal;
            inv_bytes = std::move(*data);
        } else if (h == head_.hash && head_.seq != 0) {
            auto data = fs::read_file(inventory_path().c_str());
            if (!data)
                return wire::mstatus::internal;
            inv_bytes = std::move(*data);
        } else {
            return wire::mstatus::files_missing;
        }
        if (crypto::ascon::hash256(fex::bytes{inv_bytes}) != h)
            return wire::mstatus::internal;

        // step 3: parse and validate (#7)
        const std::string_view inv_text{reinterpret_cast<const char*>(inv_bytes.data()),
                                        inv_bytes.size()};
        auto parsed = inventory::parse(inv_text);
        if (!parsed)
            return wire::mstatus::internal;

        // step 4: every file of the inventory is assembled or already stored
        for (const auto& e : parsed->entries) {
            if (e.size == 0) {
                if (e.hash != empty_content_hash())
                    return wire::mstatus::files_missing;
                continue;
            }
            if (hash_to_path_.contains(e.hash))
                continue;
            const auto it = assemblies_.find(e.hash);
            if (it == assemblies_.end() || !it->second.assembled()
                || it->second.file_size() != e.size)
                return wire::mstatus::files_missing;
        }

        // step 5: stage the new inventory verbatim + the future head
        capsule_head ph;
        ph.seq = c.seq;
        ph.hash = h;
        ph.size = inv_bytes.size();
        if (!fs::write_file_atomic(pending_path(), fex::bytes{inv_bytes}))
            return wire::mstatus::internal;
        const auto ph_text = to_dano(ph);
        if (!fs::write_file_atomic(pending_head_path(),
                                   fex::bytes{reinterpret_cast<const u8*>(ph_text.data()),
                                                 ph_text.size()}))
            return wire::mstatus::internal;

        // steps 6-7
        if (!apply_pending(*parsed, ph))
            return wire::mstatus::internal;
        return wire::mstatus::ok;
    }

    // tree == inventory enforcement (#9): at open and lazily on access; outside
    // a transaction nothing younger than a day is touched
    [[nodiscard]] std::expected<void, std::errc> maybe_enforce(u64 now_ns) noexcept {
        if (now_ns - last_enforced_ns_ < enforce_min_age_ns)
            return {};
        return enforce(now_ns);
    }

    [[nodiscard]] std::expected<void, std::errc> enforce(u64 now_ns) noexcept {
        hash_set<std::string> keep;
        for (const auto& e : inv_.entries)
            keep.emplace(e.path);
        std::vector<std::string> dirs;
        const auto tree = tree_dir();
        auto walked = fs::walk(tree.c_str(),
            [&](std::string_view rel, const fs::info& st) -> std::expected<void, std::errc> {
                if (st.kind == fs::entry_kind::dir) {
                    dirs.emplace_back(rel);
                    return {};
                }
                if (keep.contains(std::string{rel}))
                    return {};
                if (now_ns - st.mtime_ns < enforce_min_age_ns)
                    return {}; // too young to touch outside a transaction
                (void)::unlink((tree + '/' + std::string{rel}).c_str());
                return {};
            });
        if (!walked)
            return walked;
        // empty directories are unrepresentable (#7): prune bottom-up
        std::ranges::sort(dirs, [](const std::string& a, const std::string& b) {
            return a.size() > b.size();
        });
        for (const auto& d : dirs)
            (void)::rmdir((tree + '/' + d).c_str()); // fails while non-empty, fine
        last_enforced_ns_ = now_ns;
        return {};
    }

private:

    [[nodiscard]] std::string tree_dir() const { return dir_ + "/tree"; }
    [[nodiscard]] std::string assembly_dir() const { return dir_ + "/assembly"; }
    [[nodiscard]] std::string inventory_path() const { return dir_ + "/inventory.danl"; }
    [[nodiscard]] std::string head_path() const { return dir_ + "/head.dano"; }
    [[nodiscard]] std::string pending_path() const { return dir_ + "/pending.danl"; }
    [[nodiscard]] std::string pending_head_path() const { return dir_ + "/head.pending.dano"; }

    [[nodiscard]] std::expected<void, std::errc> load_inventory() noexcept {
        if (fs::stat_of(inventory_path().c_str()).kind != fs::entry_kind::file)
            return {};
        auto data = fs::read_file(inventory_path().c_str());
        if (!data)
            return std::unexpected(data.error());
        auto parsed = inventory::parse(
            std::string_view{reinterpret_cast<const char*>(data->data()), data->size()});
        if (!parsed)
            return std::unexpected(parsed.error());
        set_inventory(std::move(*parsed));
        return {};
    }

    [[nodiscard]] std::expected<void, std::errc> load_head() noexcept {
        if (fs::stat_of(head_path().c_str()).kind != fs::entry_kind::file)
            return {};
        auto data = fs::read_file(head_path().c_str());
        if (!data)
            return std::unexpected(data.error());
        auto parsed = parse_capsule_head(
            std::string_view{reinterpret_cast<const char*>(data->data()), data->size()});
        if (!parsed)
            return std::unexpected(parsed.error());
        head_ = *parsed;
        return {};
    }

    void set_inventory(inventory::file inv) {
        inv_ = std::move(inv);
        hash_to_path_.clear();
        for (const auto& e : inv_.entries)
            if (e.size != 0)
                hash_to_path_.emplace(e.hash, e.path); // first path wins
    }

    void resume_assemblies() noexcept {
        DIR* const dir = ::opendir(assembly_dir().c_str());
        if (dir == nullptr)
            return;
        std::vector<std::string> names;
        while (const auto* e = ::readdir(dir)) {
            const std::string_view name = e->d_name;
            if (name.size() == 64 && inventory::is_lower_hex(name))
                names.emplace_back(name);
            else if (name.starts_with(".fex.tmp."))
                (void)::unlink((assembly_dir() + '/' + std::string{name}).c_str());
        }
        ::closedir(dir);
        for (const auto& name : names) {
            hash256 h;
            if (!from_hex(h, name))
                continue;
            auto a = assembly::resume(assembly_dir(), h);
            if (a) {
                assemblies_.emplace(h, std::move(*a));
            } else { // unreadable state: throw it away, the client re-uploads
                (void)::unlink((assembly_dir() + '/' + name).c_str());
                (void)::unlink((assembly_dir() + '/' + name + ".map").c_str());
            }
        }
    }

    [[nodiscard]] std::expected<void, std::errc> recover() noexcept {
        const bool has_pending =
            fs::stat_of(pending_path().c_str()).kind == fs::entry_kind::file;
        const bool has_phead =
            fs::stat_of(pending_head_path().c_str()).kind == fs::entry_kind::file;
        if (!has_phead) {
            if (has_pending) // staged without a head: the commit was never applied
                (void)::unlink(pending_path().c_str());
            return {};
        }
        auto phead_data = fs::read_file(pending_head_path().c_str());
        if (!phead_data)
            return std::unexpected(phead_data.error());
        auto ph = parse_capsule_head(std::string_view{
            reinterpret_cast<const char*>(phead_data->data()), phead_data->size()});
        if (!ph) { // corrupt staging: drop it, the commit will be retried
            (void)::unlink(pending_head_path().c_str());
            if (has_pending)
                (void)::unlink(pending_path().c_str());
            return {};
        }
        if (has_pending) {
            auto pending = fs::read_file(pending_path().c_str());
            if (!pending)
                return std::unexpected(pending.error());
            if (crypto::ascon::hash256(fex::bytes{*pending}) != ph->hash) {
                (void)::unlink(pending_path().c_str());
                (void)::unlink(pending_head_path().c_str());
                return {};
            }
            auto parsed = inventory::parse(std::string_view{
                reinterpret_cast<const char*>(pending->data()), pending->size()});
            if (!parsed) {
                (void)::unlink(pending_path().c_str());
                (void)::unlink(pending_head_path().c_str());
                return {};
            }
            if (!apply_pending(*parsed, *ph))
                return std::unexpected(std::errc::io_error);
            return {};
        }
        // pending already renamed: finish if inventory.danl is the staged one
        auto inv_data = fs::read_file(inventory_path().c_str());
        if (inv_data
            && crypto::ascon::hash256(fex::bytes{*inv_data}) == ph->hash) {
            if (::rename(pending_head_path().c_str(), head_path().c_str()) != 0)
                return fs::failure();
            head_ = *ph;
            drop_consumed_assemblies();
        } else {
            (void)::unlink(pending_head_path().c_str());
        }
        return {};
    }

    // #9 steps 6-7, shared by commit and crash recovery; every write is
    // hash-verified and idempotent
    [[nodiscard]] bool apply_pending(const inventory::file& next,
                                     const capsule_head& ph) noexcept {
        // sources that must come from the old tree are read before the tree
        // mutates: a rename may remove the only copy before it is needed
        hash256_map<std::vector<u8>> from_tree;
        for (const auto& e : next.entries) {
            if (e.size == 0 || from_tree.contains(e.hash))
                continue;
            if (const auto it = assemblies_.find(e.hash);
                it != assemblies_.end() && it->second.assembled())
                continue;
            const auto old = hash_to_path_.find(e.hash);
            if (old == hash_to_path_.end())
                return false; // validated in step 4; recovery hits this only on loss
            auto data = fs::read_file((tree_dir() + '/' + old->second).c_str());
            if (!data || crypto::ascon::hash256(fex::bytes{*data}) != e.hash)
                return false;
            from_tree.emplace(e.hash, std::move(*data));
        }

        // write pass
        for (const auto& e : next.entries) {
            const auto target = tree_dir() + '/' + e.path;
            if (const auto st = fs::stat_of(target.c_str());
                st.kind == fs::entry_kind::file && st.size == e.size) {
                auto existing = fs::read_file(target.c_str());
                if (existing
                    && crypto::ascon::hash256(fex::bytes{*existing}) == e.hash)
                    continue; // already in place (idempotence)
            }
            fex::bytes source{};
            std::vector<u8> assembled_data;
            if (e.size != 0) {
                if (const auto it = assemblies_.find(e.hash);
                    it != assemblies_.end() && it->second.assembled()) {
                    auto data = fs::read_file(it->second.data_path().c_str());
                    if (!data
                        || crypto::ascon::hash256(fex::bytes{*data}) != e.hash)
                        return false;
                    assembled_data = std::move(*data);
                    source = fex::bytes{assembled_data};
                } else if (const auto ft = from_tree.find(e.hash); ft != from_tree.end()) {
                    source = fex::bytes{ft->second};
                } else {
                    return false;
                }
            }
            if (!fs::ensure_dirs(fs::dir_of(target)))
                return false;
            if (!fs::write_file_atomic(target, source))
                return false;
        }

        // delete pass: paths gone from the inventory, then empty directories
        hash_set<std::string> keep;
        for (const auto& e : next.entries)
            keep.emplace(e.path);
        std::vector<std::string> stale, dirs;
        const auto tree = tree_dir();
        if (!fs::walk(tree.c_str(),
            [&](std::string_view rel, const fs::info& st) -> std::expected<void, std::errc> {
                if (st.kind == fs::entry_kind::dir)
                    dirs.emplace_back(rel);
                else if (!keep.contains(std::string{rel}))
                    stale.emplace_back(rel);
                return {};
            }))
            return false;
        for (const auto& rel : stale)
            (void)::unlink((tree + '/' + rel).c_str());
        std::ranges::sort(dirs, [](const std::string& a, const std::string& b) {
            return a.size() > b.size();
        });
        for (const auto& d : dirs)
            (void)::rmdir((tree + '/' + d).c_str());

        // step 7: rename pending -> inventory, publish the new head
        if (::rename(pending_path().c_str(), inventory_path().c_str()) != 0)
            return false;
        if (::rename(pending_head_path().c_str(), head_path().c_str()) != 0)
            return false;
        head_ = ph;
        set_inventory(next);
        drop_consumed_assemblies();
        return true;
    }

    // assembled files now living in the tree (or being the inventory itself)
    // are consumed; an ongoing upload's files stay (#9)
    void drop_consumed_assemblies() noexcept {
        std::vector<hash256> gone;
        for (auto& [h, a] : assemblies_) {
            if (!a.assembled())
                continue;
            if (hash_to_path_.contains(h) || h == head_.hash) {
                a.discard();
                gone.push_back(h);
            }
        }
        for (const auto& h : gone)
            assemblies_.erase(h);
    }
}; // capsule

} // namespace fex::relay

#ifdef FEX_WITH_TESTS

#include <cstdlib>

TEST_SUITE("fex::relay") {

namespace fex_capsule_test {

inline std::vector<fex::u8> pattern(std::size_t n, fex::u8 salt = 0) {
    std::vector<fex::u8> data(n);
    for (std::size_t i = 0; i != n; ++i)
        data[i] = static_cast<fex::u8>((i * 31 + salt) & 0xff);
    return data;
}

inline fex::hash256 hash_of(const std::vector<fex::u8>& data) {
    return fex::crypto::ascon::hash256(fex::bytes{data});
}

inline void upload(fex::relay::capsule& c, const std::vector<fex::u8>& data) {
    using namespace fex;
    const auto h = hash_of(data);
    for (fex::u64 no = 0; no != wire::chunk_count(data.size()); ++no) {
        wire::put p{};
        p.file_size = data.size();
        p.chunk_no = no;
        std::copy(h.begin(), h.end(), p.file_hash);
        p.data = fex::bytes{data.data() + no * wire::chunk_data_size,
                               *wire::chunk_len(data.size(), no)};
        c.put_chunk(p);
    }
}

inline std::vector<fex::u8> text_bytes(const std::string& s) {
    return {s.begin(), s.end()};
}

inline fex::wire::poll poll_of(const fex::hash256& h) {
    fex::wire::poll p{};
    std::copy(h.begin(), h.end(), p.file_hash);
    return p;
}

inline fex::wire::commit commit_of(fex::u64 seq, const fex::hash256& h) {
    fex::wire::commit c{};
    c.seq = seq;
    std::copy(h.begin(), h.end(), c.inv_hash);
    return c;
}

} // namespace fex_capsule_test

SCENARIO("capsule: publish, commit, idempotence, get") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir = std::string{root} + "/cap";

    auto cap = relay::capsule::open(dir);
    REQUIRE(cap.has_value());
    CHECK(cap->head().seq == 0);
    CHECK(cap->head_msg().inv_size == 0);

    const auto a = pattern(2 * 1024 + 452);
    const auto ha = hash_of(a);
    inventory::file inv;
    inv.entries.push_back({ha, "docs/a.bin", a.size()});
    inv.entries.push_back({relay::empty_content_hash(), "empty.txt", 0});
    inv.entries.push_back({ha, "copy/a2.bin", a.size()}); // same content, second path
    const auto inv_text = inventory::to_danl(inv);
    const auto inv_bytes = text_bytes(inv_text);
    const auto hi = hash_of(inv_bytes);

    upload(*cap, a);
    CHECK(cap->poll_file(poll_of(ha)).status == wire::mstatus::ok);
    CHECK(cap->poll_file(poll_of(ha)).count == 0);
    CHECK(cap->poll_file(poll_of(hash_of(pattern(10, 9)))).status
          == wire::mstatus::not_found);
    upload(*cap, inv_bytes);

    REQUIRE(cap->commit(commit_of(1, hi)) == wire::mstatus::ok);
    CHECK(cap->head().seq == 1);
    CHECK(cap->head().hash == hi);
    CHECK(cap->head().size == inv_bytes.size());

    const auto tree = dir + "/tree";
    CHECK(*fs::read_file((tree + "/docs/a.bin").c_str()) == a);
    CHECK(*fs::read_file((tree + "/copy/a2.bin").c_str()) == a);
    CHECK(fs::stat_of((tree + "/empty.txt").c_str()).size == 0);
    CHECK(*fs::read_file((dir + "/inventory.danl").c_str()) == inv_bytes);
    CHECK(fs::stat_of((dir + "/pending.danl").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((dir + "/head.pending.dano").c_str()).kind
          == fs::entry_kind::missing);

    // get: file chunks and the inventory itself
    std::array<fex::u8, wire::chunk_data_size> buf;
    wire::get g{};
    g.chunk_no = 2;
    std::copy(ha.begin(), ha.end(), g.file_hash);
    auto got = cap->get_chunk(g, buf);
    REQUIRE(got.has_value());
    CHECK(*got == 452);
    CHECK(std::equal(buf.begin(), buf.begin() + 452, a.begin() + 2048));
    std::copy(hi.begin(), hi.end(), g.file_hash);
    g.chunk_no = 0;
    got = cap->get_chunk(g, buf);
    REQUIRE(got.has_value());
    CHECK(std::equal(buf.begin(), buf.begin() + *got, inv_bytes.begin()));
    g.chunk_no = 99;
    CHECK(cap->get_chunk(g, buf).error() == wire::mstatus::not_found);

    // idempotent re-commit; stale seq
    CHECK(cap->commit(commit_of(1, hi)) == wire::mstatus::ok);
    CHECK(cap->commit(commit_of(1, hash_of(pattern(1, 1)))) == wire::mstatus::stale_seq);
    CHECK(cap->commit(commit_of(0, hi)) == wire::mstatus::stale_seq);

    // a freshly re-opened capsule sees the same state; young junk survives
    REQUIRE(fs::write_file_atomic(tree + "/junk.bin",
                                  fex::bytes{a.data(), 10}).has_value());
    auto again = relay::capsule::open(dir);
    REQUIRE(again.has_value());
    CHECK(again->head().seq == 1);
    CHECK(again->head().hash == hi);
    CHECK(fs::stat_of((tree + "/junk.bin").c_str()).kind == fs::entry_kind::file);
    REQUIRE(::unlink((tree + "/junk.bin").c_str()) == 0);

    // second commit: rename a, drop the copy, add b -- the rename is fed from
    // the old tree, not from assembly
    const auto b = pattern(100, 5);
    const auto hb = hash_of(b);
    inventory::file inv2;
    inv2.entries.push_back({ha, "moved/a.bin", a.size()});
    inv2.entries.push_back({hb, "b.bin", b.size()});
    const auto inv2_bytes = text_bytes(inventory::to_danl(inv2));
    const auto hi2 = hash_of(inv2_bytes);
    upload(*again, b);
    upload(*again, inv2_bytes);
    REQUIRE(again->commit(commit_of(2, hi2)) == wire::mstatus::ok);
    CHECK(*fs::read_file((tree + "/moved/a.bin").c_str()) == a);
    CHECK(*fs::read_file((tree + "/b.bin").c_str()) == b);
    CHECK(fs::stat_of((tree + "/docs").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((tree + "/copy").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((tree + "/empty.txt").c_str()).kind == fs::entry_kind::missing);

    // empty inventory commit: the capsule empties, seq moves on
    const auto he = relay::empty_content_hash();
    REQUIRE(again->commit(commit_of(3, he)) == wire::mstatus::ok);
    CHECK(again->head().seq == 3);
    CHECK(again->head().size == 0);
    CHECK(fs::stat_of((tree + "/b.bin").c_str()).kind == fs::entry_kind::missing);

    REQUIRE(fs::remove_tree(root).has_value());
}

SCENARIO("capsule: commit failure arms") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir = std::string{root} + "/cap";
    auto cap = relay::capsule::open(dir);
    REQUIRE(cap.has_value());

    // inventory file not assembled
    CHECK(cap->commit(commit_of(1, hash_of(pattern(3, 3)))) == wire::mstatus::files_missing);

    // inventory references a file that was never uploaded
    inventory::file inv;
    inv.entries.push_back({hash_of(pattern(50, 7)), "missing.bin", 50});
    const auto inv_bytes = text_bytes(inventory::to_danl(inv));
    upload(*cap, inv_bytes);
    CHECK(cap->commit(commit_of(1, hash_of(inv_bytes))) == wire::mstatus::files_missing);

    // a size-0 entry must carry the hash of the empty string
    inventory::file inv2;
    inv2.entries.push_back({hash_of(pattern(1, 1)), "zero.txt", 0});
    const auto inv2_bytes = text_bytes(inventory::to_danl(inv2));
    upload(*cap, inv2_bytes);
    CHECK(cap->commit(commit_of(1, hash_of(inv2_bytes))) == wire::mstatus::files_missing);

    // an assembled file that is not a valid inventory -> internal
    const auto junk = text_bytes("{:hash \"zz\"\n");
    upload(*cap, junk);
    CHECK(cap->poll_file(poll_of(hash_of(junk))).status == wire::mstatus::ok);
    CHECK(cap->commit(commit_of(1, hash_of(junk))) == wire::mstatus::internal);

    REQUIRE(fs::remove_tree(root).has_value());
}

SCENARIO("capsule: crash recovery replays a staged commit") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir = std::string{root} + "/cap";

    const auto a = pattern(1500);
    const auto ha = hash_of(a);
    inventory::file inv1;
    inv1.entries.push_back({ha, "a.bin", a.size()});
    const auto inv1_bytes = text_bytes(inventory::to_danl(inv1));
    const auto hi1 = hash_of(inv1_bytes);
    {
        auto cap = relay::capsule::open(dir);
        REQUIRE(cap.has_value());
        upload(*cap, a);
        upload(*cap, inv1_bytes);
        REQUIRE(cap->commit(commit_of(1, hi1)) == wire::mstatus::ok);
    }

    // stage a second commit by hand: assembled b + pending files, no apply --
    // exactly the state a crash right after #9 step 5 leaves behind
    const auto b = pattern(3000, 9);
    const auto hb = hash_of(b);
    inventory::file inv2;
    inv2.entries.push_back({ha, "renamed/a.bin", a.size()}); // rename of a
    inv2.entries.push_back({hb, "b.bin", b.size()});
    const auto inv2_bytes = text_bytes(inventory::to_danl(inv2));
    const auto hi2 = hash_of(inv2_bytes);
    {
        auto asm_b = relay::assembly::start(dir + "/assembly", hb, b.size());
        REQUIRE(asm_b.has_value());
        for (fex::u64 no = 0; no != wire::chunk_count(b.size()); ++no) {
            REQUIRE(asm_b->put(no, fex::bytes{
                b.data() + no * wire::chunk_data_size,
                *wire::chunk_len(b.size(), no)}).has_value());
        }
        REQUIRE(asm_b->assembled());
        REQUIRE(fs::write_file_atomic(dir + "/pending.danl",
                                      fex::bytes{inv2_bytes}).has_value());
        relay::capsule_head ph;
        ph.seq = 2;
        ph.hash = hi2;
        ph.size = inv2_bytes.size();
        const auto ph_text = relay::to_dano(ph);
        REQUIRE(fs::write_file_atomic(dir + "/head.pending.dano",
            fex::bytes{reinterpret_cast<const fex::u8*>(ph_text.data()),
                          ph_text.size()}).has_value());
    }

    auto cap = relay::capsule::open(dir);
    REQUIRE(cap.has_value());
    CHECK(cap->head().seq == 2);
    CHECK(cap->head().hash == hi2);
    const auto tree = dir + "/tree";
    CHECK(*fs::read_file((tree + "/renamed/a.bin").c_str()) == a);
    CHECK(*fs::read_file((tree + "/b.bin").c_str()) == b);
    CHECK(fs::stat_of((tree + "/a.bin").c_str()).kind == fs::entry_kind::missing);
    CHECK(*fs::read_file((dir + "/inventory.danl").c_str()) == inv2_bytes);
    CHECK(fs::stat_of((dir + "/pending.danl").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((dir + "/head.pending.dano").c_str()).kind
          == fs::entry_kind::missing);

    // crash between the two renames of step 7: inventory renamed, head not
    relay::capsule_head ph3;
    ph3.seq = 3;
    ph3.hash = hi2;
    ph3.size = inv2_bytes.size();
    const auto ph3_text = relay::to_dano(ph3);
    REQUIRE(fs::write_file_atomic(dir + "/head.pending.dano",
        fex::bytes{reinterpret_cast<const fex::u8*>(ph3_text.data()),
                      ph3_text.size()}).has_value());
    auto cap3 = relay::capsule::open(dir);
    REQUIRE(cap3.has_value());
    CHECK(cap3->head().seq == 3);
    CHECK(fs::stat_of((dir + "/head.pending.dano").c_str()).kind
          == fs::entry_kind::missing);

    // a stray pending.danl without a staged head is dropped
    REQUIRE(fs::write_file_atomic(dir + "/pending.danl",
                                  fex::bytes{inv1_bytes}).has_value());
    auto cap4 = relay::capsule::open(dir);
    REQUIRE(cap4.has_value());
    CHECK(cap4->head().seq == 3);
    CHECK(fs::stat_of((dir + "/pending.danl").c_str()).kind == fs::entry_kind::missing);

    REQUIRE(fs::remove_tree(root).has_value());
}

SCENARIO("capsule: enforce deletes only stale extraneous files") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir = std::string{root} + "/cap";

    const auto a = pattern(100);
    inventory::file inv;
    inv.entries.push_back({hash_of(a), "a.bin", a.size()});
    const auto inv_bytes = text_bytes(inventory::to_danl(inv));
    {
        auto cap = relay::capsule::open(dir);
        REQUIRE(cap.has_value());
        upload(*cap, a);
        upload(*cap, inv_bytes);
        REQUIRE(cap->commit(commit_of(1, hash_of(inv_bytes))) == wire::mstatus::ok);
    }
    const auto tree = dir + "/tree";
    // one young stray, one two days old
    const auto junk = pattern(10, 1);
    REQUIRE(fs::write_file_atomic(tree + "/young.bin", fex::bytes{junk}).has_value());
    REQUIRE(fs::write_file_atomic(tree + "/old.bin", fex::bytes{junk}).has_value());
    const auto two_days_ago =
        static_cast<::time_t>((fs::now_ns() - 48ull * 3600 * 1'000'000'000) / 1'000'000'000);
    const ::timespec times[2] = {{two_days_ago, 0}, {two_days_ago, 0}};
    REQUIRE(::utimensat(AT_FDCWD, (tree + "/old.bin").c_str(), times, 0) == 0);

    auto cap = relay::capsule::open(dir); // startup enforce runs here
    REQUIRE(cap.has_value());
    CHECK(fs::stat_of((tree + "/old.bin").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((tree + "/young.bin").c_str()).kind == fs::entry_kind::file);
    CHECK(fs::stat_of((tree + "/a.bin").c_str()).kind == fs::entry_kind::file);

    REQUIRE(fs::remove_tree(root).has_value());
}

SCENARIO("capsule: mismatch is terminal until a new put") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir = std::string{root} + "/cap";
    auto cap = relay::capsule::open(dir);
    REQUIRE(cap.has_value());

    const auto good = pattern(1500);
    const auto h = hash_of(good);
    auto bad = good;
    bad[0] ^= 0xff;
    // upload wrong bytes under the right hash -> mismatch on completion
    for (fex::u64 no = 0; no != 2; ++no) {
        wire::put p{};
        p.file_size = bad.size();
        p.chunk_no = no;
        std::copy(h.begin(), h.end(), p.file_hash);
        p.data = fex::bytes{bad.data() + no * wire::chunk_data_size,
                               *wire::chunk_len(bad.size(), no)};
        cap->put_chunk(p);
    }
    CHECK(cap->poll_file(poll_of(h)).status == wire::mstatus::hash_mismatch);
    CHECK(cap->poll_file(poll_of(h)).status == wire::mstatus::hash_mismatch);
    // the file starts over with the next put
    upload(*cap, good);
    CHECK(cap->poll_file(poll_of(h)).status == wire::mstatus::ok);
    CHECK(cap->poll_file(poll_of(h)).count == 0);

    REQUIRE(fs::remove_tree(root).has_value());
}

}

#endif
