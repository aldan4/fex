// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// A capsule (#6) and the commit transaction (#9).
//
// The content is not here: every file and every inventory lives in the
// relay-wide object store (relay/objects.hpp), under the hash of its own
// bytes. What a capsule owns is who is publishing what, and the machinery of
// getting there:
//
//   head.dano    -- {:seq N :hash "..." :size N}, naming the current inventory
//   pending.danl -- that inventory while a commit is staged
//   assembly/    -- uploads in progress, one file a hash plus its range map
//
// So a capsule holds a sequence number and a pointer, and the objects it
// points at are shared with every other capsule that names the same bytes.
//
// On top of the spec's layout one extra file exists during a commit:
// head.pending.dano -- the future head.dano written next to pending.danl.
// #9's recovery must replay steps 6-7 after a crash, and that needs the
// commit's seq, which lives nowhere else on disk mid-transaction. States:
//   pending.danl + head.pending.dano, hashes agree -> replay steps 6-7
//   pending.danl alone            -> the head was never staged; drop it
//   head.pending.dano alone       -> finish if its objects are all stored,
//                                    otherwise a stale leftover; drop it

#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
#include <format>
#include <string>
#include <string_view>
#include <vector>

#include <dano/dano.hpp>

#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>

#include <fex/crypto.hpp>
#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/inventory.hpp>
#include <fex/relay/assembly.hpp>
#include <fex/relay/objects.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::relay {

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
    store* objects_ = nullptr;
    std::string dir_;
    capsule_head head_{}; // seq 0 + zero hash = never published (#6)
    inventory::file inv_; // the head's inventory: what this capsule pins
    hash256_map<assembly> assemblies_;
    hash256_set failed_; // terminal mismatches

public:

    struct gaps_reply {
        wire::mstatus status;
        std::size_t count;
        std::array<wire::range, wire::gaps_max_count> ranges;
    }; // gaps_reply

    [[nodiscard]] const capsule_head& head() const noexcept { return head_; }
    [[nodiscard]] const std::string& dir() const noexcept { return dir_; }
    [[nodiscard]] const inventory::file& inventory() const noexcept { return inv_; }

    [[nodiscard]] static std::expected<capsule, std::errc>
    open(std::string_view dir, store& objects) noexcept {
        capsule c;
        c.objects_ = &objects;
        c.dir_.assign(dir);
        if (auto r = fs::ensure_dirs(c.assembly_dir()); !r)
            return std::unexpected(r.error());
        if (auto r = c.load_head(); !r)
            return std::unexpected(r.error());
        c.resume_assemblies();
        if (auto r = c.recover(); !r)
            return std::unexpected(r.error());
        c.load_inventory();
        return c;
    }

    [[nodiscard]] wire::head head_msg() const noexcept {
        wire::head m{};
        m.seq = head_.seq;
        m.inv_size = head_.size;
        std::copy(head_.hash.begin(), head_.hash.end(), m.inv_hash);
        return m;
    }

    // put (#5.2): never answered; errors surface later through poll
    void put_chunk(const wire::put& p) noexcept {
        hash256 h;
        std::copy(p.file_hash, p.file_hash + 32, h.begin());
        if (objects_->contains(h))
            return; // the relay already holds these bytes
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

    // poll -> gaps (#5.2): ok when the content is stored, or assembled here and
    // waiting for the commit that will store it
    [[nodiscard]] gaps_reply poll_file(const wire::poll& p) noexcept {
        hash256 h;
        std::copy(p.file_hash, p.file_hash + 32, h.begin());
        gaps_reply reply{};
        if (h == empty_content_hash() || objects_->contains(h)) {
            reply.status = wire::mstatus::ok;
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

        // step 2: the inventory is assembled or already stored. The empty one
        // is neither and needs to be: no bytes at all is nothing to upload.
        std::vector<u8> inv_bytes;
        if (h == empty_content_hash()) {
            // an empty capsule: inv_size 0, and the hash of nothing
        } else if (const auto it = assemblies_.find(h);
                   it != assemblies_.end() && it->second.assembled()) {
            auto data = fs::read_file(it->second.data_path().c_str());
            if (!data)
                return wire::mstatus::internal;
            inv_bytes = std::move(*data);
        } else if (objects_->contains(h)) {
            auto data = objects_->read(h);
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

        // step 4: every file of the inventory is assembled or already stored.
        // A record of size zero names no object: its hash is the hash of the
        // empty string, and the client materializes the file itself (#10.2).
        for (const auto& e : parsed->entries) {
            if (e.size == 0) {
                if (e.hash != empty_content_hash())
                    return wire::mstatus::files_missing;
                continue;
            }
            if (objects_->contains(e.hash))
                continue;
            const auto it = assemblies_.find(e.hash);
            if (it == assemblies_.end() || !it->second.assembled()
                || it->second.file_size() != e.size)
                return wire::mstatus::files_missing;
        }

        // step 5: stage the new inventory verbatim + the future head. From here
        // on the objects it names are pinned, so nothing collects them out from
        // under the commit.
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

    // #6: what garbage collection must not take. The head's inventory and
    // every object it names; and, while a commit is staged, the pending
    // inventory and everything it names too -- an object a commit is about to
    // depend on is not garbage merely because no head points at it yet.
    void pins(hash256_set& out) const {
        if (head_.seq != 0)
            out.insert(head_.hash);
        for (const auto& e : inv_.entries)
            out.insert(e.hash);
        auto pending = fs::read_file(pending_path().c_str());
        if (!pending)
            return;
        out.insert(crypto::ascon::hash256(fex::bytes{*pending}));
        auto parsed = inventory::parse(std::string_view{
            reinterpret_cast<const char*>(pending->data()), pending->size()});
        if (!parsed)
            return;
        for (const auto& e : parsed->entries)
            out.insert(e.hash);
    }

private:

    [[nodiscard]] std::string assembly_dir() const { return dir_ + "/assembly"; }
    [[nodiscard]] std::string head_path() const { return dir_ + "/head.dano"; }
    [[nodiscard]] std::string pending_path() const { return dir_ + "/pending.danl"; }
    [[nodiscard]] std::string pending_head_path() const { return dir_ + "/head.pending.dano"; }

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

    // the head names an object, and that object is the inventory. A missing one
    // is not fatal here: #6 has the startup check report it, and every get for
    // it answers not_found until it comes back.
    void load_inventory() noexcept {
        inv_ = {};
        if (head_.seq == 0 || head_.hash == empty_content_hash())
            return;
        auto data = objects_->read(head_.hash);
        if (!data)
            return;
        auto parsed = inventory::parse(std::string_view{
            reinterpret_cast<const char*>(data->data()), data->size()});
        if (parsed)
            inv_ = std::move(*parsed);
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
            // step 7 renames the head before dropping pending.danl, so a
            // pending left alone belongs either side of a commit that is over
            (void)::unlink(pending_path().c_str());
            return {};
        }
        auto phead_data = fs::read_file(pending_head_path().c_str());
        if (!phead_data)
            return std::unexpected(phead_data.error());
        auto ph = parse_capsule_head(std::string_view{
            reinterpret_cast<const char*>(phead_data->data()), phead_data->size()});
        if (!ph || ph->seq <= head_.seq) { // corrupt or overtaken: drop the staging
            (void)::unlink(pending_head_path().c_str());
            (void)::unlink(pending_path().c_str());
            return {};
        }
        std::vector<u8> inv_bytes;
        if (has_pending) {
            auto pending = fs::read_file(pending_path().c_str());
            if (!pending)
                return std::unexpected(pending.error());
            inv_bytes = std::move(*pending);
        } else if (ph->hash != empty_content_hash()) {
            auto stored = objects_->read(ph->hash);
            if (!stored) { // nothing to replay from
                (void)::unlink(pending_head_path().c_str());
                return {};
            }
            inv_bytes = std::move(*stored);
        }
        if (crypto::ascon::hash256(fex::bytes{inv_bytes}) != ph->hash) {
            (void)::unlink(pending_path().c_str());
            (void)::unlink(pending_head_path().c_str());
            return {};
        }
        auto parsed = inventory::parse(std::string_view{
            reinterpret_cast<const char*>(inv_bytes.data()), inv_bytes.size()});
        if (!parsed) {
            (void)::unlink(pending_path().c_str());
            (void)::unlink(pending_head_path().c_str());
            return {};
        }
        if (!apply_pending(*parsed, *ph))
            return std::unexpected(std::errc::io_error);
        return {};
    }

    // #9 steps 6-7, shared by commit and crash recovery. Step 6 only ever adds
    // objects and step 7 only ever replaces one file with another, so replaying
    // the pair after a crash at any point lands in the same place.
    [[nodiscard]] bool apply_pending(const inventory::file& next,
                                     const capsule_head& ph) noexcept {
        // the inventory object first: the head about to be published names it
        if (!store_object(ph.hash))
            return false;
        for (const auto& e : next.entries) {
            if (e.size == 0)
                continue;
            if (!store_object(e.hash))
                return false;
        }
        // step 7
        if (::rename(pending_head_path().c_str(), head_path().c_str()) != 0)
            return false;
        (void)::unlink(pending_path().c_str());
        head_ = ph;
        inv_ = next;
        drop_consumed_assemblies();
        return true;
    }

    // one object into the store, from the assembly area if it is not there yet
    [[nodiscard]] bool store_object(const hash256& h) noexcept {
        if (h == empty_content_hash() || objects_->contains(h))
            return true;
        const auto it = assemblies_.find(h);
        if (it == assemblies_.end() || !it->second.assembled())
            return false;
        return objects_->adopt(it->second.data_path(), h);
    }

    // an upload whose content the store now holds is finished with; one still
    // in flight stays where it is (#9)
    void drop_consumed_assemblies() noexcept {
        std::vector<hash256> gone;
        for (auto& [h, a] : assemblies_) {
            if (!a.assembled() || !objects_->contains(h))
                continue;
            a.discard();
            gone.push_back(h);
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

inline fex::wire::get get_of(const fex::hash256& h, fex::u64 chunk_no) {
    fex::wire::get g{};
    g.chunk_no = chunk_no;
    std::copy(h.begin(), h.end(), g.file_hash);
    return g;
}

// backdate an object so the day-old rules of #6 can be reached in a test
inline void age(const std::string& path) {
    const auto then = static_cast<::time_t>(
        (fex::fs::now_ns() - 48ull * 3600 * 1'000'000'000) / 1'000'000'000);
    const ::timespec times[2] = {{then, 0}, {then, 0}};
    REQUIRE(::utimensat(AT_FDCWD, path.c_str(), times, 0) == 0);
}

} // namespace fex_capsule_test

SCENARIO("capsule: publish, commit, and the objects it leaves") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string base{root};
    const std::string dir = base + "/capsules/alice";
    auto objects = relay::store::open(base + "/objects");
    REQUIRE(objects.has_value());
    auto cap = relay::capsule::open(dir, *objects);
    REQUIRE(cap.has_value());
    CHECK(cap->head().seq == 0);

    const auto a = pattern(2500);
    const auto ha = hash_of(a);
    inventory::file inv;
    inv.entries.push_back({ha, "docs/a.bin", a.size()});
    inv.entries.push_back({relay::empty_content_hash(), "empty.txt", 0});
    inv.entries.push_back({ha, "copy/a2.bin", a.size()}); // same content, second path
    const auto inv_bytes = text_bytes(inventory::to_danl(inv));
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

    // #6: content lives under the hash of its own bytes, and identical content
    // lives there once -- two paths named `a` and there is one object
    CHECK(*objects->read(ha) == a);
    CHECK(*objects->read(hi) == inv_bytes);
    CHECK(objects->names().size() == 2);
    // a record of size zero names no object: the client makes that file itself
    CHECK(!objects->contains(relay::empty_content_hash()));
    // nothing is laid out by path any more, and the capsule keeps only a pointer
    CHECK(fs::stat_of((dir + "/tree").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((dir + "/inventory.danl").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((dir + "/pending.danl").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((dir + "/head.pending.dano").c_str()).kind
          == fs::entry_kind::missing);
    CHECK(fs::stat_of((dir + "/head.dano").c_str()).kind == fs::entry_kind::file);

    // get is the store's business: file chunks and the inventory alike
    std::array<fex::u8, wire::chunk_data_size> buf;
    const auto now = fs::now_ns();
    auto got = objects->get_chunk(get_of(ha, 2), buf, now);
    REQUIRE(got.has_value());
    CHECK(*got == 452);
    CHECK(std::equal(buf.begin(), buf.begin() + 452, a.begin() + 2048));
    got = objects->get_chunk(get_of(hi, 0), buf, now);
    REQUIRE(got.has_value());
    CHECK(std::equal(buf.begin(), buf.begin() + *got, inv_bytes.begin()));
    CHECK(objects->get_chunk(get_of(hi, 99), buf, now).error()
          == wire::mstatus::not_found);
    CHECK(objects->get_chunk(get_of(hash_of(pattern(7, 7)), 0), buf, now).error()
          == wire::mstatus::not_found);

    // idempotent re-commit; stale seq
    CHECK(cap->commit(commit_of(1, hi)) == wire::mstatus::ok);
    CHECK(cap->commit(commit_of(1, hash_of(pattern(1, 1)))) == wire::mstatus::stale_seq);
    CHECK(cap->commit(commit_of(0, hi)) == wire::mstatus::stale_seq);

    // a freshly re-opened capsule reads its inventory back out of the store
    auto again = relay::capsule::open(dir, *objects);
    REQUIRE(again.has_value());
    CHECK(again->head().seq == 1);
    CHECK(again->head().hash == hi);
    CHECK(again->inventory().entries.size() == 3);

    // second commit: rename a, drop the copy, add b. The rename uploads
    // nothing -- a's object is already stored, which is what addressing content
    // by its hash buys -- so only b travels.
    const auto b = pattern(100, 5);
    const auto hb = hash_of(b);
    inventory::file inv2;
    inv2.entries.push_back({hb, "b.bin", b.size()});
    inv2.entries.push_back({ha, "moved/a.bin", a.size()});
    const auto inv2_bytes = text_bytes(inventory::to_danl(inv2));
    const auto hi2 = hash_of(inv2_bytes);
    upload(*again, b);
    upload(*again, inv2_bytes);
    REQUIRE(again->commit(commit_of(2, hi2)) == wire::mstatus::ok);
    CHECK(objects->contains(ha));
    CHECK(objects->contains(hb));
    // #9: the objects of the commit before remain until collection, so a get
    // that raced the commit still finds what it was told to ask for
    CHECK(objects->contains(hi));

    // an empty inventory: the capsule empties and seq moves on. No bytes at all
    // is nothing to upload and nothing to store.
    const auto he = relay::empty_content_hash();
    REQUIRE(again->commit(commit_of(3, he)) == wire::mstatus::ok);
    CHECK(again->head().seq == 3);
    CHECK(again->head().size == 0);
    CHECK(again->inventory().entries.empty());
    CHECK(!objects->contains(he));

    REQUIRE(fs::remove_tree(base).has_value());
}

SCENARIO("capsule: commit failure arms") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string base{root};
    auto objects = relay::store::open(base + "/objects");
    REQUIRE(objects.has_value());
    auto cap = relay::capsule::open(base + "/capsules/alice", *objects);
    REQUIRE(cap.has_value());

    // the inventory itself is neither assembled nor stored
    CHECK(cap->commit(commit_of(1, hash_of(pattern(3, 3)))) == wire::mstatus::files_missing);

    // the inventory names a file that was never uploaded
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

    // nothing of a refused commit reached the store
    CHECK(objects->names().empty());

    REQUIRE(fs::remove_tree(base).has_value());
}

SCENARIO("capsule: crash recovery replays a staged commit") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string base{root};
    const std::string dir = base + "/capsules/alice";
    auto objects = relay::store::open(base + "/objects");
    REQUIRE(objects.has_value());

    const auto a = pattern(1500);
    const auto ha = hash_of(a);
    inventory::file inv1;
    inv1.entries.push_back({ha, "a.bin", a.size()});
    const auto inv1_bytes = text_bytes(inventory::to_danl(inv1));
    const auto hi1 = hash_of(inv1_bytes);
    {
        auto cap = relay::capsule::open(dir, *objects);
        REQUIRE(cap.has_value());
        upload(*cap, a);
        upload(*cap, inv1_bytes);
        REQUIRE(cap->commit(commit_of(1, hi1)) == wire::mstatus::ok);
    }

    // stage a second commit by hand: assembled b + both pending files, nothing
    // applied -- exactly the state a crash right after #9 step 5 leaves behind
    const auto b = pattern(3000, 9);
    const auto hb = hash_of(b);
    inventory::file inv2;
    inv2.entries.push_back({ha, "renamed/a.bin", a.size()}); // a rename of a
    inv2.entries.push_back({hb, "b.bin", b.size()});
    const auto inv2_bytes = text_bytes(inventory::to_danl(inv2));
    const auto hi2 = hash_of(inv2_bytes);
    {
        for (const auto& blob : {b, inv2_bytes}) {
            auto staged = relay::assembly::start(dir + "/assembly", hash_of(blob),
                                                 blob.size());
            REQUIRE(staged.has_value());
            for (fex::u64 no = 0; no != wire::chunk_count(blob.size()); ++no) {
                REQUIRE(staged->put(no, fex::bytes{
                    blob.data() + no * wire::chunk_data_size,
                    *wire::chunk_len(blob.size(), no)}).has_value());
            }
            REQUIRE(staged->assembled());
        }
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

    auto cap = relay::capsule::open(dir, *objects);
    REQUIRE(cap.has_value());
    CHECK(cap->head().seq == 2);
    CHECK(cap->head().hash == hi2);
    CHECK(objects->contains(hb));
    CHECK(objects->contains(hi2));
    CHECK(objects->contains(ha)); // the rename needed no new object
    CHECK(fs::stat_of((dir + "/pending.danl").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((dir + "/head.pending.dano").c_str()).kind
          == fs::entry_kind::missing);
    CHECK(fs::stat_of((dir + "/assembly/" + to_hex(fex::bytes{hb})).c_str()).kind
          == fs::entry_kind::missing); // consumed by the commit

    // a crash inside step 7, after the objects moved and before the head did:
    // the staged head alone is enough to finish, since its inventory is stored
    relay::capsule_head ph3;
    ph3.seq = 3;
    ph3.hash = hi2;
    ph3.size = inv2_bytes.size();
    const auto ph3_text = relay::to_dano(ph3);
    REQUIRE(fs::write_file_atomic(dir + "/head.pending.dano",
        fex::bytes{reinterpret_cast<const fex::u8*>(ph3_text.data()),
                      ph3_text.size()}).has_value());
    auto cap3 = relay::capsule::open(dir, *objects);
    REQUIRE(cap3.has_value());
    CHECK(cap3->head().seq == 3);
    CHECK(fs::stat_of((dir + "/head.pending.dano").c_str()).kind
          == fs::entry_kind::missing);

    // a stray pending.danl without a staged head belongs to a commit that is
    // over either way, and is dropped
    REQUIRE(fs::write_file_atomic(dir + "/pending.danl",
                                  fex::bytes{inv1_bytes}).has_value());
    auto cap4 = relay::capsule::open(dir, *objects);
    REQUIRE(cap4.has_value());
    CHECK(cap4->head().seq == 3);
    CHECK(fs::stat_of((dir + "/pending.danl").c_str()).kind == fs::entry_kind::missing);

    // and a staged head the current one has already overtaken is a leftover
    relay::capsule_head stale;
    stale.seq = 1;
    stale.hash = hi1;
    stale.size = inv1_bytes.size();
    const auto stale_text = relay::to_dano(stale);
    REQUIRE(fs::write_file_atomic(dir + "/head.pending.dano",
        fex::bytes{reinterpret_cast<const fex::u8*>(stale_text.data()),
                      stale_text.size()}).has_value());
    auto cap5 = relay::capsule::open(dir, *objects);
    REQUIRE(cap5.has_value());
    CHECK(cap5->head().seq == 3);
    CHECK(fs::stat_of((dir + "/head.pending.dano").c_str()).kind
          == fs::entry_kind::missing);

    REQUIRE(fs::remove_tree(base).has_value());
}

SCENARIO("store: collection takes what nothing pins") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string base{root};
    const std::string dir = base + "/capsules/alice";
    auto objects = relay::store::open(base + "/objects");
    REQUIRE(objects.has_value());
    auto cap = relay::capsule::open(dir, *objects);
    REQUIRE(cap.has_value());

    const auto a = pattern(400);
    const auto ha = hash_of(a);
    inventory::file inv1;
    inv1.entries.push_back({ha, "a.bin", a.size()});
    const auto inv1_bytes = text_bytes(inventory::to_danl(inv1));
    const auto hi1 = hash_of(inv1_bytes);
    upload(*cap, a);
    upload(*cap, inv1_bytes);
    REQUIRE(cap->commit(commit_of(1, hi1)) == wire::mstatus::ok);

    // publish again without a: its object is now what no head names
    const auto b = pattern(700, 3);
    const auto hb = hash_of(b);
    inventory::file inv2;
    inv2.entries.push_back({hb, "b.bin", b.size()});
    const auto inv2_bytes = text_bytes(inventory::to_danl(inv2));
    const auto hi2 = hash_of(inv2_bytes);
    upload(*cap, b);
    upload(*cap, inv2_bytes);
    REQUIRE(cap->commit(commit_of(2, hi2)) == wire::mstatus::ok);

    hash256_set pinned;
    cap->pins(pinned);
    CHECK(pinned.contains(hi2));
    CHECK(pinned.contains(hb));
    CHECK(!pinned.contains(hi1));
    CHECK(!pinned.contains(ha));

    // #6: nothing younger than a day is taken, pinned or not -- an upload that
    // finished a moment ago is waiting for the commit that will pin it
    CHECK(objects->collect(pinned, fs::now_ns()) == 0);
    CHECK(objects->contains(ha));

    age(objects->path_of(ha));
    age(objects->path_of(hi1));
    age(objects->path_of(hb));
    age(objects->path_of(hi2));
    CHECK(objects->collect(pinned, fs::now_ns()) == 2);
    CHECK(!objects->contains(ha));
    CHECK(!objects->contains(hi1));
    CHECK(objects->contains(hb)); // pinned, however old
    CHECK(objects->contains(hi2));

    // an object that is not what its name says is neither served nor kept
    REQUIRE(fs::write_file_atomic(objects->path_of(hb),
                                  fex::bytes{pattern(700, 4)}).has_value());
    age(objects->path_of(hb));
    std::array<fex::u8, wire::chunk_data_size> buf;
    CHECK(objects->get_chunk(get_of(hb, 0), buf, fs::now_ns()).error()
          == wire::mstatus::not_found);
    CHECK(!objects->contains(hb));

    // #6: a pinned object that has gone is reported, not repaired
    CHECK(objects->missing(pinned) == 1);

    REQUIRE(fs::remove_tree(base).has_value());
}

SCENARIO("capsule: mismatch is terminal until a new put") {
    using namespace fex;
    using namespace fex_capsule_test;
    char tmpl[] = "/tmp/fex-cap-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string base{root};
    auto objects = relay::store::open(base + "/objects");
    REQUIRE(objects.has_value());
    auto cap = relay::capsule::open(base + "/capsules/alice", *objects);
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
    // nothing that failed its hash ever reached the store
    CHECK(objects->names().empty());
    // the file starts over with the next put
    upload(*cap, good);
    CHECK(cap->poll_file(poll_of(h)).status == wire::mstatus::ok);
    CHECK(cap->poll_file(poll_of(h)).count == 0);

    REQUIRE(fs::remove_tree(base).has_value());
}

}

#endif
