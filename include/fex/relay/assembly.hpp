// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Assembly zone (#5.1, #5.2, #6): one in-progress file per hash. On disk:
//   <dir>/<hex64>       data, sized to file_size from the first put
//   <dir>/<hex64>.map   filled chunk ranges, persisted on poll
// data + map = building; data alone = assembled (verified, awaiting commit).

#include <algorithm>
#include <array>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include <fex/crypto.hpp>
#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::relay {

class assembly {
    std::string data_path_;
    std::string map_path_;
    hash256 hash_{};
    u64 file_size_ = 0;
    std::vector<wire::range> filled_; // sorted, disjoint, inclusive chunk ranges
    bool assembled_ = false;

public:

    enum struct put_result { building, assembled, mismatch };

    assembly() = default;

    [[nodiscard]] u64 file_size() const noexcept { return file_size_; }
    [[nodiscard]] bool assembled() const noexcept { return assembled_; }
    [[nodiscard]] const std::string& data_path() const noexcept { return data_path_; }

    // first put of a file: creates the data file sized to file_size; an existing
    // assembly with another file_size is thrown away and started over
    [[nodiscard]] static std::expected<assembly, std::errc>
    start(std::string_view dir, const hash256& hash, u64 file_size) noexcept {
        if (file_size == 0)
            return std::unexpected(std::errc::invalid_argument);
        assembly a;
        a.init_paths(dir, hash);
        a.hash_ = hash;
        a.file_size_ = file_size;
        const int fd = ::open(a.data_path_.c_str(),
                              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0)
            return fs::failure();
        if (::ftruncate(fd, static_cast<off_t>(file_size)) != 0) {
            const auto e = fs::last_errc();
            ::close(fd);
            return std::unexpected(e);
        }
        ::close(fd);
        if (auto p = a.persist_map(); !p)
            return std::unexpected(p.error());
        return a;
    }

    // startup recovery from the files on disk
    [[nodiscard]] static std::expected<assembly, std::errc>
    resume(std::string_view dir, const hash256& hash) noexcept {
        assembly a;
        a.init_paths(dir, hash);
        a.hash_ = hash;
        const auto st = fs::stat_of(a.data_path_.c_str());
        if (st.kind != fs::entry_kind::file || st.size == 0)
            return std::unexpected(std::errc::no_such_file_or_directory);
        a.file_size_ = st.size;
        const auto map_st = fs::stat_of(a.map_path_.c_str());
        if (map_st.kind == fs::entry_kind::missing) {
            a.assembled_ = true;
            return a;
        }
        auto map = fs::read_file(a.map_path_.c_str());
        if (!map)
            return std::unexpected(map.error());
        if (map->size() < 8 || (map->size() - 8) % 8 != 0)
            return std::unexpected(std::errc::illegal_byte_sequence);
        const u64 count = wire::load_u64(map->data());
        if (map->size() != 8 + 8 * count)
            return std::unexpected(std::errc::illegal_byte_sequence);
        a.filled_.reserve(count);
        for (u64 i = 0; i != count; ++i) {
            wire::range r;
            r.from = wire::load_u32(map->data() + 8 + 8 * i);
            r.to = wire::load_u32(map->data() + 8 + 8 * i + 4);
            a.filled_.push_back(r);
        }
        return a;
    }

    // #5.1: data length was already validated against (file_size, chunk_no) by
    // the wire decoder; put is idempotent
    [[nodiscard]] std::expected<put_result, std::errc>
    put(u64 chunk_no, fex::bytes data) noexcept {
        if (assembled_)
            return put_result::assembled;
        const int fd = ::open(data_path_.c_str(), O_WRONLY | O_CLOEXEC);
        if (fd < 0)
            return fs::failure();
        std::size_t off = 0;
        while (off != data.size()) {
            const auto n = ::pwrite(fd, data.data() + off, data.size() - off,
                                    static_cast<off_t>(chunk_no * wire::chunk_data_size + off));
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                const auto e = fs::last_errc();
                ::close(fd);
                return std::unexpected(e);
            }
            off += static_cast<std::size_t>(n);
        }
        ::close(fd);
        mark_filled(static_cast<u32>(chunk_no));
        if (!complete())
            return put_result::building;
        // every range filled -> verify the whole file (#5.2)
        auto whole = fs::read_file(data_path_.c_str());
        if (!whole)
            return std::unexpected(whole.error());
        if (crypto::ascon::hash256(fex::bytes{*whole}) == hash_) {
            if (::unlink(map_path_.c_str()) != 0 && errno != ENOENT)
                return fs::failure();
            assembled_ = true;
            filled_.clear();
            return put_result::assembled;
        }
        // mismatch is terminal: both files go away, the file starts over (#5.2)
        (void)::unlink(data_path_.c_str());
        (void)::unlink(map_path_.c_str());
        return put_result::mismatch;
    }

    // first <= out.size() missing ranges, in ascending chunk order
    [[nodiscard]] std::size_t gaps(std::span<wire::range> out) const noexcept {
        if (assembled_ || out.empty())
            return 0;
        const u64 chunks = wire::chunk_count(file_size_);
        std::size_t n = 0;
        u64 next = 0; // first chunk not yet known to be filled
        for (const auto& r : filled_) {
            if (next < r.from) {
                out[n++] = wire::range{static_cast<u32>(next), r.from - 1};
                if (n == out.size())
                    return n;
            }
            next = u64{r.to} + 1;
        }
        if (next < chunks)
            out[n++] = wire::range{static_cast<u32>(next), static_cast<u32>(chunks - 1)};
        return n;
    }

    [[nodiscard]] std::expected<void, std::errc> persist_map() const noexcept {
        if (assembled_)
            return {};
        std::vector<u8> map(8 + 8 * filled_.size());
        wire::store_u64(map.data(), filled_.size());
        for (std::size_t i = 0; i != filled_.size(); ++i) {
            wire::store_u32(map.data() + 8 + 8 * i, filled_[i].from);
            wire::store_u32(map.data() + 8 + 8 * i + 4, filled_[i].to);
        }
        return fs::write_file_atomic(map_path_, fex::bytes{map});
    }

    // removes both files from disk (after a commit consumed the content)
    void discard() noexcept {
        (void)::unlink(data_path_.c_str());
        (void)::unlink(map_path_.c_str());
    }

private:

    void init_paths(std::string_view dir, const hash256& hash) {
        data_path_.assign(dir);
        if (!data_path_.empty() && data_path_.back() != '/')
            data_path_ += '/';
        data_path_ += to_hex(fex::bytes{hash});
        map_path_ = data_path_ + ".map";
    }

    [[nodiscard]] bool complete() const noexcept {
        return filled_.size() == 1 && filled_[0].from == 0
            && u64{filled_[0].to} == wire::chunk_count(file_size_) - 1;
    }

    void mark_filled(u32 c) noexcept {
        // find the first range ending at or after c - 1 and merge around it
        std::size_t i = 0;
        while (i != filled_.size() && (u64{filled_[i].to} + 1) < c)
            ++i;
        if (i == filled_.size()) {
            filled_.push_back(wire::range{c, c});
            return;
        }
        if (c + 1 < filled_[i].from) { // strictly before, no touch
            filled_.insert(filled_.begin() + static_cast<std::ptrdiff_t>(i),
                           wire::range{c, c});
            return;
        }
        if (c >= filled_[i].from && c <= filled_[i].to)
            return; // already filled
        filled_[i].from = std::min(filled_[i].from, c);
        filled_[i].to = std::max(filled_[i].to, c);
        // the extension may have bridged the gap to the next range
        if (i + 1 != filled_.size() && u64{filled_[i].to} + 1 >= filled_[i + 1].from) {
            filled_[i].to = std::max(filled_[i].to, filled_[i + 1].to);
            filled_.erase(filled_.begin() + static_cast<std::ptrdiff_t>(i) + 1);
        }
    }
}; // assembly

} // namespace fex::relay

#ifdef FEX_WITH_TESTS

#include <cstdlib>

TEST_SUITE("fex::relay") {

namespace fex_assembly_test {

inline std::vector<fex::u8> pattern(std::size_t n) {
    std::vector<fex::u8> data(n);
    for (std::size_t i = 0; i != n; ++i)
        data[i] = static_cast<fex::u8>((i * 7 + 3) & 0xff);
    return data;
}

} // namespace fex_assembly_test

SCENARIO("assembly: out-of-order and duplicate puts, verify, resume") {
    using namespace fex;
    using fex_assembly_test::pattern;
    char tmpl[] = "/tmp/fex-asm-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir{root};

    const auto data = pattern(2 * 1024 + 300); // 3 chunks
    const auto hash = crypto::ascon::hash256(fex::bytes{data});
    fex::hash256 h;
    std::copy(hash.begin(), hash.end(), h.begin());

    auto a = relay::assembly::start(dir, h, data.size());
    REQUIRE(a.has_value());

    const auto chunk_of = [&](fex::u64 no) {
        const auto z = *wire::chunk_len(data.size(), no);
        return fex::bytes{data.data() + no * 1024, z};
    };

    // out of order: 2, 0, duplicate 2, then 1 completes
    auto r = a->put(2, chunk_of(2));
    REQUIRE(r.has_value());
    CHECK(*r == relay::assembly::put_result::building);
    REQUIRE(a->put(0, chunk_of(0)).has_value());
    REQUIRE(a->put(2, chunk_of(2)).has_value()); // idempotent
    std::array<wire::range, 147> gap_buf;
    REQUIRE(a->gaps(gap_buf) == 1);
    CHECK(gap_buf[0].from == 1);
    CHECK(gap_buf[0].to == 1);
    REQUIRE(a->persist_map().has_value());

    // resume mid-build sees the same gaps
    {
        auto b = relay::assembly::resume(dir, h);
        REQUIRE(b.has_value());
        CHECK(!b->assembled());
        CHECK(b->file_size() == data.size());
        REQUIRE(b->gaps(gap_buf) == 1);
        CHECK(gap_buf[0].from == 1);
    }

    r = a->put(1, chunk_of(1));
    REQUIRE(r.has_value());
    CHECK(*r == relay::assembly::put_result::assembled);
    CHECK(a->gaps(gap_buf) == 0);

    // assembled state survives resume (map gone)
    {
        auto b = relay::assembly::resume(dir, h);
        REQUIRE(b.has_value());
        CHECK(b->assembled());
        const auto back = fs::read_file(b->data_path().c_str());
        REQUIRE(back.has_value());
        CHECK(*back == data);
    }

    REQUIRE(fs::remove_tree(dir).has_value());
}

SCENARIO("assembly: corruption is a terminal mismatch") {
    using namespace fex;
    using fex_assembly_test::pattern;
    char tmpl[] = "/tmp/fex-asm-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir{root};

    const auto data = pattern(1500); // 2 chunks
    const auto hash = crypto::ascon::hash256(fex::bytes{data});
    fex::hash256 h;
    std::copy(hash.begin(), hash.end(), h.begin());

    auto a = relay::assembly::start(dir, h, data.size());
    REQUIRE(a.has_value());
    auto bad = pattern(1024);
    bad[0] ^= 0xff; // wrong content for chunk 0
    REQUIRE(a->put(0, fex::bytes{bad}).has_value());
    const auto r = a->put(1, fex::bytes{data.data() + 1024, 476});
    REQUIRE(r.has_value());
    CHECK(*r == relay::assembly::put_result::mismatch);
    // both files are gone
    CHECK(fs::stat_of(a->data_path().c_str()).kind == fs::entry_kind::missing);
    CHECK(!relay::assembly::resume(dir, h).has_value());

    REQUIRE(fs::remove_tree(dir).has_value());
}

SCENARIO("assembly: gaps truncation") {
    using namespace fex;
    using fex_assembly_test::pattern;
    char tmpl[] = "/tmp/fex-asm-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir{root};

    // 400 chunks; fill every even chunk -> 200 single-chunk holes
    const std::size_t chunks = 400;
    const auto data = pattern(chunks * 1024);
    const auto hash = crypto::ascon::hash256(fex::bytes{data});
    fex::hash256 h;
    std::copy(hash.begin(), hash.end(), h.begin());
    auto a = relay::assembly::start(dir, h, data.size());
    REQUIRE(a.has_value());
    for (std::size_t c = 0; c < chunks; c += 2)
        REQUIRE(a->put(c, fex::bytes{data.data() + c * 1024, 1024}).has_value());
    std::array<wire::range, 147> buf;
    REQUIRE(a->gaps(buf) == buf.size()); // truncated to what fits
    CHECK(buf[0].from == 1);
    CHECK(buf[0].to == 1);
    CHECK(buf[146].from == 293);

    REQUIRE(fs::remove_tree(dir).has_value());
}

}

#endif
