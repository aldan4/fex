// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// POSIX filesystem helpers shared by the relay and the client. Atomicity is
// always temp-file-in-the-same-directory + rename (#9, #10.2).

#include <cerrno>
#include <ctime>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fex/crypto.hpp>
#include <fex/types.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::fs {

[[nodiscard]] inline u64 now_ns() noexcept {
    ::timespec ts{};
    ::clock_gettime(CLOCK_REALTIME, &ts);
    return u64(ts.tv_sec) * 1'000'000'000ull + u64(ts.tv_nsec);
}

[[nodiscard]] inline std::errc last_errc() noexcept {
    return static_cast<std::errc>(errno);
}

template <typename T = void>
[[nodiscard]] inline std::unexpected<std::errc> failure() noexcept {
    return std::unexpected(last_errc());
}

enum struct entry_kind { missing, file, dir, other }; // other = symlink or special

struct info {
    entry_kind kind;
    u64 size;
    u64 mtime_ns;
}; // info

// lstat: symlinks are reported as `other`, never followed
[[nodiscard]] inline info stat_of(const char* path) noexcept {
    struct ::stat st;
    if (::lstat(path, &st) != 0)
        return {entry_kind::missing, 0, 0};
    const auto kind = S_ISREG(st.st_mode) ? entry_kind::file
                    : S_ISDIR(st.st_mode) ? entry_kind::dir
                                          : entry_kind::other;
#if defined(__APPLE__)
    const u64 mtime_ns = u64(st.st_mtimespec.tv_sec) * 1'000'000'000ull
                       + u64(st.st_mtimespec.tv_nsec);
#else
    const u64 mtime_ns = u64(st.st_mtim.tv_sec) * 1'000'000'000ull
                       + u64(st.st_mtim.tv_nsec);
#endif
    return {kind, u64(st.st_size), mtime_ns};
}

[[nodiscard]] inline std::expected<std::vector<u8>, std::errc>
read_file(const char* path) noexcept {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return failure();
    struct ::stat st;
    if (::fstat(fd, &st) != 0) {
        const auto e = last_errc();
        ::close(fd);
        return std::unexpected(e);
    }
    if (!S_ISREG(st.st_mode)) {
        ::close(fd);
        return std::unexpected(std::errc::invalid_argument);
    }
    std::vector<u8> data(static_cast<std::size_t>(st.st_size));
    std::size_t off = 0;
    while (off != data.size()) {
        const auto n = ::read(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            const auto e = last_errc();
            ::close(fd);
            return std::unexpected(e);
        }
        if (n == 0)
            break; // file shrank mid-read
        off += static_cast<std::size_t>(n);
    }
    data.resize(off);
    ::close(fd);
    return data;
}

namespace detail {

inline void hex_of(char* out, const u8* in, std::size_t n) noexcept {
    constexpr char digits[] = "0123456789abcdef";
    for (std::size_t i = 0; i != n; ++i) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0f];
    }
}

[[nodiscard]] inline std::string temp_name_in(std::string_view dir) {
    u8 rnd[6];
    crypto::random_bytes(rnd);
    char hex[12];
    hex_of(hex, rnd, sizeof rnd);
    std::string path{dir};
    if (!path.empty() && path.back() != '/')
        path += '/';
    path += ".fex.tmp.";
    path.append(hex, sizeof hex);
    return path;
}

} // namespace detail

// directory part of a path ("" when the path has no '/')
[[nodiscard]] inline std::string_view dir_of(std::string_view path) noexcept {
    const auto slash = path.rfind('/');
    return slash == std::string_view::npos ? std::string_view{} : path.substr(0, slash);
}

// mkdir -p; every component is created 0755, existing ones are left alone
[[nodiscard]] inline std::expected<void, std::errc> ensure_dirs(std::string_view dir) noexcept {
    if (dir.empty())
        return {};
    std::string path;
    path.reserve(dir.size());
    std::size_t from = 0;
    while (from <= dir.size()) {
        auto to = dir.find('/', from);
        if (to == std::string_view::npos)
            to = dir.size();
        path.assign(dir.substr(0, to));
        from = to + 1;
        if (path.empty() || path == "/")
            continue;
        if (::mkdir(path.c_str(), 0755) != 0 && errno != EEXIST)
            return failure();
    }
    return {};
}

// temp file in the target's directory + fsync + rename; parent dirs must exist
[[nodiscard]] inline std::expected<void, std::errc>
write_file_atomic(std::string_view final_path, fex::bytes data,
                  ::mode_t mode = 0644) noexcept {
    const auto tmp = detail::temp_name_in(dir_of(final_path));
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0)
        return failure();
    const auto fail = [&](std::errc e) -> std::expected<void, std::errc> {
        ::close(fd);
        ::unlink(tmp.c_str());
        return std::unexpected(e);
    };
    if (::fchmod(fd, mode) != 0)
        return fail(last_errc());
    std::size_t off = 0;
    while (off != data.size()) {
        const auto n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return fail(last_errc());
        }
        off += static_cast<std::size_t>(n);
    }
    if (::fsync(fd) != 0)
        return fail(last_errc());
    if (::close(fd) != 0) {
        ::unlink(tmp.c_str());
        return failure();
    }
    const std::string final_str{final_path};
    if (::rename(tmp.c_str(), final_str.c_str()) != 0) {
        const auto e = last_errc();
        ::unlink(tmp.c_str());
        return std::unexpected(e);
    }
    return {};
}

// A file's hash, read a block at a time. Nothing here holds the file: a capsule may
// carry more than this machine has memory for, and only the sponge sees all of it.
[[nodiscard]] inline std::expected<hash256, std::errc> hash_file(const char* path) noexcept {
    const int fd = ::open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return failure();
    crypto::ascon::hash256_stream h;
    std::vector<u8> block(64 * 1024);
    for (;;) {
        const auto n = ::read(fd, block.data(), block.size());
        if (n < 0) {
            if (errno == EINTR)
                continue;
            const auto e = last_errc();
            ::close(fd);
            return std::unexpected(e);
        }
        if (n == 0)
            break;
        h.update(fex::bytes{block.data(), static_cast<std::size_t>(n)});
    }
    ::close(fd);
    return h.final();
}

// A file opened to be written from nothing, for a download that arrives in pieces and
// is renamed into place once its hash agrees. write_file_atomic is the whole-buffer
// counterpart and stays what the small writers use.
[[nodiscard]] inline std::expected<int, std::errc>
open_new(const char* path, ::mode_t mode = 0644) noexcept {
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
    if (fd < 0)
        return failure();
    return fd;
}

[[nodiscard]] inline std::expected<void, std::errc> write_all(int fd, fex::bytes data) noexcept {
    std::size_t off = 0;
    while (off != data.size()) {
        const auto n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return failure();
        }
        off += static_cast<std::size_t>(n);
    }
    return {};
}

// depth-first removal of a file or directory tree; a missing root is success
[[nodiscard]] inline std::expected<void, std::errc> remove_tree(const std::string& path) noexcept {
    const auto st = stat_of(path.c_str());
    switch (st.kind) {
    case entry_kind::missing:
        return {};
    case entry_kind::dir:
        break;
    default:
        if (::unlink(path.c_str()) != 0 && errno != ENOENT)
            return failure();
        return {};
    }
    DIR* const dir = ::opendir(path.c_str());
    if (dir == nullptr)
        return failure();
    while (const auto* e = ::readdir(dir)) {
        const std::string_view name = e->d_name;
        if (name == "." || name == "..")
            continue;
        auto sub = remove_tree(path + '/' + std::string{name});
        if (!sub) {
            ::closedir(dir);
            return sub;
        }
    }
    ::closedir(dir);
    if (::rmdir(path.c_str()) != 0 && errno != ENOENT)
        return failure();
    return {};
}

namespace detail {

template <typename Cb>
[[nodiscard]] inline std::expected<void, std::errc>
walk_dir(const std::string& full, std::string& rel, Cb&& cb) noexcept {
    DIR* const dir = ::opendir(full.c_str());
    if (dir == nullptr)
        return failure();
    const std::size_t rel_len = rel.size();
    while (const auto* e = ::readdir(dir)) {
        const std::string_view name = e->d_name;
        if (name == "." || name == "..")
            continue;
        rel.resize(rel_len);
        if (!rel.empty())
            rel += '/';
        rel += name;
        const std::string sub_full = full + '/' + std::string{name};
        const auto st = stat_of(sub_full.c_str());
        if (st.kind == entry_kind::dir) {
            if (auto r = cb(std::string_view{rel}, st); !r) {
                ::closedir(dir);
                return r;
            }
            if (auto r = walk_dir(sub_full, rel, cb); !r) {
                ::closedir(dir);
                return r;
            }
        } else if (st.kind != entry_kind::missing) {
            if (auto r = cb(std::string_view{rel}, st); !r) {
                ::closedir(dir);
                return r;
            }
        }
    }
    ::closedir(dir);
    rel.resize(rel_len);
    return {};
}

} // namespace detail

// recursive walk; cb(rel_path, info) -> expected<void, errc> is called for every
// entry (dirs before their contents); symlinks/specials arrive as `other`
template <typename Cb>
[[nodiscard]] inline std::expected<void, std::errc> walk(const char* root, Cb&& cb) noexcept {
    std::string full{root};
    std::string rel;
    return detail::walk_dir(full, rel, cb);
}

} // namespace fex::fs

#ifdef FEX_WITH_TESTS

#include <cstdlib>

TEST_SUITE("fex::fs") {

SCENARIO("atomic write, read back, walk, remove") {
    using namespace fex;
    char tmpl[] = "/tmp/fex-fs-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string base{root};

    REQUIRE(fs::ensure_dirs(base + "/a/b/c").has_value());
    REQUIRE(fs::ensure_dirs(base + "/a/b/c").has_value()); // idempotent

    const std::array<fex::u8, 5> data{'h', 'e', 'l', 'l', 'o'};
    REQUIRE(fs::write_file_atomic(base + "/a/b/c/f.txt", fex::bytes{data}).has_value());
    // overwrite via rename is atomic and allowed
    const std::array<fex::u8, 3> data2{'x', 'y', 'z'};
    REQUIRE(fs::write_file_atomic(base + "/a/b/c/f.txt", fex::bytes{data2}).has_value());

    const auto back = fs::read_file((base + "/a/b/c/f.txt").c_str());
    REQUIRE(back.has_value());
    CHECK(std::equal(back->begin(), back->end(), data2.begin(), data2.end()));

    CHECK(!fs::read_file((base + "/absent").c_str()).has_value());
    CHECK(fs::stat_of((base + "/absent").c_str()).kind == fs::entry_kind::missing);
    CHECK(fs::stat_of((base + "/a").c_str()).kind == fs::entry_kind::dir);
    const auto st = fs::stat_of((base + "/a/b/c/f.txt").c_str());
    CHECK(st.kind == fs::entry_kind::file);
    CHECK(st.size == 3);
    CHECK(st.mtime_ns != 0);

    // no temp files left behind
    int files = 0, dirs = 0, others = 0;
    const auto walked = fs::walk(base.c_str(),
        [&](std::string_view rel, const fs::info& i) -> std::expected<void, std::errc> {
            if (i.kind == fs::entry_kind::file) {
                ++files;
                CHECK(rel == "a/b/c/f.txt");
            } else if (i.kind == fs::entry_kind::dir) {
                ++dirs;
            } else {
                ++others;
            }
            return {};
        });
    REQUIRE(walked.has_value());
    CHECK(files == 1);
    CHECK(dirs == 3);
    CHECK(others == 0);

    // symlinks surface as `other`
    REQUIRE(::symlink("f.txt", (base + "/a/b/c/link").c_str()) == 0);
    int other_count = 0;
    REQUIRE(fs::walk(base.c_str(),
        [&](std::string_view, const fs::info& i) -> std::expected<void, std::errc> {
            if (i.kind == fs::entry_kind::other)
                ++other_count;
            return {};
        }).has_value());
    CHECK(other_count == 1);

    REQUIRE(fs::remove_tree(base).has_value());
    CHECK(fs::stat_of(base.c_str()).kind == fs::entry_kind::missing);
    REQUIRE(fs::remove_tree(base).has_value()); // missing root is fine
}

}

#endif
