// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Wire codecs for the fex protocol: outer layer (#4) and inner layer (#5).
// All integers are little-endian; nothing is memcpy'd to or from the wire.

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <span>

#include <fex/crypto.hpp>
#include <fex/types.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::wire {

inline constexpr u8 protocol_version = 1;

// #4 outer layer
inline constexpr std::size_t datagram_max = 1232;
inline constexpr std::size_t pheader_size = 24;
inline constexpr std::size_t nonce_size = 14;
inline constexpr std::size_t aead_tag_size = crypto::ascon::tag_bytes;
inline constexpr std::size_t ballast_size = 72;
inline constexpr std::size_t peek_size = pheader_size + ballast_size;
inline constexpr std::size_t max_command = datagram_max - pheader_size - aead_tag_size;

// #5 inner layer
inline constexpr std::size_t mprefix_size = 8;
inline constexpr std::size_t head_size = 56;
inline constexpr std::size_t put_base = 56;
inline constexpr std::size_t get_size = 48;
inline constexpr std::size_t chunk_base = 16;
inline constexpr std::size_t poll_size = 40;
inline constexpr std::size_t gaps_base = 16;
inline constexpr std::size_t commit_size = 48;
inline constexpr std::size_t done_size = 8;

// #5.1 chunks
inline constexpr u64 chunk_data_size = 1024;

inline constexpr std::size_t gaps_max_count = (max_command - gaps_base) / 8;

static_assert(max_command == 1192);
static_assert(gaps_max_count == 147);
static_assert(peek_size == 96);

enum struct pkind : u8 {
  peek = 0x01, request = 0x02, response = 0x81
}; // pkind

struct pheader {
  u8 version;
  pkind kind;
  u8 nonce[nonce_size];
  u64 id;
}; // pheader
static_assert(sizeof(pheader) == pheader_size);

enum struct mkind : u8 {
  put = 0x01, get = 0x02, poll = 0x03, commit = 0x04,
  head = 0x80, chunk = 0x82, gaps = 0x83, done = 0x84
}; // mkind

enum struct mstatus : u8 {
  ok = 0x00, internal = 0x01, not_found = 0x02, stale_seq = 0x03,
  files_missing = 0x04, hash_mismatch = 0x05
}; // mstatus

inline constexpr bool is_request_kind(mkind k) noexcept {
  return k == mkind::put || k == mkind::get || k == mkind::poll || k == mkind::commit;
}

inline constexpr bool is_response_kind(mkind k) noexcept {
  return k == mkind::head || k == mkind::chunk || k == mkind::gaps || k == mkind::done;
}

// in-memory prefix; on the wire it is kind:u8@0 || status:u8@1 || req_id:b6@2
// bit layout:
// 0-47: request id
// 48-55: mstatus
// 56-63: mkind
using mheader = u64;

inline constexpr u64 request_id_mask = (u64{1} << 48) - 1;
inline constexpr unsigned mstatus_shift = 48;
inline constexpr unsigned mkind_shift = 56;

inline constexpr mheader mheader_of(mkind k, mstatus s, u64 req_id) {
  return (u64{static_cast<u8>(k)} << mkind_shift)
       | (u64{static_cast<u8>(s)} << mstatus_shift)
       | (req_id & request_id_mask);
}

inline constexpr mkind mkind_of(mheader h) {
  return static_cast<mkind>(static_cast<u8>(h >> mkind_shift));
}

inline constexpr mstatus mstatus_of(mheader h) {
  return static_cast<mstatus>(static_cast<u8>(h >> mstatus_shift));
}

inline constexpr u64 request_id_of(mheader h) {
  return h & request_id_mask;
}

// little-endian load/store

inline constexpr u64 load_u64(const u8* p) noexcept {
  u64 v = 0;
  for (unsigned i = 0; i != 8; ++i)
    v |= u64{p[i]} << (8 * i);
  return v;
}

inline constexpr u32 load_u32(const u8* p) noexcept {
  u32 v = 0;
  for (unsigned i = 0; i != 4; ++i)
    v |= u32{p[i]} << (8 * i);
  return v;
}

inline constexpr void store_u64(u8* p, u64 v) noexcept {
  for (unsigned i = 0; i != 8; ++i)
    p[i] = static_cast<u8>(v >> (8 * i));
}

inline constexpr void store_u32(u8* p, u32 v) noexcept {
  for (unsigned i = 0; i != 4; ++i)
    p[i] = static_cast<u8>(v >> (8 * i));
}

// outer header codec

inline void write_pheader(std::span<u8> out, const pheader& h) noexcept {
  out[0] = h.version;
  out[1] = static_cast<u8>(h.kind);
  std::copy(h.nonce, h.nonce + nonce_size, out.data() + 2);
  store_u64(out.data() + 16, h.id);
}

// nullopt = silent drop: short datagram or version mismatch; kind is not
// checked here -- each side drops the halves it does not accept itself
inline std::optional<pheader> read_pheader(bytes datagram) noexcept {
  if (datagram.size() < pheader_size)
    return std::nullopt;
  if (datagram[0] != protocol_version)
    return std::nullopt;
  pheader h;
  h.version = datagram[0];
  h.kind = static_cast<pkind>(datagram[1]);
  std::copy(datagram.data() + 2, datagram.data() + 2 + nonce_size, h.nonce);
  h.id = load_u64(datagram.data() + 16);
  return h;
}

// inner prefix codec

inline void write_mprefix(std::span<u8> out, mheader h) noexcept {
  out[0] = static_cast<u8>(mkind_of(h));
  out[1] = static_cast<u8>(mstatus_of(h));
  const u64 req = request_id_of(h);
  for (unsigned i = 0; i != 6; ++i)
    out[2 + i] = static_cast<u8>(req >> (8 * i));
}

inline std::optional<mheader> read_mheader(bytes plain) noexcept {
  if (plain.size() < mprefix_size)
    return std::nullopt;
  u64 req = 0;
  for (unsigned i = 0; i != 6; ++i)
    req |= u64{plain[2 + i]} << (8 * i);
  return mheader_of(static_cast<mkind>(plain[0]), static_cast<mstatus>(plain[1]), req);
}

// messages

struct head {
  u64 seq;
  u64 inv_size;
  u8 inv_hash[32];
}; // head

struct put {
  u64 file_size;
  u64 chunk_no;
  u8 file_hash[32];
  bytes data; // view into the decoded buffer
}; // put

struct get {
  u64 chunk_no;
  u8 file_hash[32];
}; // get

struct chunk {
  bytes data; // view into the decoded buffer; empty in error responses
}; // chunk

struct poll {
  u8 file_hash[32];
}; // poll

struct range {
  u32 from;
  u32 to; // inclusive chunk numbers
}; // range

struct gaps {
  u64 count;
  std::array<range, gaps_max_count> ranges;
}; // gaps

struct commit {
  u64 seq;
  u8 inv_hash[32];
}; // commit

struct done {}; // done

// z = min(1024, file_size - chunk_no*1024); nullopt when file_size is zero
// (#5.1: invalid) or chunk_no is past the end of the file
inline constexpr std::optional<u64> chunk_len(u64 file_size, u64 chunk_no) noexcept {
  if (file_size == 0)
    return std::nullopt;
  const u64 chunks = (file_size + chunk_data_size - 1) / chunk_data_size;
  if (chunk_no >= chunks)
    return std::nullopt;
  return std::min(chunk_data_size, file_size - chunk_no * chunk_data_size);
}

inline constexpr u64 chunk_count(u64 file_size) noexcept {
  return (file_size + chunk_data_size - 1) / chunk_data_size;
}

// encoders: write prefix + payload, return bytes written, 0 if out is too small

inline std::size_t write_head(std::span<u8> out, mheader h, const head& m) noexcept {
  if (out.size() < head_size)
    return 0;
  write_mprefix(out, h);
  store_u64(out.data() + 8, m.seq);
  store_u64(out.data() + 16, m.inv_size);
  std::copy(m.inv_hash, m.inv_hash + 32, out.data() + 24);
  return head_size;
}

inline std::size_t write_put(std::span<u8> out, mheader h, const put& m) noexcept {
  const std::size_t total = put_base + m.data.size();
  if (out.size() < total)
    return 0;
  write_mprefix(out, h);
  store_u64(out.data() + 8, m.file_size);
  store_u64(out.data() + 16, m.chunk_no);
  std::copy(m.file_hash, m.file_hash + 32, out.data() + 24);
  std::copy(m.data.begin(), m.data.end(), out.data() + put_base);
  return total;
}

inline std::size_t write_get(std::span<u8> out, mheader h, const get& m) noexcept {
  if (out.size() < get_size)
    return 0;
  write_mprefix(out, h);
  store_u64(out.data() + 8, m.chunk_no);
  std::copy(m.file_hash, m.file_hash + 32, out.data() + 16);
  return get_size;
}

inline std::size_t write_chunk(std::span<u8> out, mheader h, bytes data) noexcept {
  const std::size_t total = chunk_base + data.size();
  if (data.size() > chunk_data_size || out.size() < total)
    return 0;
  write_mprefix(out, h);
  store_u64(out.data() + 8, data.size());
  std::copy(data.begin(), data.end(), out.data() + chunk_base);
  return total;
}

inline std::size_t write_poll(std::span<u8> out, mheader h, const poll& m) noexcept {
  if (out.size() < poll_size)
    return 0;
  write_mprefix(out, h);
  std::copy(m.file_hash, m.file_hash + 32, out.data() + 8);
  return poll_size;
}

inline std::size_t write_gaps(std::span<u8> out, mheader h,
                              std::span<const range> ranges) noexcept {
  const std::size_t total = gaps_base + 8 * ranges.size();
  if (ranges.size() > gaps_max_count || out.size() < total)
    return 0;
  write_mprefix(out, h);
  store_u64(out.data() + 8, ranges.size());
  for (std::size_t i = 0; i != ranges.size(); ++i) {
    store_u32(out.data() + gaps_base + 8 * i, ranges[i].from);
    store_u32(out.data() + gaps_base + 8 * i + 4, ranges[i].to);
  }
  return total;
}

inline std::size_t write_commit(std::span<u8> out, mheader h, const commit& m) noexcept {
  if (out.size() < commit_size)
    return 0;
  write_mprefix(out, h);
  store_u64(out.data() + 8, m.seq);
  std::copy(m.inv_hash, m.inv_hash + 32, out.data() + 16);
  return commit_size;
}

inline std::size_t write_done(std::span<u8> out, mheader h) noexcept {
  if (out.size() < done_size)
    return 0;
  write_mprefix(out, h);
  return done_size;
}

// decoders: exact length validation per #5, nullopt = silent drop;
// the caller has already read the prefix and dispatched on its kind

inline std::optional<head> read_head(bytes plain) noexcept {
  if (plain.size() != head_size)
    return std::nullopt;
  head m;
  m.seq = load_u64(plain.data() + 8);
  m.inv_size = load_u64(plain.data() + 16);
  std::copy(plain.data() + 24, plain.data() + 56, m.inv_hash);
  return m;
}

inline std::optional<put> read_put(bytes plain) noexcept {
  if (plain.size() < put_base)
    return std::nullopt;
  put m;
  m.file_size = load_u64(plain.data() + 8);
  m.chunk_no = load_u64(plain.data() + 16);
  const auto z = chunk_len(m.file_size, m.chunk_no);
  if (!z || plain.size() != put_base + *z)
    return std::nullopt;
  std::copy(plain.data() + 24, plain.data() + 56, m.file_hash);
  m.data = plain.subspan(put_base);
  return m;
}

inline std::optional<get> read_get(bytes plain) noexcept {
  if (plain.size() != get_size)
    return std::nullopt;
  get m;
  m.chunk_no = load_u64(plain.data() + 8);
  std::copy(plain.data() + 16, plain.data() + 48, m.file_hash);
  return m;
}

inline std::optional<chunk> read_chunk(bytes plain) noexcept {
  if (plain.size() < chunk_base)
    return std::nullopt;
  const u64 size = load_u64(plain.data() + 8);
  if (size > chunk_data_size || plain.size() != chunk_base + size)
    return std::nullopt;
  return chunk{plain.subspan(chunk_base)};
}

inline std::optional<poll> read_poll(bytes plain) noexcept {
  if (plain.size() != poll_size)
    return std::nullopt;
  poll m;
  std::copy(plain.data() + 8, plain.data() + 40, m.file_hash);
  return m;
}

inline std::optional<gaps> read_gaps(bytes plain) noexcept {
  if (plain.size() < gaps_base)
    return std::nullopt;
  const u64 count = load_u64(plain.data() + 8);
  if (count > gaps_max_count || plain.size() != gaps_base + 8 * count)
    return std::nullopt;
  gaps m;
  m.count = count;
  for (u64 i = 0; i != count; ++i) {
    m.ranges[i].from = load_u32(plain.data() + gaps_base + 8 * i);
    m.ranges[i].to = load_u32(plain.data() + gaps_base + 8 * i + 4);
  }
  return m;
}

inline std::optional<commit> read_commit(bytes plain) noexcept {
  if (plain.size() != commit_size)
    return std::nullopt;
  commit m;
  m.seq = load_u64(plain.data() + 8);
  std::copy(plain.data() + 16, plain.data() + 48, m.inv_hash);
  return m;
}

inline std::optional<done> read_done(bytes plain) noexcept {
  if (plain.size() != done_size)
    return std::nullopt;
  return done{};
}

} // namespace fex::wire

#ifdef FEX_WITH_TESTS

TEST_SUITE("fex::wire") {

SCENARIO("mheader_roundtrip") {
    using namespace fex;
    using namespace fex::wire;
    constexpr auto req = 0x0000'1234'5678'9abcull;
    constexpr auto h = mheader_of(mkind::chunk, mstatus::stale_seq, req);
    static_assert(mkind_of(h) == mkind::chunk);
    static_assert(mstatus_of(h) == mstatus::stale_seq);
    static_assert(request_id_of(h) == req);
}

SCENARIO("mprefix wire layout") {
    using namespace fex;
    using namespace fex::wire;
    constexpr auto req = 0x0000'1234'5678'9abcull;
    const auto h = mheader_of(mkind::gaps, mstatus::not_found, req);
    fex::u8 buf[8];
    write_mprefix(buf, h);
    CHECK(buf[0] == 0x83);        // kind@0
    CHECK(buf[1] == 0x02);        // status@1
    CHECK(buf[2] == 0xbc);        // req_id b6@2, little-endian
    CHECK(buf[3] == 0x9a);
    CHECK(buf[7] == 0x12);
    const auto back = read_mheader(std::span<const fex::u8>{buf});
    REQUIRE(back.has_value());
    CHECK(*back == h);
    CHECK(!read_mheader(std::span<const fex::u8>{buf, 7}).has_value());
}

SCENARIO("pheader roundtrip and drops") {
    using namespace fex;
    using namespace fex::wire;
    pheader h{};
    h.version = protocol_version;
    h.kind = pkind::request;
    for (unsigned i = 0; i != nonce_size; ++i)
        h.nonce[i] = static_cast<u8>(i + 1);
    h.id = 0x0123'4567'89ab'cdefull;
    u8 buf[pheader_size];
    write_pheader(buf, h);
    CHECK(buf[0] == 1);
    CHECK(buf[1] == 0x02);
    CHECK(buf[16] == 0xef);
    const auto back = read_pheader(bytes{buf});
    REQUIRE(back.has_value());
    CHECK(back->id == h.id);
    CHECK(back->kind == h.kind);
    CHECK(std::equal(back->nonce, back->nonce + nonce_size, h.nonce));
    // version mismatch and short datagram -> drop
    buf[0] = 2;
    CHECK(!read_pheader(bytes{buf}).has_value());
    buf[0] = 1;
    CHECK(!read_pheader(bytes{buf, pheader_size - 1}).has_value());
}

SCENARIO("chunk_len") {
    using namespace fex;
    using namespace fex::wire;
    static_assert(!chunk_len(0, 0).has_value());
    static_assert(chunk_len(1, 0) == 1);
    static_assert(chunk_len(1024, 0) == 1024);
    static_assert(!chunk_len(1024, 1).has_value());
    static_assert(chunk_len(1025, 1) == 1);
    static_assert(chunk_len(2048, 1) == 1024);
    static_assert(!chunk_len(2048, 2).has_value());
    static_assert(chunk_count(1) == 1);
    static_assert(chunk_count(2048) == 2);
    static_assert(chunk_count(2049) == 3);
}

SCENARIO("head roundtrip") {
    using namespace fex;
    using namespace fex::wire;
    head m{};
    m.seq = 7;
    m.inv_size = 12345;
    for (unsigned i = 0; i != 32; ++i)
        m.inv_hash[i] = static_cast<u8>(i);
    u8 buf[head_size];
    const auto h = mheader_of(mkind::head, mstatus::ok, 0);
    REQUIRE(write_head(buf, h, m) == head_size);
    const auto back = read_head(bytes{buf});
    REQUIRE(back.has_value());
    CHECK(back->seq == m.seq);
    CHECK(back->inv_size == m.inv_size);
    CHECK(std::equal(back->inv_hash, back->inv_hash + 32, m.inv_hash));
    CHECK(!read_head(bytes{buf, head_size - 1}).has_value());
}

SCENARIO("put roundtrip and rejects") {
    using namespace fex;
    using namespace fex::wire;
    std::array<u8, 700> data{};
    for (std::size_t i = 0; i != data.size(); ++i)
        data[i] = static_cast<u8>(i);
    put m{};
    m.file_size = 1024 + 700; // second chunk is the 700-byte remainder
    m.chunk_no = 1;
    for (unsigned i = 0; i != 32; ++i)
        m.file_hash[i] = static_cast<u8>(0xa0 + i);
    m.data = bytes{data};
    std::array<u8, put_base + 1024> buf{};
    const auto h = mheader_of(mkind::put, mstatus::ok, 0);
    const auto n = write_put(buf, h, m);
    REQUIRE(n == put_base + 700);
    const auto back = read_put(bytes{buf.data(), n});
    REQUIRE(back.has_value());
    CHECK(back->file_size == m.file_size);
    CHECK(back->chunk_no == m.chunk_no);
    CHECK(std::equal(back->data.begin(), back->data.end(), data.begin()));
    // z mismatch: same message, truncated/extended datagram
    CHECK(!read_put(bytes{buf.data(), n - 1}).has_value());
    CHECK(!read_put(bytes{buf.data(), n + 1}).has_value());
    // file_size == 0 is invalid
    store_u64(buf.data() + 8, 0);
    CHECK(!read_put(bytes{buf.data(), n}).has_value());
    // chunk_no past the end of the file
    store_u64(buf.data() + 8, 1024 + 700);
    store_u64(buf.data() + 16, 2);
    CHECK(!read_put(bytes{buf.data(), n}).has_value());
}

SCENARIO("get/poll/commit/done roundtrip") {
    using namespace fex;
    using namespace fex::wire;
    u8 buf[64];
    get g{};
    g.chunk_no = 42;
    for (unsigned i = 0; i != 32; ++i)
        g.file_hash[i] = static_cast<u8>(i * 3);
    REQUIRE(write_get(buf, mheader_of(mkind::get, mstatus::ok, 1), g) == get_size);
    auto gb = read_get(bytes{buf, get_size});
    REQUIRE(gb.has_value());
    CHECK(gb->chunk_no == 42);
    CHECK(std::equal(gb->file_hash, gb->file_hash + 32, g.file_hash));
    CHECK(!read_get(bytes{buf, get_size + 1}).has_value());

    fex::wire::poll p{};
    for (unsigned i = 0; i != 32; ++i)
        p.file_hash[i] = static_cast<u8>(i * 5);
    REQUIRE(write_poll(buf, mheader_of(mkind::poll, mstatus::ok, 2), p) == poll_size);
    auto pb = read_poll(bytes{buf, poll_size});
    REQUIRE(pb.has_value());
    CHECK(std::equal(pb->file_hash, pb->file_hash + 32, p.file_hash));
    CHECK(!read_poll(bytes{buf, poll_size - 1}).has_value());

    commit c{};
    c.seq = 9;
    for (unsigned i = 0; i != 32; ++i)
        c.inv_hash[i] = static_cast<u8>(i * 7);
    REQUIRE(write_commit(buf, mheader_of(mkind::commit, mstatus::ok, 3), c) == commit_size);
    auto cb = read_commit(bytes{buf, commit_size});
    REQUIRE(cb.has_value());
    CHECK(cb->seq == 9);
    CHECK(std::equal(cb->inv_hash, cb->inv_hash + 32, c.inv_hash));

    REQUIRE(write_done(buf, mheader_of(mkind::done, mstatus::ok, 4)) == done_size);
    CHECK(read_done(bytes{buf, done_size}).has_value());
    CHECK(!read_done(bytes{buf, done_size + 1}).has_value());
}

SCENARIO("chunk roundtrip and rejects") {
    using namespace fex;
    using namespace fex::wire;
    std::array<u8, 1024> data{};
    for (std::size_t i = 0; i != data.size(); ++i)
        data[i] = static_cast<u8>(i ^ 0x5a);
    std::array<u8, chunk_base + 1024> buf{};
    const auto h = mheader_of(mkind::chunk, mstatus::ok, 5);
    const auto n = write_chunk(buf, h, bytes{data});
    REQUIRE(n == chunk_base + 1024);
    auto back = read_chunk(bytes{buf.data(), n});
    REQUIRE(back.has_value());
    CHECK(std::equal(back->data.begin(), back->data.end(), data.begin()));
    // empty chunk (error responses carry no data)
    REQUIRE(write_chunk(buf, h, bytes{}) == chunk_base);
    CHECK(read_chunk(bytes{buf.data(), chunk_base})->data.empty());
    // size beyond 1024 or length mismatch -> drop
    store_u64(buf.data() + 8, 1025);
    CHECK(!read_chunk(bytes{buf.data(), chunk_base + 1025}).has_value());
    store_u64(buf.data() + 8, 100);
    CHECK(!read_chunk(bytes{buf.data(), chunk_base + 99}).has_value());
}

SCENARIO("gaps roundtrip and boundary") {
    using namespace fex;
    using namespace fex::wire;
    std::array<range, gaps_max_count> rs{};
    for (std::size_t i = 0; i != rs.size(); ++i)
        rs[i] = range{static_cast<u32>(2 * i), static_cast<u32>(2 * i + 1)};
    std::array<u8, max_command> buf{};
    const auto h = mheader_of(mkind::gaps, mstatus::ok, 6);
    // maximum count fills max_command exactly
    const auto n = write_gaps(buf, h, std::span<const range>{rs});
    REQUIRE(n == max_command);
    auto back = read_gaps(bytes{buf.data(), n});
    REQUIRE(back.has_value());
    CHECK(back->count == gaps_max_count);
    CHECK(back->ranges[146].from == 292);
    CHECK(back->ranges[146].to == 293);
    // count 148 -> reject
    store_u64(buf.data() + 8, gaps_max_count + 1);
    CHECK(!read_gaps(bytes{buf.data(), gaps_base + 8 * (gaps_max_count + 1)}).has_value());
    // count/length mismatch -> reject
    store_u64(buf.data() + 8, 2);
    CHECK(!read_gaps(bytes{buf.data(), gaps_base + 8 * 3}).has_value());
    // empty gaps (fully assembled)
    REQUIRE(write_gaps(buf, h, {}) == gaps_base);
    CHECK(read_gaps(bytes{buf.data(), gaps_base})->count == 0);
}

SCENARIO("kind halves") {
    using namespace fex;
    using namespace fex::wire;
    static_assert(is_request_kind(mkind::put));
    static_assert(is_request_kind(mkind::commit));
    static_assert(!is_request_kind(mkind::head));
    static_assert(is_response_kind(mkind::gaps));
    static_assert(!is_response_kind(mkind::poll));
    static_assert(!is_request_kind(static_cast<mkind>(0x05)));
    static_assert(!is_response_kind(static_cast<mkind>(0x81)));
}

}

#endif
