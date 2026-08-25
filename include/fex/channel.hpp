// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Channel layer (#2, #4): key derivation and AEAD sealing of datagrams.
// One key serves both directions; the 24-byte outer header is the associated
// data, so the packet kind is authenticated (#2); the nonce space is shared --
// 14 fresh random bytes per sealed packet, uniqueness is the sender's duty.

#include <algorithm>
#include <optional>
#include <span>

#include <fex/crypto.hpp>
#include <fex/types.hpp>
#include <fex/wire.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::channel {

using key = crypto::ascon::key;

// k = hash(dh(priv, pub))[0:16]; false when dh yields the all-zero secret (RFC 7748)
[[nodiscard]] inline bool derive(key& out, const crypto::x25519::secret_key& priv,
                                 const crypto::x25519::public_key& pub) noexcept {
    crypto::x25519::shared_secret shared;
    if (!crypto::x25519::exchange(shared, priv, pub))
        return false;
    const auto digest = crypto::ascon::hash256(bytes{shared});
    std::copy(digest.begin(), digest.begin() + crypto::ascon::key_bytes, out.begin());
    return true;
}

inline crypto::ascon::nonce aead_nonce(const u8 (&nonce14)[wire::nonce_size]) noexcept {
    crypto::ascon::nonce n{}; // 16 bytes, the trailing two stay zero
    std::copy(nonce14, nonce14 + wire::nonce_size, n.begin());
    return n;
}

// request/response: header with a fresh random nonce + ciphertext;
// returns 24 + n + 16, or 0 when plain exceeds max_command or out is too small
inline std::size_t seal(std::span<u8> out, wire::pkind kind, u64 id,
                        bytes plain, const key& k) noexcept {
    const std::size_t total = wire::pheader_size + plain.size() + wire::aead_tag_size;
    if (plain.size() > wire::max_command || out.size() < total)
        return 0;
    wire::pheader h{};
    h.version = wire::protocol_version;
    h.kind = kind;
    crypto::random_bytes({h.nonce, wire::nonce_size});
    h.id = id;
    wire::write_pheader(out, h);
    crypto::ascon::aead128_encrypt(out.subspan(wire::pheader_size), plain,
                                   bytes{out.first(wire::pheader_size)},
                                   aead_nonce(h.nonce), k);
    return total;
}

// peek (#4): zero nonce, 72 zero ballast bytes; always exactly 96 bytes
inline std::size_t make_peek(std::span<u8> out, u64 id) noexcept {
    if (out.size() < wire::peek_size)
        return 0;
    std::fill(out.begin(), out.begin() + wire::peek_size, u8{0});
    wire::pheader h{};
    h.version = wire::protocol_version;
    h.kind = wire::pkind::peek;
    h.id = id;
    wire::write_pheader(out, h);
    return wire::peek_size;
}

// decrypts a request/response datagram (header already validated by the caller);
// out must hold datagram.size() - 40 bytes; nullopt = drop
inline std::optional<std::size_t> open(std::span<u8> out, bytes datagram,
                                       const key& k) noexcept {
    if (datagram.size() < wire::pheader_size + wire::aead_tag_size)
        return std::nullopt;
    const std::size_t n = datagram.size() - wire::pheader_size - wire::aead_tag_size;
    if (out.size() < n)
        return std::nullopt;
    crypto::ascon::nonce nn{};
    std::copy(datagram.data() + 2, datagram.data() + 2 + wire::nonce_size, nn.begin());
    if (!crypto::ascon::aead128_decrypt(out.first(n), datagram.subspan(wire::pheader_size),
                                        datagram.first(wire::pheader_size), nn, k))
        return std::nullopt;
    return n;
}

} // namespace fex::channel

#ifdef FEX_WITH_TESTS

TEST_SUITE("fex::channel") {

SCENARIO("both sides derive the same key") {
    using namespace fex;
    const auto a = crypto::x25519::keypair();
    const auto b = crypto::x25519::keypair();
    channel::key ka{}, kb{};
    REQUIRE(channel::derive(ka, a.sk, b.pk));
    REQUIRE(channel::derive(kb, b.sk, a.pk));
    CHECK(ka == kb);
    // low-order peer -> rejected
    crypto::x25519::public_key zero{};
    channel::key kz{};
    CHECK(!channel::derive(kz, a.sk, zero));
}

SCENARIO("seal/open roundtrip and tamper rejection") {
    using namespace fex;
    const auto a = crypto::x25519::keypair();
    const auto b = crypto::x25519::keypair();
    channel::key k{};
    REQUIRE(channel::derive(k, a.sk, b.pk));

    std::array<fex::u8, 48> plain{};
    for (std::size_t i = 0; i != plain.size(); ++i)
        plain[i] = static_cast<fex::u8>(i);
    std::array<fex::u8, wire::datagram_max> dgram{};
    const auto n = channel::seal(dgram, wire::pkind::request, 0x1122334455667788ull,
                                 fex::bytes{plain}, k);
    REQUIRE(n == wire::pheader_size + plain.size() + wire::aead_tag_size);

    const auto h = wire::read_pheader(fex::bytes{dgram.data(), n});
    REQUIRE(h.has_value());
    CHECK(h->kind == wire::pkind::request);
    CHECK(h->id == 0x1122334455667788ull);

    std::array<fex::u8, wire::max_command> out{};
    const auto m = channel::open(out, fex::bytes{dgram.data(), n}, k);
    REQUIRE(m.has_value());
    REQUIRE(*m == plain.size());
    CHECK(std::equal(plain.begin(), plain.end(), out.begin()));

    // flipping any header byte (ver, kind, nonce, id) breaks authentication
    for (const std::size_t at : {std::size_t{0}, std::size_t{1}, std::size_t{5},
                                 std::size_t{17}}) {
        auto bad = dgram;
        bad[at] ^= 0x01;
        CHECK(!channel::open(out, fex::bytes{bad.data(), n}, k).has_value());
    }
    // flipped ciphertext and tag bytes
    for (const std::size_t at : {wire::pheader_size + 3, static_cast<std::size_t>(n - 1)}) {
        auto bad = dgram;
        bad[at] ^= 0x01;
        CHECK(!channel::open(out, fex::bytes{bad.data(), n}, k).has_value());
    }
    // truncated ciphertext
    CHECK(!channel::open(out, fex::bytes{dgram.data(), n - 1}, k).has_value());
    CHECK(!channel::open(out, fex::bytes{dgram.data(), 30}, k).has_value());
    // wrong key
    channel::key other{};
    CHECK(!channel::open(out, fex::bytes{dgram.data(), n}, other).has_value());
}

SCENARIO("peek layout") {
    using namespace fex;
    std::array<fex::u8, wire::peek_size> buf{};
    std::fill(buf.begin(), buf.end(), fex::u8{0xff});
    REQUIRE(channel::make_peek(buf, 42) == wire::peek_size);
    CHECK(buf[0] == wire::protocol_version);
    CHECK(buf[1] == 0x01);
    // zero nonce, zero ballast
    for (std::size_t i = 2; i != 16; ++i)
        CHECK(buf[i] == 0);
    CHECK(buf[16] == 42);
    for (std::size_t i = wire::pheader_size; i != wire::peek_size; ++i)
        CHECK(buf[i] == 0);
}

SCENARIO("seal refuses oversized commands") {
    using namespace fex;
    channel::key k{};
    std::array<fex::u8, wire::max_command + 1> big{};
    std::array<fex::u8, 2 * wire::datagram_max> out{};
    CHECK(channel::seal(out, wire::pkind::request, 1, fex::bytes{big}, k) == 0);
    CHECK(channel::seal(out, wire::pkind::request, 1,
                        fex::bytes{big.data(), wire::max_command}, k)
          == wire::datagram_max);
}

}

#endif
