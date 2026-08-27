// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Channel layer (#2, #4): key derivation and AEAD sealing of datagrams.
// One key serves both directions; the 32-byte routing prefix is the associated
// data, so the version, the nonce and both ends of the route are authenticated
// (#2); the nonce space of a channel is shared -- 15 fresh random bytes per
// sealed packet, uniqueness is the sender's duty. A relay re-encrypting a
// packet is the sender on that leg and draws a fresh one.

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

inline crypto::ascon::nonce aead_nonce(const u8 (&nonce15)[wire::nonce_size]) noexcept {
    crypto::ascon::nonce n{}; // 16 bytes, the trailing one stays zero
    std::copy(nonce15, nonce15 + wire::nonce_size, n.begin());
    return n;
}

// seals a command under a nonce the caller drew: the deterministic form, which
// is what lets a golden be written down. Returns 32 + n + 16, or 0 when plain
// exceeds max_command or out is too small.
inline std::size_t seal(std::span<u8> out, const u8 (&nonce)[wire::nonce_size],
                        u64 id, u64 peer, bytes plain, const key& k) noexcept {
    const std::size_t total = wire::pheader_size + plain.size() + wire::aead_tag_size;
    if (plain.size() > wire::max_command || out.size() < total)
        return 0;
    wire::pheader h{};
    h.version = wire::protocol_version;
    std::copy(nonce, nonce + wire::nonce_size, h.nonce);
    h.id = id;
    h.peer = peer;
    wire::write_pheader(out, h);
    crypto::ascon::aead128_encrypt(out.subspan(wire::pheader_size), plain,
                                   bytes{out.first(wire::pheader_size)},
                                   aead_nonce(h.nonce), k);
    return total;
}

// the same, with a fresh nonce from the system csprng: what every real sender
// uses
inline std::size_t seal(std::span<u8> out, u64 id, u64 peer, bytes plain,
                        const key& k) noexcept {
    u8 nonce[wire::nonce_size];
    crypto::random_bytes(nonce);
    return seal(out, nonce, id, peer, plain, k);
}

// decrypts a datagram (the prefix has already been read by the caller);
// out must hold datagram.size() - 48 bytes; nullopt = drop
inline std::optional<std::size_t> open(std::span<u8> out, bytes datagram,
                                       const key& k) noexcept {
    if (datagram.size() < wire::min_datagram)
        return std::nullopt;
    const std::size_t n = datagram.size() - wire::pheader_size - wire::aead_tag_size;
    if (out.size() < n)
        return std::nullopt;
    crypto::ascon::nonce nn{};
    std::copy(datagram.data() + 1, datagram.data() + 1 + wire::nonce_size, nn.begin());
    if (!crypto::ascon::aead128_decrypt(out.first(n), datagram.subspan(wire::pheader_size),
                                        datagram.first(wire::pheader_size), nn, k))
        return std::nullopt;
    return n;
}

} // namespace fex::channel

#ifdef FEX_WITH_TESTS

#include <fex/identity.hpp>

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

SCENARIO("known answers: the datagrams three implementations agree on") {
    using namespace fex;
    // The rfc 7748 section 6.1 pair, which is what tools/fexcheck/fexref.py and
    // the guest's modules/net/fexw_spec derive their own goldens from. fexref
    // earns that role by passing the nist sp 800-232 katalogues, so a value
    // below is one two other implementations already agree on -- and because
    // the nonce is an argument here, the whole datagram is a function of its
    // inputs and can be written down at all.
    crypto::x25519::secret_key a_sk{};
    crypto::x25519::public_key a_pk{}, b_pk{};
    REQUIRE(from_hex(a_sk, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"));
    REQUIRE(from_hex(a_pk, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    REQUIRE(from_hex(b_pk, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));

    channel::key k{};
    REQUIRE(channel::derive(k, a_sk, b_pk));
    CHECK(to_hex(fex::bytes{k}) == "f12c7454fcba14833abc03326dec1c44");
    CHECK(fingerprint_hex(a_pk) == "92de969e323b0906");
    CHECK(fingerprint_hex(b_pk) == "7e277045701543da");
    const auto a_id = fingerprint(a_pk); // the member
    const auto b_id = fingerprint(b_pk); // the relay

    u8 nonce[wire::nonce_size];
    for (unsigned i = 0; i != wire::nonce_size; ++i)
        nonce[i] = static_cast<u8>(i);

    std::array<u8, wire::max_command> cmd{};
    std::array<u8, wire::datagram_max> dgram{};

    // a peek from the member: req_id 0x123456789abc, time 1700000000, target = itself
    auto n = wire::write_peek(cmd, wire::mheader_of(wire::mkind::peek,
                                                    wire::mstatus::ok, 0x123456789abcull),
                              wire::peek{1700000000ull, a_id});
    REQUIRE(n == wire::peek_size);
    CHECK(to_hex(fex::bytes{cmd.data(), n}) == "0600bc9a7856341200f153650000000092de969e323b0906");
    auto total = channel::seal(dgram, nonce, a_id, 0, fex::bytes{cmd.data(), n}, k);
    REQUIRE(total == wire::pheader_size + wire::peek_size + wire::aead_tag_size);
    CHECK(to_hex(fex::bytes{dgram.data(), total})
          == "01000102030405060708090a0b0c0d0e92de969e323b09060000000000000000"
              "8e2707ae18483a1a6c718b279c2a33a4deaa306ef9e463a8b7858a2891682ece"
              "2895485447168084");

    // a poll, same request id, over the hash of nothing at all
    wire::poll pl{};
    const auto empty = crypto::ascon::hash256(fex::bytes{});
    std::copy(empty.begin(), empty.end(), pl.file_hash);
    n = wire::write_poll(cmd, wire::mheader_of(wire::mkind::poll, wire::mstatus::ok,
                                               0x123456789abcull), pl);
    REQUIRE(n == wire::poll_size);
    CHECK(to_hex(fex::bytes{cmd.data(), n}) == "0300bc9a785634120b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2");
    total = channel::seal(dgram, nonce, a_id, 0, fex::bytes{cmd.data(), n}, k);
    CHECK(to_hex(fex::bytes{dgram.data(), total})
          == "01000102030405060708090a0b0c0d0e92de969e323b09060000000000000000"
              "8b2707ae18483a1a67bb3dc79305583c6a96edc276eb36d198d94e7b443c873f"
              "9a1e2289300588552f66195fb5b06b5e8e04875aed389194");

    // a commit: req_id 1, seq 7
    wire::commit cm{};
    cm.seq = 7;
    std::copy(empty.begin(), empty.end(), cm.inv_hash);
    n = wire::write_commit(cmd, wire::mheader_of(wire::mkind::commit,
                                                 wire::mstatus::ok, 1), cm);
    REQUIRE(n == wire::commit_size);
    CHECK(to_hex(fex::bytes{cmd.data(), n}) == "040001000000000007000000000000000b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2");
    total = channel::seal(dgram, nonce, a_id, 0, fex::bytes{cmd.data(), n}, k);
    CHECK(to_hex(fex::bytes{dgram.data(), total})
          == "01000102030405060708090a0b0c0d0e92de969e323b09060000000000000000"
              "8c27ba34601e0e086b80d8429c2a33a475fc789fecc63c927e42b49adbf41117"
              "060c985b6882ef356d53423a55446065ac45ec06b655d8927c90d310b0042a28");

    // and the head the relay answers that peek with. The sender is the relay
    // now, so the id in the prefix is its own and peer is zero -- the packet is
    // for the member itself.
    wire::head hd{};
    hd.seq = 7;
    std::copy(empty.begin(), empty.end(), hd.inv_hash);
    n = wire::write_head(cmd, wire::mheader_of(wire::mkind::head, wire::mstatus::ok,
                                               0x123456789abcull), hd);
    REQUIRE(n == wire::head_size);
    CHECK(to_hex(fex::bytes{cmd.data(), n}) == "8000bc9a78563412070000000000000000000000000000000b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2");
    total = channel::seal(dgram, nonce, b_id, 0, fex::bytes{cmd.data(), n}, k);
    CHECK(to_hex(fex::bytes{dgram.data(), total})
          == "01000102030405060708090a0b0c0d0e7e277045701543da0000000000000000"
              "52cdde45962676e082f7409dc873e7b4defc8c4f7c1114f34e270b9be2a6bf78"
              "002e525d3f6dc38287302207a38518d73ae5cafc0452d4ea17ebb2435bed44c9"
              "add74c9f4d2e0666");

    // and it opens again to exactly what went in
    std::array<u8, wire::max_command> out{};
    const auto m = channel::open(out, fex::bytes{dgram.data(), total}, k);
    REQUIRE(m.has_value());
    CHECK(*m == wire::head_size);
    const auto back = wire::read_head(fex::bytes{out.data(), *m});
    REQUIRE(back.has_value());
    CHECK(back->seq == 7);
    CHECK(back->inv_size == 0);
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
    const auto n = channel::seal(dgram, 0x1122334455667788ull, 0x99aabbccddeeff00ull,
                                 fex::bytes{plain}, k);
    REQUIRE(n == wire::pheader_size + plain.size() + wire::aead_tag_size);

    const auto h = wire::read_pheader(fex::bytes{dgram.data(), n});
    REQUIRE(h.has_value());
    CHECK(h->id == 0x1122334455667788ull);
    CHECK(h->peer == 0x99aabbccddeeff00ull);

    std::array<fex::u8, wire::max_command> out{};
    const auto m = channel::open(out, fex::bytes{dgram.data(), n}, k);
    REQUIRE(m.has_value());
    REQUIRE(*m == plain.size());
    CHECK(std::equal(plain.begin(), plain.end(), out.begin()));

    // flipping any prefix byte -- version, either end of the nonce, the id, the
    // peer -- breaks authentication, which is what proves all 32 bytes are the
    // associated data and not merely written next to the ciphertext
    for (const std::size_t at : {std::size_t{0}, std::size_t{1}, std::size_t{15},
                                 std::size_t{17}, std::size_t{25}}) {
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
    // truncated ciphertext, and one below the shortest datagram there is
    CHECK(!channel::open(out, fex::bytes{dgram.data(), n - 1}, k).has_value());
    CHECK(!channel::open(out, fex::bytes{dgram.data(), wire::min_datagram - 1}, k)
               .has_value());
    // an empty command still seals and opens: 32 bytes of prefix and a tag
    const auto e = channel::seal(dgram, 7, 0, fex::bytes{}, k);
    REQUIRE(e == wire::min_datagram);
    CHECK(channel::open(out, fex::bytes{dgram.data(), e}, k) == 0);
    // wrong key
    channel::key other{};
    CHECK(!channel::open(out, fex::bytes{dgram.data(), n}, other).has_value());
}

SCENARIO("a fresh nonce every time") {
    using namespace fex;
    channel::key k{};
    std::array<fex::u8, wire::datagram_max> one{}, two{};
    const auto n = channel::seal(one, 1, 0, fex::bytes{}, k);
    REQUIRE(n == channel::seal(two, 1, 0, fex::bytes{}, k));
    CHECK(!std::equal(one.data() + 1, one.data() + 1 + wire::nonce_size, two.data() + 1));
}

SCENARIO("seal refuses oversized commands") {
    using namespace fex;
    channel::key k{};
    std::array<fex::u8, wire::max_command + 1> big{};
    std::array<fex::u8, 2 * wire::datagram_max> out{};
    CHECK(channel::seal(out, 1, 0, fex::bytes{big}, k) == 0);
    CHECK(channel::seal(out, 1, 0, fex::bytes{big.data(), wire::max_command}, k)
          == wire::datagram_max);
}

}

#endif
