// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Thin C++ wrappers over the compiled crypto primitives:
//   - Ascon-Hash256, Ascon-CXOF128, Ascon-AEAD128 (NIST SP 800-232) from ascon-c
//   - X25519 key exchange and Ed25519 signatures from TweetNaCl

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include <fex/types.hpp>

#if defined(FEX_WITH_TESTS) || defined(FEX_WITH_BENCHS)
#include <doctest/doctest.h>
#endif

#ifdef FEX_WITH_BENCHS
#include <nanobench.h>
#endif

extern "C" {

// ascon-c entry points, renamed from the generic crypto_* names in build.zig
int fex_ascon_hash256(unsigned char* out, const unsigned char* in, unsigned long long inlen);
int fex_ascon_cxof128(unsigned char* out, unsigned long long outlen,
                      const unsigned char* in, unsigned long long inlen,
                      const unsigned char* cs, unsigned long long cslen);
int fex_ascon_aead128_encrypt(unsigned char* c, unsigned long long* clen,
                              const unsigned char* m, unsigned long long mlen,
                              const unsigned char* ad, unsigned long long adlen,
                              const unsigned char* nsec, const unsigned char* npub,
                              const unsigned char* k);
int fex_ascon_aead128_decrypt(unsigned char* m, unsigned long long* mlen, unsigned char* nsec,
                              const unsigned char* c, unsigned long long clen,
                              const unsigned char* ad, unsigned long long adlen,
                              const unsigned char* npub, const unsigned char* k);

// TweetNaCl (canonical 20140427 release). Declared here rather than including
// <tweetnacl.h>, whose unprefixed crypto_* macros would leak into every translation unit;
// these are the real exported symbols, which keep the library's _tweet suffix.
int crypto_scalarmult_curve25519_tweet(std::uint8_t* q, const std::uint8_t* n, const std::uint8_t* p);
int crypto_scalarmult_curve25519_tweet_base(std::uint8_t* q, const std::uint8_t* n);
int crypto_verify_32_tweet(const std::uint8_t* x, const std::uint8_t* y);
int crypto_sign_ed25519_tweet_keypair(std::uint8_t* pk, std::uint8_t* sk);
int crypto_sign_ed25519_tweet(std::uint8_t* sm, unsigned long long* smlen,
                              const std::uint8_t* m, unsigned long long mlen,
                              const std::uint8_t* sk);
int crypto_sign_ed25519_tweet_open(std::uint8_t* m, unsigned long long* mlen,
                                   const std::uint8_t* sm, unsigned long long smlen,
                                   const std::uint8_t* pk);

// System CSPRNG (src/randombytes.c); also the entropy hook TweetNaCl requires.
void randombytes(std::uint8_t* out, unsigned long long n);

} // extern "C"

namespace fex::crypto {

// ---- Ascon-Hash256 ---------------------------------------------------------

namespace ascon {

inline constexpr std::size_t hash_bytes = 32;
inline constexpr std::size_t key_bytes = 16;
inline constexpr std::size_t nonce_bytes = 16;
inline constexpr std::size_t tag_bytes = 16;

using digest = std::array<std::uint8_t, hash_bytes>;
using key = std::array<std::uint8_t, key_bytes>;
using nonce = std::array<std::uint8_t, nonce_bytes>;

inline digest hash256(bytes msg) noexcept {
    digest out;
    fex_ascon_hash256(out.data(), msg.data(), msg.size());
    return out;
}

// Customized XOF: fills `out` entirely. `custom` is the customization string (<= 256 bytes).
inline void cxof128(std::span<std::uint8_t> out, bytes msg, bytes custom) noexcept {
    fex_ascon_cxof128(out.data(), out.size(), msg.data(), msg.size(), custom.data(), custom.size());
}

// AEAD encrypt: `out` must hold msg.size() + tag_bytes. Returns bytes written.
inline std::size_t aead128_encrypt(std::span<std::uint8_t> out, bytes msg, bytes ad,
                                   const nonce& n, const key& k) noexcept {
    unsigned long long clen = 0;
    fex_ascon_aead128_encrypt(out.data(), &clen, msg.data(), msg.size(),
                              ad.data(), ad.size(), nullptr, n.data(), k.data());
    return static_cast<std::size_t>(clen);
}

// AEAD decrypt: `out` must hold ct.size() - tag_bytes. Returns false on authentication failure.
[[nodiscard]] inline bool aead128_decrypt(std::span<std::uint8_t> out, bytes ct, bytes ad,
                                          const nonce& n, const key& k) noexcept {
    if (ct.size() < tag_bytes) return false;
    unsigned long long mlen = 0;
    return fex_ascon_aead128_decrypt(out.data(), &mlen, nullptr, ct.data(), ct.size(),
                                     ad.data(), ad.size(), n.data(), k.data()) == 0;
}

} // namespace ascon

// Fill with bytes from the system CSPRNG (getentropy / BCryptGenRandom).
inline void random_bytes(std::span<std::uint8_t> out) noexcept {
    randombytes(out.data(), out.size());
}

// ---- X25519 (RFC 7748) -----------------------------------------------------

namespace x25519 {

inline constexpr std::size_t public_key_bytes = 32;
inline constexpr std::size_t secret_key_bytes = 32;
inline constexpr std::size_t shared_secret_bytes = 32;

using public_key = std::array<std::uint8_t, public_key_bytes>;
using secret_key = std::array<std::uint8_t, secret_key_bytes>;
using shared_secret = std::array<std::uint8_t, shared_secret_bytes>;

struct keypair_t {
    public_key pk;
    secret_key sk;
};

inline keypair_t keypair() noexcept {
    keypair_t kp;
    random_bytes(kp.sk); // clamped inside crypto_scalarmult, so no shaping needed here
    crypto_scalarmult_curve25519_tweet_base(kp.pk.data(), kp.sk.data());
    return kp;
}

// Derive our public key from an existing secret (e.g. one loaded from disk).
inline public_key derive_public(const secret_key& sk) noexcept {
    public_key pk;
    crypto_scalarmult_curve25519_tweet_base(pk.data(), sk.data());
    return pk;
}

// Raw X25519. Returns false if `peer` is a low-order point, which would yield an
// all-zero secret shared by every party. The result is *not* uniformly random: run it
// through a KDF (ascon::cxof128) before using it as a key.
[[nodiscard]] inline bool exchange(shared_secret& out, const secret_key& sk,
                                   const public_key& peer) noexcept {
    crypto_scalarmult_curve25519_tweet(out.data(), sk.data(), peer.data());
    constexpr shared_secret zero{};
    return crypto_verify_32_tweet(out.data(), zero.data()) != 0;
}

} // namespace x25519

// ---- Ed25519 (RFC 8032) ----------------------------------------------------

namespace ed25519 {

inline constexpr std::size_t signature_bytes = 64;
inline constexpr std::size_t public_key_bytes = 32;
inline constexpr std::size_t secret_key_bytes = 64; // seed || public key

using public_key = std::array<std::uint8_t, public_key_bytes>;
using secret_key = std::array<std::uint8_t, secret_key_bytes>;

struct keypair_t {
    public_key pk;
    secret_key sk;
};

inline keypair_t keypair() noexcept {
    keypair_t kp;
    crypto_sign_ed25519_tweet_keypair(kp.pk.data(), kp.sk.data());
    return kp;
}

// TweetNaCl only offers combined mode: signature and message travel in one buffer, of
// this size. `open` needs a buffer this large too -- see below.
inline constexpr std::size_t signed_bytes(std::size_t msg_len) noexcept {
    return msg_len + signature_bytes;
}

// Sign `msg` into `out`, which must hold signed_bytes(msg.size()).
// Returns bytes written, or 0 if `out` is too small.
inline std::size_t sign(std::span<std::uint8_t> out, bytes msg, const secret_key& sk) noexcept {
    if (out.size() < signed_bytes(msg.size())) return 0;
    unsigned long long smlen = 0;
    crypto_sign_ed25519_tweet(out.data(), &smlen, msg.data(), msg.size(), sk.data());
    return static_cast<std::size_t>(smlen);
}

// Verify `sm` and recover the message into out.first(sm.size() - signature_bytes).
// `out` must hold sm.size() bytes, not sm.size() - signature_bytes: crypto_sign_open
// copies the entire signed message into the buffer before shifting the payload down.
// Returns false on a bad signature, leaving `out` zeroed.
[[nodiscard]] inline bool open(std::span<std::uint8_t> out, bytes sm,
                               const public_key& pk) noexcept {
    // crypto_sign_open indexes the buffer with a plain int, so cap the length well
    // below INT_MAX rather than letting it overflow.
    if (sm.size() < signature_bytes || out.size() < sm.size() || sm.size() > 0x7ffffffful)
        return false;
    unsigned long long mlen = 0;
    return crypto_sign_ed25519_tweet_open(out.data(), &mlen, sm.data(), sm.size(), pk.data()) == 0;
}

} // namespace ed25519

} // namespace fex::crypto

// ---- Tests (known-answer vectors from ascon-c KAT files) --------------------

#ifdef FEX_WITH_TESTS

#include <string_view>
#include <vector>

namespace fex::crypto::detail {

inline std::vector<std::uint8_t> unhex(std::string_view hex) {
    auto nibble = [](char c) -> std::uint8_t {
        return static_cast<std::uint8_t>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    };
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(nibble(hex[i]) << 4 | nibble(hex[i + 1])));
    return out;
}

template <std::size_t N>
std::array<std::uint8_t, N> unhex_array(std::string_view hex) {
    auto v = unhex(hex);
    std::array<std::uint8_t, N> a{};
    for (std::size_t i = 0; i < N && i < v.size(); ++i) a[i] = v[i];
    return a;
}

} // namespace fex::crypto::detail

TEST_CASE("ascon-hash256 matches LWC_HASH_KAT_128_256") {
    using namespace fex;
    using namespace fex::crypto;
    struct kat { std::string_view msg, md; };
    constexpr kat vectors[] = {
        {"", "0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2"},
        {"00", "0728621035AF3ED2BCA03BF6FDE900F9456F5330E4B5EE23E7F6A1E70291BC80"},
        {"0001020304050607", "B88E497AE8E6FB641B87EF622EB8F2FCA0ED95383F7FFEBE167ACF1099BA764F"},
    };
    for (const auto& v : vectors) {
        const auto msg = detail::unhex(v.msg);
        REQUIRE_EQ(ascon::hash256(msg), detail::unhex_array<32>(v.md));
    }
}

TEST_CASE("ascon-cxof128 matches LWC_CXOF_KAT_128_512") {
    using namespace fex;
    using namespace fex::crypto;
    struct kat { std::string_view msg, z, md; };
    constexpr kat vectors[] = {
        {"", "", "4F50159EF70BB3DAD8807E034EAEBD44C4FA2CBBC8CF1F05511AB66CDCC529905CA12083FC186AD899B270B1473DC5F7EC88D1052082DCDFE69FB75D269E7B74"},
        {"", "10", "0C93A483E7D574D49FE52CCE03EE646117977D57A8AA57704AB4DAF44B501430FF6AC11A5D1FD6F2154B5C65728268270C8BB578508487B8965718ADA6272FD6"},
    };
    for (const auto& v : vectors) {
        const auto msg = detail::unhex(v.msg);
        const auto z = detail::unhex(v.z);
        std::array<std::uint8_t, 64> out{};
        ascon::cxof128(out, msg, z);
        REQUIRE_EQ(out, detail::unhex_array<64>(v.md));
    }
}

TEST_CASE("ascon-aead128 matches LWC_AEAD_KAT_128_128 and rejects tampering") {
    using namespace fex;
    using namespace fex::crypto;
    const auto k = detail::unhex_array<16>("000102030405060708090A0B0C0D0E0F");
    const auto n = detail::unhex_array<16>("101112131415161718191A1B1C1D1E1F");
    struct kat { std::string_view pt, ad, ct; };
    constexpr kat vectors[] = {
        {"", "", "4F9C278211BEC9316BF68F46EE8B2EC6"},
        {"", "303132333435363738393A3B3C3D3E3F40", "BD8851CD3AF9847844839A791DD70E8C"},
        {"20", "", "E8DD576ABA1CD3E6FC704DE02AEDB79588"},
        {"20", "30", "962B8016836C75A7D86866588CA245D886"},
        {"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", "",
         "E8C3DEEE246CC5EAE3E872313897A2BB6089AA3E15E80307970F2D1F006654C2AAA5FA172CB9F07D07463CEFC7440BC1"},
    };
    for (const auto& v : vectors) {
        const auto pt = detail::unhex(v.pt);
        const auto ad = detail::unhex(v.ad);
        const auto expected = detail::unhex(v.ct);

        std::vector<std::uint8_t> ct(pt.size() + ascon::tag_bytes);
        REQUIRE_EQ(ascon::aead128_encrypt(ct, pt, ad, n, k), expected.size());
        REQUIRE_EQ(ct, expected);

        std::vector<std::uint8_t> dec(pt.size());
        REQUIRE(ascon::aead128_decrypt(dec, ct, ad, n, k));
        REQUIRE_EQ(dec, pt);

        ct.back() ^= 0x01;
        REQUIRE_FALSE(ascon::aead128_decrypt(dec, ct, ad, n, k));
    }
}

TEST_CASE("x25519 matches RFC 7748 section 6.1 and rejects low-order points") {
    using namespace fex;
    using namespace fex::crypto;
    const auto a_sk = detail::unhex_array<32>("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const auto a_pk = detail::unhex_array<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const auto b_sk = detail::unhex_array<32>("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const auto b_pk = detail::unhex_array<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const auto expected = detail::unhex_array<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    REQUIRE_EQ(x25519::derive_public(a_sk), a_pk);
    REQUIRE_EQ(x25519::derive_public(b_sk), b_pk);

    x25519::shared_secret ab{}, ba{};
    REQUIRE(x25519::exchange(ab, a_sk, b_pk));
    REQUIRE(x25519::exchange(ba, b_sk, a_pk));
    REQUIRE_EQ(ab, expected);
    REQUIRE_EQ(ba, expected);

    // The all-zero point has order 1; every secret maps it to an all-zero shared secret.
    x25519::shared_secret degenerate{};
    REQUIRE_FALSE(x25519::exchange(degenerate, a_sk, x25519::public_key{}));
}

TEST_CASE("x25519 fresh keypairs agree") {
    using namespace fex;
    using namespace fex::crypto;
    const auto a = x25519::keypair();
    const auto b = x25519::keypair();
    REQUIRE_NE(a.pk, b.pk);

    x25519::shared_secret ab{}, ba{};
    REQUIRE(x25519::exchange(ab, a.sk, b.pk));
    REQUIRE(x25519::exchange(ba, b.sk, a.pk));
    REQUIRE_EQ(ab, ba);
}

TEST_CASE("ed25519 matches RFC 8032 section 7.1") {
    using namespace fex;
    using namespace fex::crypto;
    struct kat { std::string_view seed, pk, msg, sig; };
    constexpr kat vectors[] = {
        {"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
        {"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
        {"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
    };
    for (const auto& v : vectors) {
        // TweetNaCl's 64-byte secret key is the RFC's seed followed by the public key.
        const auto seed = detail::unhex_array<32>(v.seed);
        const auto pk = detail::unhex_array<32>(v.pk);
        ed25519::secret_key sk{};
        for (std::size_t i = 0; i < 32; ++i) sk[i] = seed[i], sk[i + 32] = pk[i];

        const auto msg = detail::unhex(v.msg);
        const auto sig = detail::unhex(v.sig);

        std::vector<std::uint8_t> sm(ed25519::signed_bytes(msg.size()));
        REQUIRE_EQ(ed25519::sign(sm, msg, sk), sm.size());
        REQUIRE_EQ(std::vector<std::uint8_t>(sm.begin(), sm.begin() + 64), sig);
        REQUIRE_EQ(std::vector<std::uint8_t>(sm.begin() + 64, sm.end()), msg);

        std::vector<std::uint8_t> out(sm.size());
        REQUIRE(ed25519::open(out, sm, pk));
        REQUIRE_EQ(std::vector<std::uint8_t>(out.begin(), out.begin() + msg.size()), msg);
    }
}

TEST_CASE("ed25519 rejects tampering and undersized buffers") {
    using namespace fex;
    using namespace fex::crypto;
    const auto kp = ed25519::keypair();
    const std::vector<std::uint8_t> msg{1, 2, 3, 4, 5};

    std::vector<std::uint8_t> sm(ed25519::signed_bytes(msg.size()));
    REQUIRE_EQ(ed25519::sign(sm, msg, kp.sk), sm.size());

    std::vector<std::uint8_t> out(sm.size());
    REQUIRE(ed25519::open(out, sm, kp.pk));
    REQUIRE_EQ(std::vector<std::uint8_t>(out.begin(), out.begin() + msg.size()), msg);

    // A flipped signature bit, a flipped message bit, and the wrong signer all fail.
    auto bad = sm;
    bad[0] ^= 0x01;
    REQUIRE_FALSE(ed25519::open(out, bad, kp.pk));
    bad = sm;
    bad.back() ^= 0x01;
    REQUIRE_FALSE(ed25519::open(out, bad, kp.pk));
    REQUIRE_FALSE(ed25519::open(out, sm, ed25519::keypair().pk));

    // Ed25519 is deterministic, so re-signing reproduces the signature exactly.
    std::vector<std::uint8_t> again(sm.size());
    REQUIRE_EQ(ed25519::sign(again, msg, kp.sk), sm.size());
    REQUIRE_EQ(again, sm);

    // Short buffers are refused rather than overrun.
    std::vector<std::uint8_t> small(sm.size() - 1);
    REQUIRE_EQ(ed25519::sign(small, msg, kp.sk), 0);
    REQUIRE_FALSE(ed25519::open(small, sm, kp.pk));
    REQUIRE_FALSE(ed25519::open(out, bytes{sm}.first(63), kp.pk));
}

TEST_CASE("random_bytes produces non-constant output") {
    std::array<std::uint8_t, 32> a{}, b{};
    fex::crypto::random_bytes(a);
    fex::crypto::random_bytes(b);
    REQUIRE_NE(a, b);
}

#endif // FEX_WITH_TESTS

// ---- Benchmarks --------------------------------------------------------------

#ifdef FEX_WITH_BENCHS

#include <vector>

TEST_CASE("bench: ascon") {
    using namespace fex;
    using namespace fex::crypto;
    std::vector<std::uint8_t> msg(1024, 0xAB);
    ascon::key k{};
    ascon::nonce n{};
    std::vector<std::uint8_t> ct(msg.size() + ascon::tag_bytes), pt(msg.size());

    ankerl::nanobench::Bench b;
    b.batch(msg.size()).unit("byte");
    b.run("ascon-hash256 1KiB", [&] { ankerl::nanobench::doNotOptimizeAway(ascon::hash256(msg)); });
    b.run("ascon-aead128 encrypt 1KiB", [&] { ascon::aead128_encrypt(ct, msg, {}, n, k); });
    b.run("ascon-aead128 decrypt 1KiB", [&] { ankerl::nanobench::doNotOptimizeAway(ascon::aead128_decrypt(pt, ct, {}, n, k)); });
}


TEST_CASE("bench: tweetnacl") {
    using namespace fex;
    using namespace fex::crypto;
    const auto xk = x25519::keypair();
    const auto peer = x25519::keypair();
    x25519::shared_secret ss{};

    const auto ek = ed25519::keypair();
    std::vector<std::uint8_t> msg(1024, 0xAB);
    std::vector<std::uint8_t> sm(ed25519::signed_bytes(msg.size())), out(sm.size());
    ed25519::sign(sm, msg, ek.sk);

    ankerl::nanobench::Bench b;
    b.run("x25519 keypair", [&] { ankerl::nanobench::doNotOptimizeAway(x25519::keypair()); });
    b.run("x25519 exchange", [&] { ankerl::nanobench::doNotOptimizeAway(x25519::exchange(ss, xk.sk, peer.pk)); });
    b.run("ed25519 keypair", [&] { ankerl::nanobench::doNotOptimizeAway(ed25519::keypair()); });
    b.run("ed25519 sign 1KiB", [&] { ankerl::nanobench::doNotOptimizeAway(ed25519::sign(sm, msg, ek.sk)); });
    b.run("ed25519 open 1KiB", [&] { ankerl::nanobench::doNotOptimizeAway(ed25519::open(out, sm, ek.pk)); });
}

#endif // FEX_WITH_BENCHS
