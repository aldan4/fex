// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// Identity documents (doc/fex_spec.md #3). Two shapes, both dano:
//
//   identity       :kind "identity"      :algo "x25519" :pub "..." :priv "..."
//   identity card  :kind "identity_card" :algo "x25519" :pub "..." [:addr "..."]
//
// The formats are not part of the protocol -- they are general identity documents, and
// fex only states requirements on them: the kind above, `algo` = "x25519", and, for a
// relay's card, an `addr`. Unknown keys are ignored, hex is lowercase, and an identity
// carries a secret so it is written 0600 and never leaves the node.

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#include <dano/dano.hpp>

#include <fex/crypto.hpp>
#include <fex/path.hpp>

#if defined(FEX_WITH_TESTS) || defined(FEX_WITH_BENCHS)
#include <doctest/doctest.h>
#endif

namespace fex {

inline constexpr std::string_view identity_kind = "identity";
inline constexpr std::string_view identity_card_kind = "identity_card";
inline constexpr std::string_view identity_algo = "x25519";

// The private half is the node's whole security: owner-only, per #3.
inline constexpr ::mode_t identity_mode = 0600;
inline constexpr ::mode_t identity_card_mode = 0644;

using public_key = crypto::x25519::public_key;
using secret_key = crypto::x25519::secret_key;

struct identity {
    public_key pub{};
    secret_key priv{};
};

// `addr` is empty on a member's card and required on a relay's. `intro` is the
// node's public self-description, carried over from the profile (#3); fex never
// reads it, it is there for the people working with the registry.
struct identity_card {
    public_key pub{};
    std::string addr;
    std::string intro;
};

// ---- hex -------------------------------------------------------------------

[[nodiscard]] inline std::string to_hex(fex::bytes in) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() * 2);
    for (const auto b : in) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

// Strict: hex of either case, and exactly enough of it to fill `out`.
[[nodiscard]] inline bool from_hex(std::span<std::uint8_t> out, std::string_view hex) noexcept {
    if (hex.size() != out.size() * 2) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int hi = nibble(hex[i * 2]);
        const int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>(hi << 4 | lo);
    }
    return true;
}

// ---- fingerprint -----------------------------------------------------------

// id = hash(pub)[0:8], read little-endian (#2). Those same eight bytes are what people
// compare out of band, so fingerprint_hex() renders them in stored order.
[[nodiscard]] inline std::uint64_t fingerprint(const public_key& pub) noexcept {
    const auto digest = crypto::ascon::hash256(pub);
    std::uint64_t id = 0;
    for (std::size_t i = 0; i < 8; ++i) id |= std::uint64_t{digest[i]} << (8 * i);
    return id;
}

[[nodiscard]] inline std::string fingerprint_hex(const public_key& pub) {
    const auto digest = crypto::ascon::hash256(pub);
    return to_hex(fex::bytes{digest}.first(8));
}

// ---- values ----------------------------------------------------------------

// dano strings carry no escapes, so a quote or a line break in a value would produce a
// document that no longer parses. Nothing fex writes may contain either.
[[nodiscard]] inline bool is_writable_string(std::string_view s) noexcept {
    for (const char c : s)
        if (c == '"' || static_cast<unsigned char>(c) < 0x20 || c == 0x7f) return false;
    return true;
}

// A relay address is a host and a port. The host may be a name, so it is neither
// resolved nor parsed further here -- only the port is checked.
[[nodiscard]] inline bool is_valid_addr(std::string_view addr) noexcept {
    if (addr.empty() || addr.size() > 255 || !is_writable_string(addr)) return false;
    const auto colon = addr.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 == addr.size()) return false;
    const auto port = addr.substr(colon + 1);
    if (port.size() > 5) return false;
    unsigned value = 0;
    for (const char c : port) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<unsigned>(c - '0');
    }
    return value > 0 && value <= 65535;
}

// ---- writing ---------------------------------------------------------------

[[nodiscard]] inline std::string to_dano(const identity& id) {
    std::string out = ":kind \"";
    out += identity_kind;
    out += "\" :algo \"";
    out += identity_algo;
    out += "\" :pub \"";
    out += to_hex(id.pub);
    out += "\" :priv \"";
    out += to_hex(id.priv);
    out += "\"\n";
    return out;
}

[[nodiscard]] inline std::string to_dano(const identity_card& card) {
    std::string out = ":kind \"";
    out += identity_card_kind;
    out += "\" :algo \"";
    out += identity_algo;
    out += "\" :pub \"";
    out += to_hex(card.pub);
    out += "\"";
    if (!card.addr.empty()) {
        out += " :addr \"";
        out += card.addr;
        out += "\"";
    }
    if (!card.intro.empty()) {
        out += " :intro \"";
        out += card.intro;
        out += "\"";
    }
    out += "\n";
    return out;
}

// Create `path` and write `text` to it. Fails with std::errc::file_exists rather than
// overwriting: an identity that already exists is a key nobody can recover.
[[nodiscard]] inline std::expected<void, std::errc> write_new_file(const char* path,
                                                                   std::string_view text,
                                                                   ::mode_t mode) noexcept {
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
    if (fd < 0) return std::unexpected(static_cast<std::errc>(errno));
    // O_CREAT's mode is filtered through the umask, which for 0600 would usually leave
    // it alone -- but "usually" is not good enough for a secret key.
    auto fail = [&](int code) {
        ::close(fd);
        ::unlink(path); // a half-written key file is worse than none
        return std::unexpected(static_cast<std::errc>(code));
    };
    if (::fchmod(fd, mode) != 0) return fail(errno);
    const char* at = text.data();
    std::size_t left = text.size();
    while (left > 0) {
        const auto written = ::write(fd, at, left);
        if (written < 0) {
            if (errno == EINTR) continue;
            return fail(errno);
        }
        at += written;
        left -= static_cast<std::size_t>(written);
    }
    if (::close(fd) != 0) {
        const int code = errno;
        ::unlink(path);
        return std::unexpected(static_cast<std::errc>(code));
    }
    return {};
}

// ---- reading ---------------------------------------------------------------

namespace detail {

[[nodiscard]] inline std::errc as_errc(const std::error_code& ec) noexcept {
    if (ec.category() == std::generic_category()) return static_cast<std::errc>(ec.value());
    return std::errc::invalid_argument; // a dano error: the document is malformed
}

// The keys fex looks for. Anything else is left unread, which the map iterator skips
// on its own as it advances.
struct fields {
    std::string_view kind, algo, pub, priv, addr, intro;
};

[[nodiscard]] inline std::expected<fields, std::errc> read_fields(dano::value root) noexcept {
    auto doc = root.map();
    if (!doc) return std::unexpected(as_errc(doc.error()));
    fields f;
    while (doc->has_next()) {
        auto entry = doc->next();
        if (!entry) return std::unexpected(as_errc(entry.error()));
        auto& [key, value] = *entry;
        std::string_view* const slot = key == "kind" ? &f.kind
                                     : key == "algo" ? &f.algo
                                     : key == "pub"  ? &f.pub
                                     : key == "priv" ? &f.priv
                                     : key == "addr" ? &f.addr
                                     : key == "intro" ? &f.intro
                                                     : nullptr;
        if (slot == nullptr) continue;
        auto text = value.string();
        if (!text) return std::unexpected(as_errc(text.error()));
        *slot = *text;
    }
    return f;
}

// The public key is checked against the private one: a pair that does not agree is a
// corrupt file, not a usable identity.
[[nodiscard]] inline std::expected<identity, std::errc> identity_of(const fields& f) noexcept {
    if (f.kind != identity_kind || f.algo != identity_algo)
        return std::unexpected(std::errc::invalid_argument);
    identity id;
    if (!from_hex(id.pub, f.pub) || !from_hex(id.priv, f.priv))
        return std::unexpected(std::errc::invalid_argument);
    if (crypto::x25519::derive_public(id.priv) != id.pub)
        return std::unexpected(std::errc::invalid_argument);
    return id;
}

// `require_addr` is set for a relay's card, where #3 makes `addr` mandatory; a member's
// card may still carry one, and it is kept if present.
[[nodiscard]] inline std::expected<identity_card, std::errc> card_of(const fields& f,
                                                                     bool require_addr) {
    if (f.kind != identity_card_kind || f.algo != identity_algo)
        return std::unexpected(std::errc::invalid_argument);
    if (require_addr && f.addr.empty()) return std::unexpected(std::errc::invalid_argument);
    if (!f.addr.empty() && !is_valid_addr(f.addr)) return std::unexpected(std::errc::invalid_argument);
    if (!is_writable_string(f.intro)) return std::unexpected(std::errc::invalid_argument);
    identity_card card;
    if (!from_hex(card.pub, f.pub)) return std::unexpected(std::errc::invalid_argument);
    card.addr = f.addr;
    card.intro = f.intro;
    return card;
}

} // namespace detail

[[nodiscard]] inline std::expected<identity, std::errc> parse_identity(std::string_view text) noexcept {
    auto reader = dano::reader::from_text(text);
    if (!reader) return std::unexpected(detail::as_errc(reader.error()));
    const auto f = detail::read_fields(reader->root());
    if (!f) return std::unexpected(f.error());
    return detail::identity_of(*f);
}

[[nodiscard]] inline std::expected<identity_card, std::errc>
parse_identity_card(std::string_view text, bool require_addr = false) {
    auto reader = dano::reader::from_text(text);
    if (!reader) return std::unexpected(detail::as_errc(reader.error()));
    const auto f = detail::read_fields(reader->root());
    if (!f) return std::unexpected(f.error());
    return detail::card_of(*f, require_addr);
}

[[nodiscard]] inline std::expected<identity, std::errc> read_identity(const char* path) noexcept {
    auto reader = dano::reader::from_file(path);
    if (!reader) return std::unexpected(detail::as_errc(reader.error()));
    const auto f = detail::read_fields(reader->root());
    if (!f) return std::unexpected(f.error());
    return detail::identity_of(*f);
}

[[nodiscard]] inline std::expected<identity_card, std::errc>
read_identity_card(const char* path, bool require_addr = false) {
    auto reader = dano::reader::from_file(path);
    if (!reader) return std::unexpected(detail::as_errc(reader.error()));
    const auto f = detail::read_fields(reader->root());
    if (!f) return std::unexpected(f.error());
    return detail::card_of(*f, require_addr);
}

// ---- generating ------------------------------------------------------------

[[nodiscard]] inline identity generate_identity() noexcept {
    const auto kp = crypto::x25519::keypair();
    return identity{.pub = kp.pk, .priv = kp.sk};
}

// The card exports the public half; `addr` turns it into a relay's card.
[[nodiscard]] inline identity_card card_of(const identity& id, std::string_view addr = {},
                                           std::string_view intro = {}) {
    return identity_card{.pub = id.pub, .addr = std::string{addr},
                         .intro = std::string{intro}};
}

} // namespace fex

// ---- Tests -----------------------------------------------------------------

#ifdef FEX_WITH_TESTS

#include <cstdlib>

TEST_CASE("hex round-trips and rejects malformed input") {
    const std::array<std::uint8_t, 4> in{0x00, 0x0f, 0xa5, 0xff};
    REQUIRE_EQ(fex::to_hex(in), "000fa5ff");

    std::array<std::uint8_t, 4> out{};
    REQUIRE(fex::from_hex(out, "000fa5ff"));
    REQUIRE_EQ(out, in);
    REQUIRE(fex::from_hex(out, "000FA5FF")); // uppercase reads, lowercase writes
    REQUIRE_EQ(out, in);

    REQUIRE_FALSE(fex::from_hex(out, "000fa5f"));   // odd length
    REQUIRE_FALSE(fex::from_hex(out, "000fa5ffff")); // too long
    REQUIRE_FALSE(fex::from_hex(out, "000fa5fg"));   // not hex
}

TEST_CASE("fingerprint is hash(pub)[0:8] little-endian") {
    const auto id = fex::generate_identity();
    const auto digest = fex::crypto::ascon::hash256(id.pub);
    const auto hex = fex::fingerprint_hex(id.pub);
    REQUIRE_EQ(hex, fex::to_hex(fex::bytes{digest}.first(8)));

    std::uint64_t expected = 0;
    for (std::size_t i = 0; i < 8; ++i) expected |= std::uint64_t{digest[i]} << (8 * i);
    REQUIRE_EQ(fex::fingerprint(id.pub), expected);
}

TEST_CASE("identity documents round-trip") {
    const auto id = fex::generate_identity();
    const auto text = fex::to_dano(id);
    REQUIRE(text.starts_with(":kind \"identity\" :algo \"x25519\" :pub \""));

    const auto parsed = fex::parse_identity(text);
    REQUIRE(parsed.has_value());
    REQUIRE_EQ(parsed->pub, id.pub);
    REQUIRE_EQ(parsed->priv, id.priv);
}

TEST_CASE("cards round-trip, with and without an address") {
    const auto id = fex::generate_identity();

    const auto member = fex::card_of(id);
    const auto member_text = fex::to_dano(member);
    REQUIRE(member_text.find(":addr") == std::string::npos);
    const auto read_member = fex::parse_identity_card(member_text);
    REQUIRE(read_member.has_value());
    REQUIRE_EQ(read_member->pub, id.pub);
    REQUIRE(read_member->addr.empty());

    const auto relay = fex::card_of(id, "relay.example.net:4444");
    const auto read_relay = fex::parse_identity_card(fex::to_dano(relay), true);
    REQUIRE(read_relay.has_value());
    REQUIRE_EQ(read_relay->addr, "relay.example.net:4444");

    // A relay's card without :addr is a configuration error (#3).
    REQUIRE_FALSE(fex::parse_identity_card(member_text, true).has_value());
}

TEST_CASE("cards carry the profile's intro (#3)") {
    const auto id = fex::generate_identity();

    // a member's card: intro without an address
    const auto member = fex::card_of(id, {}, "family photo archive");
    const auto member_text = fex::to_dano(member);
    REQUIRE(member_text.find(":addr") == std::string::npos);
    REQUIRE(member_text.find(":intro \"family photo archive\"") != std::string::npos);
    const auto read_member = fex::parse_identity_card(member_text);
    REQUIRE(read_member.has_value());
    REQUIRE_EQ(read_member->intro, "family photo archive");

    // a relay's card: the profile keys follow :pub, in the order of #3
    const auto relay = fex::card_of(id, "relay.example.net:4444", "home relay");
    const auto relay_text = fex::to_dano(relay);
    REQUIRE(relay_text.find(":addr") < relay_text.find(":intro"));
    const auto read_relay = fex::parse_identity_card(relay_text, true);
    REQUIRE(read_relay.has_value());
    REQUIRE_EQ(read_relay->addr, "relay.example.net:4444");
    REQUIRE_EQ(read_relay->intro, "home relay");

    // no intro means no key at all, and the field reads back empty
    const auto bare = fex::card_of(id);
    REQUIRE(fex::to_dano(bare).find(":intro") == std::string::npos);
    REQUIRE(fex::parse_identity_card(fex::to_dano(bare))->intro.empty());

    // a control character survives dano's lexer but would make the card
    // unwritable, so a card carrying one is refused on read
    const auto pub = fex::to_hex(id.pub);
    REQUIRE_FALSE(fex::parse_identity_card(
        ":kind \"identity_card\" :algo \"x25519\" :pub \"" + pub + "\" :intro \"a\tb\"")
        .has_value());
    REQUIRE(fex::parse_identity_card(
        ":kind \"identity_card\" :algo \"x25519\" :pub \"" + pub + "\" :intro \"a b\"")
        .has_value());
    REQUIRE_FALSE(fex::is_writable_string("say \"hi\""));
    REQUIRE(fex::is_writable_string("family photo archive"));
}

TEST_CASE("malformed identity documents are refused") {
    const auto id = fex::generate_identity();
    const auto pub = fex::to_hex(id.pub);
    const auto priv = fex::to_hex(id.priv);
    auto document = [&](std::string_view kind, std::string_view algo, std::string_view p) {
        return ":kind \"" + std::string{kind} + "\" :algo \"" + std::string{algo}
             + "\" :pub \"" + std::string{p} + "\" :priv \"" + priv + "\"\n";
    };

    REQUIRE(fex::parse_identity(document("identity", "x25519", pub)).has_value());
    REQUIRE_FALSE(fex::parse_identity(document("identity_card", "x25519", pub)).has_value());
    REQUIRE_FALSE(fex::parse_identity(document("identity", "ed25519", pub)).has_value());
    REQUIRE_FALSE(fex::parse_identity(document("identity", "x25519", "zz")).has_value());
    REQUIRE_FALSE(fex::parse_identity(":algo \"x25519\" :pub \"" + pub + "\"\n").has_value());
    REQUIRE_FALSE(fex::parse_identity(":kind \"identity\" :algo").has_value()); // truncated

    // A public key that does not belong to the private one means a corrupt file.
    const auto other = fex::generate_identity();
    REQUIRE_FALSE(fex::parse_identity(document("identity", "x25519", fex::to_hex(other.pub))).has_value());

    // Unknown keys are ignored, whatever they hold.
    const auto extra = ":note \"whatever\" :kind \"identity\" :algo \"x25519\" :pub \"" + pub
                     + "\" :priv \"" + priv + "\" :tags [1 2 3]\n";
    REQUIRE(fex::parse_identity(extra).has_value());
}

TEST_CASE("relay addresses are checked") {
    REQUIRE(fex::is_valid_addr("relay.example.net:4444"));
    REQUIRE(fex::is_valid_addr("1.2.3.4:1"));
    REQUIRE(fex::is_valid_addr("[::1]:65535"));

    REQUIRE_FALSE(fex::is_valid_addr(""));
    REQUIRE_FALSE(fex::is_valid_addr("relay.example.net"));  // no port
    REQUIRE_FALSE(fex::is_valid_addr("relay.example.net:"));
    REQUIRE_FALSE(fex::is_valid_addr(":4444"));
    REQUIRE_FALSE(fex::is_valid_addr("relay:0"));
    REQUIRE_FALSE(fex::is_valid_addr("relay:65536"));
    REQUIRE_FALSE(fex::is_valid_addr("relay:44a4"));
    // dano has no string escapes, so these could not be written back out.
    REQUIRE_FALSE(fex::is_valid_addr("re\"lay:4444"));
    REQUIRE_FALSE(fex::is_valid_addr("relay\n:4444"));
}

TEST_CASE("identity files are created 0600 and never overwritten") {
    char dir[] = "/tmp/fex-identity-XXXXXX";
    REQUIRE(::mkdtemp(dir) != nullptr);
    const std::string path = std::string{dir} + "/node.dano";

    const auto id = fex::generate_identity();
    REQUIRE(fex::write_new_file(path.c_str(), fex::to_dano(id), fex::identity_mode).has_value());

    struct ::stat info{};
    REQUIRE_EQ(::stat(path.c_str(), &info), 0);
    REQUIRE_EQ(info.st_mode & 07777, fex::identity_mode);

    const auto again = fex::write_new_file(path.c_str(), "replaced\n", fex::identity_mode);
    REQUIRE_FALSE(again.has_value());
    REQUIRE(again.error() == std::errc::file_exists);

    const auto loaded = fex::read_identity(path.c_str());
    REQUIRE(loaded.has_value());
    REQUIRE_EQ(loaded->pub, id.pub);
    REQUIRE_EQ(loaded->priv, id.priv);

    // A card is not an identity and vice versa, whichever way round they are read.
    REQUIRE_FALSE(fex::read_identity_card(path.c_str()).has_value());
    REQUIRE_FALSE(fex::read_identity("/nonexistent/fex/node.dano").has_value());

    ::unlink(path.c_str());
    ::rmdir(dir);
}

#endif // FEX_WITH_TESTS
