// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// The registry (#3) and the published directory (#6) are one file:
//
//   <root>/roster.danl
//
// A member line grants what a member has -- a capsule, and the right to put and
// commit into it -- and the same bytes are what `list` hands out and `get`
// serves. There is no derivation step and nothing to keep in step: the file the
// operator edits is the file every member reads.
//
// That is why an address is not here. A federated relay has to be reachable and
// the roster must not say where anybody is (#6), so when federation arrives its
// addresses belong in a file of their own, next to this one and never published.
// A `relay` line is already carried through to readers; it simply grants
// nothing yet.
//
// Registration is appending a line, removal is deleting one, renaming is
// editing `:name`. The file is re-read when its mtime moves.

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include <fex/crypto.hpp>
#include <fex/fs.hpp>
#include <fex/identity.hpp>
#include <fex/path.hpp>
#include <fex/roster.hpp>
#include <fex/types.hpp>

#ifdef FEX_WITH_TESTS
#include <doctest/doctest.h>
#endif

namespace fex::relay {

struct member {
    std::string name; // #8 segment rules, the name of the capsule directory
    crypto::x25519::public_key pub;
    u64 id;
}; // member

class registry {
    hash_map<u64, member> by_id_;
    std::string text_;  // the file verbatim: what list points at and get serves
    hash256 hash_{};
    u64 mtime_ns_ = 0;

public:

    [[nodiscard]] static std::expected<registry, std::errc>
    load(const std::string& path) noexcept {
        registry reg;
        const auto st = fs::stat_of(path.c_str());
        reg.mtime_ns_ = st.mtime_ns;
        if (st.kind == fs::entry_kind::missing) {
            // a relay nobody is registered on yet: empty, and able to say so
            reg.hash_ = crypto::ascon::hash256({});
            return reg;
        }
        auto data = fs::read_file(path.c_str());
        if (!data)
            return std::unexpected(data.error());
        reg.text_.assign(reinterpret_cast<const char*>(data->data()), data->size());
        reg.hash_ = crypto::ascon::hash256(fex::bytes{*data});
        // roster::parse rejects the file whole on a duplicate name or key (#3's
        // registry rule), invalid hex or a name breaking #8, so those are not
        // re-checked here
        auto parsed = fex::roster::parse(reg.text_);
        if (!parsed)
            return std::unexpected(parsed.error());
        for (const auto& r : parsed->records) {
            if (r.what() != fex::roster::kind::member)
                continue; // a relay line grants nothing until federation lands
            member m;
            m.name = r.name;
            m.pub = r.pub;
            m.id = fingerprint(r.pub);
            if (m.id == 0) // #3: an id of zero names the packet that is for nobody
                return std::unexpected(std::errc::invalid_argument);
            if (!reg.by_id_.emplace(m.id, std::move(m)).second)
                return std::unexpected(std::errc::invalid_argument); // id collision
        }
        return reg;
    }

    [[nodiscard]] const member* find(u64 id) const noexcept {
        const auto it = by_id_.find(id);
        return it == by_id_.end() ? nullptr : &it->second;
    }

    [[nodiscard]] std::size_t size() const noexcept {
        return by_id_.size();
    }

    // the published directory (#6): these bytes, not a rendering of them
    [[nodiscard]] fex::bytes text() const noexcept {
        return fex::bytes{reinterpret_cast<const u8*>(text_.data()), text_.size()};
    }

    [[nodiscard]] const hash256& hash() const noexcept { return hash_; }

    // every registered member, for the sweeps that cannot wait to be asked:
    // opening each capsule at startup (#9 recovery) and gathering what garbage
    // collection must keep (#6)
    [[nodiscard]] auto begin() const noexcept { return by_id_.begin(); }
    [[nodiscard]] auto end() const noexcept { return by_id_.end(); }

    [[nodiscard]] bool changed_on_disk(const std::string& path) const noexcept {
        return fs::stat_of(path.c_str()).mtime_ns != mtime_ns_;
    }

    // rescan when the file's mtime moved; returns true when the registry was
    // rebuilt (the caller resets its address cache accordingly). A rescan that
    // fails keeps the old registry and reports the error -- an operator's
    // half-written line does not take a running relay down with it.
    [[nodiscard]] std::expected<bool, std::errc>
    maybe_reload(const std::string& path) noexcept {
        if (!changed_on_disk(path))
            return false;
        auto fresh = load(path);
        if (!fresh) {
            mtime_ns_ = fs::stat_of(path.c_str()).mtime_ns; // do not re-read it every packet
            return std::unexpected(fresh.error());
        }
        *this = std::move(*fresh);
        return true;
    }
}; // registry

} // namespace fex::relay

#ifdef FEX_WITH_TESTS

#include <cstdlib>
#include <unistd.h>

TEST_SUITE("fex::relay") {

namespace fex_registry_test {

// registration, as an operator does it: one line appended to the file
inline void put_roster(const std::string& path, const fex::roster::file& r) {
    const auto text = fex::roster::to_danl(r);
    REQUIRE(fex::fs::write_file_atomic(
        path, fex::bytes{reinterpret_cast<const fex::u8*>(text.data()), text.size()})
            .has_value());
    ::usleep(20'000); // so a rewrite is a visible change of mtime
}

} // namespace fex_registry_test

SCENARIO("registry: the roster file is the registry") {
    using namespace fex;
    using namespace fex_registry_test;
    char tmpl[] = "/tmp/fex-reg-XXXXXX";
    char* root = ::mkdtemp(tmpl);
    REQUIRE(root != nullptr);
    const std::string dir{root};
    const auto path = dir + "/roster.danl";

    const auto alice = generate_identity();
    const auto bob = generate_identity();
    const auto other = generate_identity();

    roster::file r;
    r.records.push_back(roster::member_record("alice", alice.pub));
    r.records.push_back(roster::member_record("bob", bob.pub));
    put_roster(path, r);

    auto reg = relay::registry::load(path);
    REQUIRE(reg.has_value());
    CHECK(reg->size() == 2);
    const auto* m = reg->find(fingerprint(alice.pub));
    REQUIRE(m != nullptr);
    CHECK(m->name == "alice");
    CHECK(m->pub == alice.pub);
    CHECK(reg->find(0xdeadbeefull) == nullptr);

    // #6: what it publishes is this file, not a rendering of it
    const auto on_disk = fs::read_file(path.c_str());
    REQUIRE(on_disk.has_value());
    CHECK(std::equal(reg->text().begin(), reg->text().end(), on_disk->begin(),
                     on_disk->end()));
    CHECK(reg->hash() == crypto::ascon::hash256(fex::bytes{*on_disk}));

    // a relay line reaches every reader and grants nothing: no capsule, no id
    r.records.push_back(roster::relay_record("r2", "r2.example.net:4444", other.pub));
    put_roster(path, r);
    auto federated = relay::registry::load(path);
    REQUIRE(federated.has_value());
    CHECK(federated->size() == 2);
    CHECK(federated->find(fingerprint(other.pub)) == nullptr);
    CHECK(federated->text().size() > reg->text().size());

    // a file nobody has written yet is a relay nobody is on, not a failure
    auto fresh = relay::registry::load(dir + "/nothing.danl");
    REQUIRE(fresh.has_value());
    CHECK(fresh->size() == 0);
    CHECK(fresh->text().empty());
    CHECK(fresh->hash() == crypto::ascon::hash256({}));

    // #6 rejects the file whole, and the registry with it
    const auto refuses = [&](std::string_view text) {
        REQUIRE(fs::write_file_atomic(
            path, fex::bytes{reinterpret_cast<const u8*>(text.data()), text.size()})
                .has_value());
        ::usleep(20'000);
        return !relay::registry::load(path).has_value();
    };
    const auto pub_a = to_hex(fex::bytes{alice.pub});
    const auto pub_b = to_hex(fex::bytes{bob.pub});
    CHECK(refuses("{:kind \"id_card\" :name \"alice\" :pub \"" + pub_a + "\"}\n"
                  "{:kind \"id_card\" :name \"alice\" :pub \"" + pub_b + "\"}\n"));
    CHECK(refuses("{:kind \"id_card\" :name \"alice\" :pub \"" + pub_a + "\"}\n"
                  "{:kind \"id_card\" :name \"bob\" :pub \"" + pub_a + "\"}\n"));
    CHECK(refuses("{:kind \"id_card\" :name \"BAD\" :pub \"" + pub_a + "\"}\n"));
    CHECK(refuses("{:kind \"id_card\" :name \"alice\"}\n"));

    // and a running relay keeps the registry it had rather than adopting that
    auto live = relay::registry::load(dir + "/nothing.danl");
    REQUIRE(live.has_value());
    r.records.clear();
    r.records.push_back(roster::member_record("alice", alice.pub));
    put_roster(path, r);
    auto adopted = relay::registry::load(path);
    REQUIRE(adopted.has_value());
    CHECK(adopted->size() == 1);

    // removal is deleting a line, and maybe_reload picks it up
    auto watching = relay::registry::load(path);
    REQUIRE(watching.has_value());
    CHECK(watching->size() == 1);
    r.records.push_back(roster::member_record("bob", bob.pub));
    put_roster(path, r);
    const auto reloaded = watching->maybe_reload(path);
    REQUIRE(reloaded.has_value());
    CHECK(*reloaded);
    CHECK(watching->size() == 2);
    CHECK(watching->find(fingerprint(bob.pub)) != nullptr);
    // and an unchanged file is not re-read
    const auto same = watching->maybe_reload(path);
    REQUIRE(same.has_value());
    CHECK(!*same);

    REQUIRE(fs::remove_tree(dir).has_value());
}

}

#endif
