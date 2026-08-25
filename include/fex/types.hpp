// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

#pragma once

// The vocabulary every layer shares: the integer names, the 32-byte digest, and
// the hash containers. Kept apart from protocol.hpp so the protocol headers can
// use them without including their own umbrella.
//
// This is also the only file that names the container implementation, so
// swapping it out is a one-file change.

#include <array>
#include <cstdint>
#include <span>

#include <ankerl/unordered_dense.h>

namespace fex {

using u8 = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// a read-only view of raw bytes: the currency of every hashing, aead and
// filesystem call in fex
using bytes = std::span<const u8>;

// ascon-hash256 output, and every fex identifier derived from it
using hash256 = std::array<u8, 32>;

template <typename K, typename V, typename H = ankerl::unordered_dense::hash<K>>
using hash_map = ankerl::unordered_dense::map<K, V, H>;

template <typename K, typename H = ankerl::unordered_dense::hash<K>>
using hash_set = ankerl::unordered_dense::set<K, H>;

// A hash256 is already a cryptographic digest, so its first eight bytes are as
// good a bucket index as any hash function would produce. `is_avalanching` tells
// the container exactly that: do not re-mix.
struct hash256_hasher {
    using is_avalanching = void;

    [[nodiscard]] u64 operator()(const hash256& h) const noexcept {
        u64 v = 0;
        for (unsigned i = 0; i != 8; ++i)
            v |= u64{h[i]} << (8 * i);
        return v;
    }
}; // hash256_hasher

template <typename V>
using hash256_map = hash_map<hash256, V, hash256_hasher>;

using hash256_set = hash_set<hash256, hash256_hasher>;

} // namespace fex
