# fex - capsule synchronization protocol (stage 1, revision 9, normative edition)

## 1. Model

- **Member** - a node with an x25519 key pair, registered on a relay.
- **Relay** - a node at a known address; stores capsules without interpreting their contents. The relay is trusted.
- Each member has exactly one capsule (a local directory, published to a relay and read back from it file by file). There is no access to other members' capsules and no anonymous access. There is one channel per member, and it leads only into that member's capsule.

## 2. Cryptography

| role | primitive |
| --- | --- |
| hash, derivation | ascon-hash256 (32-byte output) |
| channel (aead) | ascon-aead128 (16-byte key, 16-byte tag) |
| key exchange | x25519 |

```
k  = hash(dh(priv_N, pub_R))[0:16]   channel key, both directions
id = hash(pub_N)[0:8]                member fingerprint, u64 le
```

- An all-zero dh result is rejected (rfc 7748 check).
- Each side derives k locally from its own priv and the peer's pub. There is no handshake and no durable channel state; the channel exists as long as the member's card is in the registry.
- The packet kind is part of the aead associated data; the nonce space is shared by both directions.

## 3. Registration and key files

Card exchange is out of scope of the protocol and happens over an integrity-preserving channel; the safeguard against substitution is fingerprint verification over an independent channel. A member's card is placed as a file into the relay's `members/`; the relay's card goes into the client's `keys/`.

- Removing a member means deleting their file from `members/` plus flushing the address cache; renaming a member means renaming the file.
- The id -> member map is built from `members/` and rebuilt whenever it changes. Two cards with the same public key are a registry error.

The file format is dano (`.dano` document, `.danl` stream); binary values are lowercase hex; unknown keys are ignored. A node's name is its file name; names are subject to the segment rules of #8.

Key file formats do not belong to the protocol: they are general-purpose identity documents, and fex merely imposes requirements on them.

**Identity** (mode 0600, never transmitted, not edited after generation):

```
:kind "identity"  :algo "x25519"  :pub "9f2c..."  :priv "a01b..."
```

**Profile** - an optional non-secret file holding a node's public self-description; arbitrary keys are allowed except the reserved `:kind`, `:algo`, `:pub`, `:priv` (their presence is an error):

```
:kind "profile"  :intro "family photo archive"
:kind "profile"  :addr "relay.example.net:4444"  :intro "home relay"
```

**Card** is generated; manual editing is not expected:

```
card = {:kind "identity_card", :algo, :pub from the identity} + all profile keys except :kind
```

```
:kind "identity_card"  :algo "x25519"  :pub "..."  :intro "family photo archive"
```

fex requires: `:kind "identity"` for the node key, `:kind "identity_card"` for cards, `:algo "x25519"`; `keys/<relay>.relay.dano` additionally requires `:addr`. A file with a different `kind`/`algo`, or missing a required key, is a configuration error. The protocol does not read any other card fields (including `:intro`); they exist for the people working with the registry.

## 4. Outer layer

The transport is udp; one datagram = one message; the datagram ceiling is 1232 bytes. Numbers are little-endian, the layout is fixed, with no alignment padding. Notation: `name:type@offset`; `bN` is an opaque array of N bytes.

Common header, 24 bytes:

```
ver:u8@0 || kind:u8@1 || nonce:b14@2 || id:u64@16
```

- `ver` = 1; a mismatch is a silent drop.
- `nonce` - 14 random bytes (uniqueness is the sender's responsibility, the receiver does not check it); the aead nonce is nonce || 2 zero bytes. In peek it is all zeros.
- `id` - the member fingerprint, present in every packet type.
- The entire header is the aead associated data.
- The high bit of kind means "the sender is a relay"; a packet from the wrong half of the kind space is dropped.

```
0x01 peek      header || ballast:b72@24             = 96
0x02 request   header || ciphertext:b(n+16)@24      = 24 + n + 16
0x81 response  header || ciphertext:b(n+16)@24      = 24 + n + 16
```

- `ciphertext` is the aead output over a command of length n under key k; n = len - 40.
- `ballast` is zeros; the receiver only checks the peek length (== 96).

**peek** - a pointer request and an address confirmation. On receipt: length != 96 or id not in the registry - silent drop; otherwise record addr (the source address) and reply with head (req_id all zeros) under k.

**request** - a client command. Dropped without a reply when: the source address != addr, the id is not in the registry, or the aead is invalid. There are no replies other than response.

Per-side state:

- client (durable): node key, relay card;
- relay (durable): node key, `members/`, capsules;
- relay (cache, may be lost): `{id -> addr}`.

## 5. Inner layer

Delivery is neither guaranteed nor ordered. Requests are concurrent; `req_id` is 6 random bytes, echoed in the reply. No reply within the timeout -> send peek, wait for head, resend the request.

Common prefix, 8 bytes (offsets are from the start of the plaintext):

```
kind:u8@0 || status:u8@1 || req_id:b6@2
```

The high bit of kind marks a reply; `status` is meaningful in replies and is 0 in requests; in put, `req_id` is all zeros.

```
0x80 head    prefix || seq:u64@8 || inv_size:u64@16 || inv_hash:b32@24   56
0x01 put     prefix || file_size:u64@8 || chunk_no:u64@16 ||
             file_hash:b32@24 || data:b(z)@56                            56 + z
0x02 get     prefix || chunk_no:u64@8 || file_hash:b32@16                48
0x82 chunk   prefix || size:u64@8 || data:b(size)@16                     16 + size
0x03 poll    prefix || file_hash:b32@8                                   40
0x83 gaps    prefix || count:u64@8 || {from:u32, to:u32} x count @16     16 + 8*count
0x04 commit  prefix || seq:u64@8 || inv_hash:b32@16                      48
0x84 done    prefix                                                      8
```

- Pairs: get -> chunk, poll -> gaps, commit -> done; put has no reply; head is the reply to peek.
- A datagram length that disagrees with the layout is a silent drop. An unknown inner kind is dropped without a reply.
- chunk does not echo file_hash/chunk_no - matching is by req_id.
- Status codes: `0 ok`, `1 internal`, `2 not_found`, `3 stale_seq`, `4 files_missing`, `5 hash_mismatch`.

### 5.1 Chunks

- Chunk data is 1024 bytes; a file's last chunk is the remainder. z = min(1024, file_size - chunk_no*1024).
- A chunk is addressed by the pair `(file_hash, chunk_no)`; put is idempotent.
- On receiving put: `len(data) == z`, otherwise drop; `file_size = 0` is invalid - drop.

### 5.2 put / poll / gaps

put has no reply; on the first chunk the relay creates a temporary file of file_size in the assembly area, writes the chunk, and marks the range. Once all ranges are filled the hash is verified: on a match the file is assembled (awaiting commit); otherwise the file is deleted and the status is mismatch.

`status` in gaps: `ok` - assembled and verified (either in tree or in the assembly area); `hash_mismatch` - terminal, the file starts over; `not_found`; otherwise the ranges of missing chunks `{from, to}`, inclusive. If they do not all fit, the first count are sent; the client fills them in and repeats poll.

## 6. Relay storage

```
<root>/
  members/<name>.dano            -- registry
  capsules/<name>/tree/...         -- the capsule byte-for-byte, paths from the inventory
  capsules/<name>/inventory.danl -- current inventory
  capsules/<name>/head.dano      -- {:seq N :hash "..." :size N}
  capsules/<name>/pending.danl   -- new inventory for the duration of commit
  capsules/<name>/assembly/      -- assembly area: <hex64> + range map
```

- get(hash) is served by a "hash -> path" map, rebuilt at startup from inventory.danl.
- Identical content under two paths yields independent copies; there is no deduplication.
- head: seq is strictly monotonic; `seq=0, inv_hash=zeros` means the capsule has never been published; an empty capsule is `seq>0, inv_size=0`.

## 7. Inventory

danl, one record per file:

```
{:path "docs/a.txt" :size 10240 :hash "9f2c..."}
```

**Canonical form (for writing):** key order is exactly `:path :size :hash`; a single space between pairs, no comments; lowercase hex; lines sorted bytewise by `path`; every line terminated by `\n`, including the last.

**Reading:** `path`, `size` and `hash` are required in any order; unknown keys are ignored. The inventory is rejected as a whole on: a syntax error, a missing required key, a duplicate path, `size < 0`, invalid hex, or an invalid path (#8).

**Capsule contents:** regular files only. Empty directories are not representable; a symlink or special file aborts the entire publication with an explicit error; metadata (mtime, permissions) is not preserved.

## 8. Paths

```
segment:  [a-z0-9._-]+, <= 255 bytes; != "." and "..", not all dots,
          does not start with "-"
path:     segments joined by "/", no leading/trailing "/", no "//",
          <= 1024 bytes
plus:     reserved windows names are forbidden (con, nul, prn, aux,
          com1-com9, lpt1-lpt9 - and with any extension)
reserved: the path "inventory.danl" belongs to the client (#10.3)
```

Lowercase ascii only. Non-representable names and the reserved path abort publication; there is no automatic renaming. One validation function used in two places: at publication and before laying files out on disk.

## 9. The commit transaction

```
1. seq > current                            -> otherwise stale_seq
2. the inventory file is assembled          -> otherwise files_missing
3. the inventory parses and is valid (#7)   -> otherwise internal/files_missing
4. every file in the inventory is assembled -> otherwise files_missing
   (a record with size = 0 is assembled by definition: its hash must be the
   hash of the empty string; the file is created in step 6 without upload)
5. write the new inventory as pending.danl (temporary file + rename)
6. apply the diff to tree: lay out what is assembled from the assembly area
   by path (several paths with the same hash become independent copies;
   size = 0 means creating an empty file); delete paths that disappeared
   from the inventory; every step is hash-verified and idempotent
7. rename pending.danl -> inventory.danl; replace head.dano atomically
   (temporary file + rename)
```

- After `ok`: tree == inventory. Between commits the assembly area may hold files of an upload in progress.
- Repeating the same commit (same seq, inv_hash) is idempotent.
- On a crash at any point: at startup the relay sees pending.danl and replays steps 6-7. There is no snapshot isolation: during step 6 a get for files being replaced may return not_found - the client retries.
- The "tree == inventory" invariant is enforced at startup and lazily when a capsule that has not been checked for a long time is accessed; outside a transaction it does not touch objects younger than a day.

## 10. Client

### 10.1 Publication

```
1. snapshot: walk files/, skipping inventory.danl at its root, compute
   hashes, fix the whole inventory; an invalid path / special file ->
   abort the entire publication
2. peek -> head: inv_hash matches -> done
3. for each new non-empty file: a put / poll loop until assembled
   (empty files are not uploaded); on mismatch -> abort, restart from step 1
4. upload the inventory file the same way
5. commit (new seq = old + 1)
6. write the inventory as files/inventory.danl
```

Uploads come strictly from the snapshot. n consecutive "batch of put -> poll" rounds without the missing set shrinking -> abort the upload with an explicit error.

### 10.2 Reading a capsule back

Every command begins by bringing the inventory level with the head:

```
refresh: 1. peek -> head; seq=0 with inv_hash=zeros -> never published
         2. if files/inventory.danl does not hash to inv_hash: get the
            inventory by inv_hash into state/staging/, verify, rename it
            into place (inv_size=0 -> an empty inventory.danl; inv_hash
            must be hash(""))
         3. validate the inventory and the paths (#7, #8)
```

The inventory is the one object addressed by the head rather than by a record, since an inventory cannot carry a record of itself; that is what the reserved path of #8 is for. Fetching it by name is the refresh above, reported.

```
fetch:   1-3 refresh
         4. path = "inventory.danl" -> done, it is already in place
         5. otherwise the path must be valid (#8) and present in the
            inventory -> otherwise not_found
         6. a file already at files/<path> whose hash matches -> done, no
            download
         7. size = 0 -> create an empty file (hash must be hash(""))
         8. get chunks into state/staging/<hash>, hashing as they arrive ->
            verify -> rename into files/<path> (parent directories are
            created)
```

A client is expected to offer the inventory read out as well as fetched -- the path and size of each record, which is what a member needs in order to choose the next fetch.

Nothing here deletes anything, and nothing here holds a file in memory: a download is written to its staging file as it arrives and is verified against the hash that named it before the rename puts it in place.

### 10.3 Client layout

```
<root>/
  keys/node.dano                -- identity
  keys/profile.dano             -- profile (optional)
  keys/<relay>.relay.dano       -- relay card
  self/<name>@<relay>/          -- the capsule published to this relay
    files/                      -- the content, byte for byte
    files/inventory.danl        -- the relay's inventory as last known
                                   (#10.1 step 6, #10.2 step 2); reserved
                                   (#8), never a record of itself
    state/staging/<hex>         -- downloads in progress, one file per hash
```

The #8 rules apply inside files/ and do not extend to service names. files/ holds the content and, at its root, inventory.danl: the inventory the relay last published, kept for the member to read and refreshed by every command - never authored, and never a record, since an inventory cannot carry the hash of a file containing that very line. state/ holds temporaries only; it is under the same directory as files/ (one filesystem - atomic rename), and staging/ is cleaned at the start of every command.
