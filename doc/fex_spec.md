# fex - capsule synchronization protocol (stage 1, revision 11, normative edition)

## 1. Model

- **Member** - a node with an x25519 key pair, registered on a relay.
- **Relay** - a node at a known address; stores capsules without interpreting
  their contents; maintains registries; routes requests to federated relays.
  The relay is trusted by its members.
- A member has exactly one channel, and it leads to their own relay.
- **Federation** - registration of relays with each other (#3). Federated
  relays are reachable in exactly one hop, through one's own relay; there is
  no transit.
- Each member has exactly one capsule, on their own relay. Reading covers all
  capsules of the own relay and of its federated relays; writing covers only
  the member's own capsule.
- Member attribution across the federation border is an assertion of the
  originating relay and is not verifiable by the serving relay; accounting
  and limits for federated traffic are per-relay.

## 2. Cryptography

| role | primitive |
| --- | --- |
| hash, derivation | ascon-hash256 (32-byte output) |
| channel (aead) | ascon-aead128 (16-byte key, 16-byte tag) |
| key exchange | x25519 |

```
k  = hash(dh(priv_N, pub_R))[0:16]   channel key, both directions
id = hash(pub_N)[0:8]                node fingerprint, u64 le
```

- An all-zero dh result is rejected (rfc 7748 check).
- Two channel classes, same derivation: member <-> own relay, relay <->
  federated relay. Each side derives k locally from its own priv and the
  peer's pub. There is no handshake and no durable channel state; a channel
  exists as long as the node's card is in the registry.
- The 32-byte routing prefix of the packet (#4) is the aead associated data;
  the nonce space of a channel is shared by both directions.

## 3. Registries and key files

Card exchange is out of scope of the protocol and happens over an
integrity-preserving channel; the safeguard against substitution is
fingerprint verification over an independent channel.

Registries are danl streams, one line per node.

```
relay:   roster.danl       -- the registry and the published directory (#6)
                              in one file: members have put/commit rights
                              and a capsule each
client:  keys/relays.danl  -- the member's relays; lines are the relays'
                              cards, which carry :addr by definition
```

- A relay's registry is the roster of #6, and a line of it is a card of this
  section, unchanged. It is what `list` points at and what `get` serves, byte
  for byte, so there is no second file, nothing to render and nothing to keep
  in step.
- A record carrying an `:addr` is a relay's card. It reaches every reader and
  grants nothing until federation lands: a relay serves capsules to the
  members of its registry, and a card with an address is not one of them.
- Registration is appending the node's card; removal is deleting the line plus
  flushing the node's addr cache entry; renaming is editing `:name`.
- The id -> node map is built from the registry and rebuilt whenever it
  changes; a relay re-reads the file when its mtime moves, and a file that
  fails to parse leaves the registry it is already serving in place.
- Registry errors are the roster's own (#6), plus: two records carrying one
  `name` or one `pub`, two mapping to one id, and an id equal to zero. The
  duplicate rules live here rather than in #6's reader because deciding them
  needs the whole file: the registry is the one place it is all in hand at
  once, and the relay is the only thing that writes it.
- A relay that cannot read its registry does not start; one already running
  keeps the registry it has and says so.
- `:name` follows the segment rules of #8; the reserved names of #8 are
  forbidden as node names.

The file format is dano (`.dano` document, `.danl` stream); binary values are
lowercase hex; unknown keys are ignored. Key files are general-purpose
identity documents; fex imposes only the requirements below.

**Identity** - a dano document, unbraced (mode 0600, never transmitted, not
edited after generation):

```
:kind "id"  :algo "x25519"  :pub "9f2c..."  :priv "a01b..."
```

It is unbraced deliberately: an identity is not a danl record, so appending one
to a roster (#6) is a syntax error rather than a published private key.

**Profile** - an optional non-secret file holding a node's public
self-description; arbitrary keys are allowed except the reserved `:kind`,
`:algo`, `:pub`, `:priv` (their presence is an error):

```
:kind "profile"  :intro "family photo archive"
:kind "profile"  :name "r1"  :addr "relay.example.net:4444"  :intro "home relay"
```

**Card** - a danl record: braced, one line, everything public about a node. It
is generated, and it is also a roster record (#6), which is what registration
consists of:

```
card = {:kind "id_card", :name, :algo, :pub} + all profile keys except :kind
```

```
{:kind "id_card" :name "alice" :intro "family photo archive" :algo "x25519" :pub "9f2c..."}
{:kind "id_card" :name "r1" :intro "home relay" :addr "relay.example.net:4444" :algo "x25519" :pub "77aa..."}
```

Key order is `:kind :name :intro :addr :algo :pub`: who this is, what it says
about itself, where it answers, and only then the algorithm and the key -- the
order a person reads, not the order a machine needs.

There is one card kind, because there is one kind of thing here: what a node
says publicly about itself. `:addr` is what tells a relay's card from a
member's, which is what generating with an address has always meant.

fex requires: `:kind "id"` for the node key, `:kind "id_card"` for cards,
`:algo "x25519"`, a `:name` that #8 accepts, and `:addr` on a relay's card. A
document with a different `kind`/`algo`, or missing a required key, is a
configuration error. A card carrying `:priv` is refused: that is an identity
under a card's name.

## 4. Outer layer

The transport is udp; one datagram = one message; the datagram ceiling is
1232 bytes. Numbers are little-endian, the layout is fixed, with no alignment
padding. Notation: `name:type@offset`; `bN` is an opaque array of N bytes.

One packet format:

```
ver:u8@0 || nonce:b15@1 || id:u64@16 || peer:u64@24 || ciphertext:b(n+16)@32
```

- `ver` = 1; a mismatch is a silent drop.
- `nonce` - 15 random bytes; the aead nonce is nonce || 1 zero byte.
  Uniqueness is the sender's responsibility; the receiver does not check it,
  with one exception (direct peek, below). A relay re-encrypting a packet is
  the sender on that leg and generates a fresh nonce.
- `id` - the fingerprint of the immediate sender.
- `peer` - the second end of the route: `peer = 0` - the packet is for the
  receiving node itself; in a packet from a member - the id of the target
  relay; in a packet between relays - the id of the originating member.
- The first 32 bytes are the aead associated data; `ciphertext` is the aead
  output over an inner command (#5) of length n; n = len - 48. A length that
  disagrees with the inner layout is a silent drop.
- There are no outer packet types; whether a packet is a request or a reply
  is the high bit of the inner kind.

**Processing at a relay.** `ver` ok, `id` in members or federation, derive k,
aead valid - otherwise silent drop. Then:

```
inner kind = peek, peer = 0 (the one exception to the addr rule):
    |now - time| <= W  and  nonce not in cache[id]
        -> remember nonce, addr[id] := source, execute peek, reply
    otherwise silent drop

inner is a request, source == addr[id]:
    sender in members:
        peer = 0            -> execute, reply with peer = 0
        peer in federation  -> re-encrypt under the federate's k,
                               peer := sender id, send to the federate's addr
    sender in federation:
        execute in the read-only context (#5), reply,
        peer echoed byte-for-byte

inner is a reply, source == addr[id], sender in federation:
    peer in members         -> re-encrypt under the member's k,
                               peer := sender id, send to addr[peer];
                               addr unknown -> drop

anything else               -> silent drop
```

- When routing, a relay inspects only the inner kind byte; the plaintext is
  re-encrypted unchanged.
- Direct peek replay protection: `time` is the sender's creation timestamp;
  W is an operational window on the order of minutes; the nonce cache holds,
  per sender id, the nonces of direct peeks seen within W and may be lost
  like the addr cache. Clocks of a node and its relay must agree within W;
  this requirement is local to peek. An out-of-window peek is a silent drop.
- In a forwarded peek (`peer != 0`) the window and the nonce cache are not
  consulted and `time` is ignored.

**Member side.** A member accepts packets only from its relay's address, and
only those whose inner kind is a reply; matching is by req_id; `peer` names
the relay the reply came from (0 - the member's own). The first command
after start or an address change must be a direct peek: until addr is set,
everything else is dropped.

Per-side state:

- client (durable): node key, `keys/relays.danl`;
- relay (durable): node key, `roster.danl`, capsules;
- relay (cache, may be lost): `{id -> addr}`, the peek nonce cache.

## 5. Inner layer

Delivery is neither guaranteed nor ordered. Requests are concurrent;
`req_id` is 6 random bytes, echoed in the reply. No reply within the
timeout -> direct peek to one's own relay, wait for head, resend the
request.

Common prefix, 8 bytes (offsets are from the start of the plaintext):

```
kind:u8@0 || status:u8@1 || req_id:b6@2
```

The high bit of kind marks a reply; `status` is meaningful in replies and is
0 in requests; in put, `req_id` is all zeros.

```
0x06 peek    prefix || time:u64@8 || target:u64@16                       24
0x80 head    prefix || seq:u64@8 || inv_size:u64@16 || inv_hash:b32@24   56
0x01 put     prefix || file_size:u64@8 || chunk_no:u64@16 ||
             file_hash:b32@24 || data:b(z)@56                            56 + z
0x02 get     prefix || chunk_no:u64@8 || file_hash:b32@16                48
0x82 chunk   prefix || size:u64@8 || data:b(size)@16                     16 + size
0x03 poll    prefix || file_hash:b32@8                                   40
0x83 gaps    prefix || count:u64@8 || {from:u32, to:u32} x count @16     16 + 8*count
0x04 commit  prefix || seq:u64@8 || inv_hash:b32@16                      48
0x84 done    prefix                                                      8
0x05 list    prefix                                                      8
0x85 roster  prefix || size:u64@8 || hash:b32@16                         48
```

- Pairs: peek -> head, get -> chunk, poll -> gaps, commit -> done,
  list -> roster; put has no reply.
- A datagram length that disagrees with the layout is a silent drop. An
  unknown inner kind is dropped without a reply.
- chunk does not echo file_hash/chunk_no - matching is by req_id.
- Status codes: `0 ok`, `1 internal`, `2 not_found`, `3 stale_seq`,
  `4 files_missing`, `5 hash_mismatch`, `6 read_only`. A reply with a
  non-zero status keeps its fixed layout with the remaining fields zeroed
  (gaps, which defines its own statuses, excepted).

**peek** - the head of a capsule and, on the direct leg, an address
confirmation. `target` is the id of the member whose capsule is asked about,
always explicit - including the requester asking about their own capsule.
The reply is that capsule's head; `seq = 0, inv_hash = zeros` - never
published; `target` not in the serving relay's members - `not_found`.
`time` is meaningful only in a direct peek (#4).

**list** - a pointer to the serving relay's current roster (#6): its size
and hash. The file itself is fetched by get.

**Read-only context.** Every request arriving from a federate - the
federate's own (`peer = 0`) or forwarded (`peer != 0`) - is read-only:
peek, get, poll, list work as normal; commit is answered with `read_only`;
put is silently dropped. put and commit act only on the sender's own capsule
at their own relay.

### 5.1 Chunks

- Chunk data is 1024 bytes; a file's last chunk is the remainder.
  z = min(1024, file_size - chunk_no*1024).
- A chunk is addressed by the pair `(file_hash, chunk_no)`; put is
  idempotent.
- On receiving put: `len(data) == z`, otherwise drop; `file_size = 0` is
  invalid - drop.

### 5.2 put / poll / gaps

put has no reply; on the first chunk the relay creates a temporary file of
file_size in the sender's assembly area, writes the chunk, and marks the
range. Once all ranges are filled the hash is verified: on a match the file
is assembled (awaiting commit); otherwise the file is deleted and the status
is mismatch.

`status` in gaps: `ok` - the hash is present in objects/ (#6) or assembled
in the sender's own assembly area (in the read-only context, objects/ only);
`hash_mismatch` - terminal, the file starts over; `not_found`; otherwise
the ranges of missing chunks `{from, to}`, inclusive. If they do not all
fit, the first count are sent; the client fills them in and repeats poll.

## 6. Relay storage

The relay stores content in a content-addressed object store; an object's
name is the hash of its content.

```
<root>/
  roster.danl                  -- the registry (#3) and the directory this
                                  relay publishes, in one file
  objects/<hex64>              -- every capsule file, every current
                                  inventory, the roster
  capsules/<name>/head.dano    -- {:seq N :hash "..." :size N}
  capsules/<name>/pending.danl -- new inventory for the duration of commit
  capsules/<name>/assembly/    -- assembly area: <hex64> + range map
```

- get(hash) is served by objects/ directly, for any member and any federate;
  a hash absent from objects/ is `not_found`.
- Identical content is stored once, regardless of how many paths or capsules
  reference it.
- head: seq is strictly monotonic; `seq=0, inv_hash=zeros` means the capsule
  has never been published; an empty capsule is `seq>0, inv_size=0`.
- **Pinning and garbage collection.** An object is pinned if it is: the
  current roster; the inventory object of any head, or referenced by a
  record of such an inventory; a pending.danl inventory (by its hash), or
  referenced by a record of any pending.danl. Unpinned objects may be
  deleted at startup or periodically; objects younger than a day are never
  deleted.
- The invariant "every pinned object exists in objects/" is enforced at
  startup; object contents are verified against their names lazily when an
  object that has not been checked for a long time is served, not touching
  objects younger than a day.

**Roster** - the relay's published directory. Every line is a card (#3), so
registering someone is their card appended to this file and nothing else. It is
the registry of #3 itself: the relay reads its members from these lines and
serves the same bytes back, so `list` (#5) answers with the size and hash of
the file on disk and `get` fetches that file:

```
{:kind "id_card" :name "bob" :algo "x25519" :pub "9f2c..."}
{:kind "id_card" :name "r2" :addr "relay.example.net:4444" :algo "x25519" :pub "77aa..."}
```

A record with an `:addr` is a relay's and grants nothing until federation
lands; one without is a member, and is what the relay serves a capsule for.
There is no separate member/relay kind to keep in step with the addr.

- Canonical form (for writing): the card form of #3 -- key order `:kind :name
  :intro :addr :algo :pub`, a single space between pairs, no comments,
  lowercase hex; lines sorted bytewise by `name`; every line terminated by
  `\n`, including the last. A relay serves the file as it stands rather than
  re-rendering it, so the canonical form is what whoever edits the registry is
  expected to write -- and it is exactly what `generate` wrote in the card.
- Reading: required keys in any order; unknown keys are ignored; a record
  with an unknown `:kind` is ignored as a whole. The roster is rejected as
  a whole on: a syntax error, a missing required key, a `:priv` in any record,
  invalid hex, an unusable `:addr`, or a `name` violating #8. Every one of
  these is decidable on the record in hand, so a reader may walk the file and
  keep nothing but the record it stands on.
- The registry's own rule: no two records may carry the same `name` or the
  same `pub`. This binds whoever writes the file, not whoever reads it --
  deciding it needs a memory of the whole file, which a node walking a served
  roster has no reason to keep. A relay refuses a registry that breaks it (#3)
  and so never serves one; a reader that does hold the whole file may refuse
  as well, and nothing it would refuse can reach it from a conforming relay.

## 7. Inventory

danl, one record per file:

```
{:path "docs/a.txt" :size 10240 :hash "9f2c..."}
```

**Canonical form (for writing):** key order is exactly `:path :size :hash`;
a single space between pairs, no comments; lowercase hex; lines sorted
bytewise by `path`; every line terminated by `\n`, including the last.

**Reading:** `path`, `size` and `hash` are required in any order; unknown
keys are ignored. The inventory is rejected as a whole on: a syntax error, a
missing required key, a duplicate path, `size < 0`, invalid hex, or an
invalid path (#8).

**Capsule contents:** regular files only. Empty directories are not
representable; a symlink or special file aborts the entire publication with
an explicit error; metadata (mtime, permissions) is not preserved.

## 8. Paths

```
segment:  [a-z0-9._-]+, <= 255 bytes; != "." and "..", not all dots,
          does not start with "-"
path:     segments joined by "/", no leading/trailing "/", no "//",
          <= 1024 bytes
plus:     reserved windows names are forbidden (con, nul, prn, aux,
          com1-com9, lpt1-lpt9 - and with any extension)
reserved: the paths "inventory.danl" and "roster.danl" belong to the
          service layer (#6, #10.3) and cannot be capsule content
```

Lowercase ascii only. Non-representable names and the reserved paths abort
publication; there is no automatic renaming. One validation function, used
at publication (#10.1), at inventory validation (#7, #9), and before laying
files out on disk (#10.2). Node names in the registries and rosters (#3,
#6) obey the segment rules.

## 9. The commit transaction

```
1. seq > current                            -> otherwise stale_seq
2. the inventory is assembled or already in objects/
                                            -> otherwise files_missing
3. the inventory parses and is valid (#7)   -> otherwise internal/files_missing
4. every file in the inventory is assembled or already in objects/
                                            -> otherwise files_missing
   (a record with size = 0 requires no object: its hash must be the hash of
   the empty string; empty files are materialized by the client, #10.2)
5. write the new inventory as pending.danl (temporary file + rename)
6. move every newly assembled file from the assembly area into objects/
   (rename; an object already present -> discard the assembly copy);
   idempotent
7. replace head.dano atomically (temporary file + rename); delete
   pending.danl
```

- commit is accepted only from the capsule's owner over the direct channel
  (#5, read-only context).
- After `ok`: every record of the new inventory resolves in objects/.
  Previous objects remain until garbage collection (#6): commits are
  snapshot-isolated, and a get by a hash that no current inventory
  references succeeds until the object is collected - the client retries
  through refresh (#10.2) on `not_found`.
- Repeating the same commit (same seq, inv_hash) is idempotent.
- On a crash at any point: at startup the relay sees pending.danl and
  replays steps 6-7.

## 10. Client

### 10.1 Publication

```
1. snapshot: walk files/, skipping inventory.danl at its root, compute
   hashes, fix the whole inventory; an invalid path / special file ->
   abort the entire publication
2. peek(self) -> head: inv_hash matches -> done
3. for each new non-empty file: a put / poll loop until assembled
   (empty files are not uploaded); on mismatch -> abort, restart from step 1
4. upload the inventory file the same way
5. commit (new seq = old + 1)
6. write the inventory as files/inventory.danl
```

Publication goes only to one's own relay (`peer = 0`). Uploads come strictly
from the snapshot. n consecutive "batch of put -> poll" rounds without the
missing set shrinking -> abort the upload with an explicit error.

### 10.2 Reading a capsule

One procedure for any capsule, parameterized by the serving relay R
(`peer` = 0 for one's own relay, the relay's id otherwise) and the target
member m (their id, from the roster or one's own). The capsule root is
`self/<name>@<relay>/` for one's own capsule and `peers/<R>/<m>/` for any
other (#10.3).

Every command begins by bringing the inventory level with the head:

```
refresh: 1. peek(target=m, peer=R) -> head; seq=0 with inv_hash=zeros ->
            never published
         2. if <capsule root>/files/inventory.danl does not hash to
            inv_hash: get the inventory by inv_hash into state/staging/,
            verify, rename it into place (inv_size=0 -> an empty
            inventory.danl; inv_hash must be hash(""))
         3. validate the inventory and the paths (#7, #8)
```

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

get/poll travel with the same `peer` as the peek that opened the read.

**Discovery.**

```
1. list(peer=0) -> (size, hash) of the own relay's roster; the local
   peers/<relay>/roster.danl does not hash to it -> get by hash into
   state/staging/, verify, rename; validate (#6)
2. relay records of the own roster = reachable relays; a relay's id is
   hash(pub)[0:8] of its record
3. list(peer=R) -> the roster of R, fetched and validated the same way
4. member records of R's roster: the id goes into peek/fetch, the name into
   the local layout (#10.3)
```

A client is expected to offer rosters and inventories read out as well as
fetched: the names of each roster, the path and size of each inventory
record.

Nothing in reading deletes anything, and nothing holds a file in memory: a
download is written to its staging file as it arrives and is verified
against the hash that named it before the rename puts it in place.

### 10.3 Client layout

```
<root>/
  keys/node.dano                -- identity
  keys/profile.dano             -- profile (optional)
  keys/relays.danl              -- relay registry (#3)
  self/<name>@<relay>/          -- the capsule published to this relay
    files/                      -- the content, byte for byte
    files/inventory.danl        -- the relay's inventory as last known
                                   (#10.1 step 6, #10.2 step 2); reserved
                                   (#8), never a record of itself
    state/staging/<hex>         -- uploads/downloads in progress
  peers/<relay>/                -- everything read from this relay: one's
                                   own relay and federated ones, uniformly
    card.danl                   -- pinned relay identity (a card, #3)
    roster.danl                 -- the relay's roster as last known
    state/staging/<hex>         -- roster staging
    <member>/
      card.danl                 -- pinned member identity (a card, #3)
      files/                    -- the member's capsule, read-only
      files/inventory.danl      -- their inventory as last known
      state/staging/<hex>
```

- `(relay, member, path) -> local path` is a fixed function of names:
  `<relay>` is `:name` from `keys/relays.danl` for one's own relay and
  `:name` from the own relay's roster for a federated one; `<member>` is
  `:name` from that relay's roster.
- `card.danl` pins identity: written on first contact from the registry
  line or roster record that introduced the node. A later roster naming a
  different pub under the same name is a hard stop with an explicit error,
  never an overwrite. A remote rename produces a new directory; the old one
  is not touched.
- The #8 rules apply inside files/ and do not extend to service names.
  files/ holds the content and, at its root, inventory.danl - refreshed by
  every command, never authored. state/ holds temporaries only; it is under
  the same directory as its files/ (one filesystem - atomic rename), and
  staging/ is cleaned at the start of every command.
