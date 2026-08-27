# fex

A capsule synchronization protocol over UDP. Each member owns exactly one
**capsule** -- a local directory published to a **relay** and read back from it,
byte for byte, a file at a time. The relay stores capsules without interpreting
their contents; there is no access to other members' capsules and no anonymous
access. What a relay does publish to its members is its **roster**: the name,
the key and the self-description of everyone registered on it.

Members are identified by an x25519 key pair. A channel key is derived locally
on both sides (`hash(dh(priv, pub))[0:16]`), so there is no handshake and no
durable channel state: the channel exists for as long as the member's card sits
in the relay's registry -- literally, since the registry is a file of cards.
Every datagram is sealed with ascon-aead128, and publication is transactional --
a capsule on the relay always matches its inventory, even across a crash
mid-commit.

The protocol is specified in [doc/fex_spec.md](doc/fex_spec.md). The
implementation is header-only C++23 under `include/fex/`, with two thin
executables: `fexerver` (the relay: `serve`, `include`, `exclude`, `roster`) and
`fex` (the client: `generate`, `publish`, `inventory`, `fetch`, `roster`).
Running a relay for real -- as a service, with a user of its own and the paths
and modes that go with it -- is [packaging/README.md](packaging/README.md).

## Requirements

- [zig](https://ziglang.org/) 0.16.0 or newer -- used as the C++ build system
  and cross compiler; no separate toolchain is needed
- [just](https://github.com/casey/just) (optional) for the shortcuts below

## Clone and build

```sh
git clone https://github.com/aldan4/fex.git
cd fex
zig build                 # debug build, binaries in zig-out/bin
```

Optimized binaries for the host go to the same place:

```sh
zig build -Doptimize=ReleaseFast
```

With `just`: `just build`, `just build-release-host`, `just test` for the unit
and end-to-end tests, `just smoke` for a full publish/list/fetch run against the
real binaries, and `just check` for all of it.

## Running a relay

A relay needs its own identity and a registry of members. Generate the identity
anywhere and move it into place; `--addr` is what makes the generated card a
relay's card, and `--intro` is an optional public note.

```sh
zig-out/bin/fex generate relay1 --addr relay.example.net:4444 --intro "home relay"

mkdir -p relay-root
mv relay1.dano relay-root/node.dano       # secret, mode 0600, never share it
                                          # relay1.card.danl goes to your members
```

Register a member by their card. `roster.danl` is the registry and the
directory the relay publishes at once, and a card **is** one of its records --
there is nothing to extract and nothing to rewrite:

```sh
zig-out/bin/fexerver include alice.card.danl --root relay-root
zig-out/bin/fexerver roster --root relay-root
zig-out/bin/fexerver exclude alice --root relay-root
```

`cat alice.card.danl >> relay-root/roster.danl` is the same registration; what
the command adds is refusing the few things that would take the whole file
down -- a duplicate name or key, a card that is really an identity, hex that is
not hex -- and writing the file whole rather than in part.

The name the member goes by here is the `:name` in the card, which is the name
they generated with. Renaming someone is editing that one field; the key is what
the relay actually goes by. A line reads as a person would:

```
{:kind "id_card" :name "alice" :intro "family photo archive" :algo "x25519" :pub "8520f009...9b4e6a"}
```

Then serve:

```sh
zig-out/bin/fexerver serve --root relay-root --addr 0.0.0.0:4444
```

The relay keeps `roster.danl`, `objects/` and `capsules/<name>/` under its root,
and rereads the registry when it changes -- adding or removing a member does not
need a restart. Ctrl-C stops it. A roster it cannot read is a refusal to start,
not a warning.

That is a relay in a directory you own, which is the right shape for trying one.
For a relay that outlives your shell, see below and then
[packaging/README.md](packaging/README.md).

## Running it as a service

`fexerver serve` stays in the foreground, says one line, writes only under its
`--root` and stops on `SIGTERM`, so any supervisor can run it as it is. On the
server, with the binaries beside you:

```sh
doas ./packaging/install.sh --addr relay.example.net:4444      # sudo, elsewhere
```

That makes the service user, installs the binaries and the relay root, generates
the identity if there is none, and installs the service file for whichever init
the machine runs -- systemd, OpenRC or runit. It is safe to run twice and never
overwrites an identity. The units it installs are in
[packaging/](packaging) if you would rather place them yourself.

All three run `/usr/bin/fexerver serve` on `/var/lib/fexerver` as a `fexerver`
user. The operator's guide, **[packaging/README.md](packaging/README.md)**, has
the rest: the service user, the relay's identity, which path is owned by whom
and in what mode, cross-compiling and copying the binaries to a server that
builds nothing itself, registration, backups, the firewall rule, and what the
startup failures mean.

## Using a client

Generate an identity, hand the card to whoever runs the relay, and get the
relay's card back. Fingerprints are printed on generation: compare them over an
independent channel before trusting a card.

```sh
zig-out/bin/fex generate alice --intro "family photo archive"
```

That writes two files: `alice.dano`, the identity, which stays on this machine
and nowhere else, and `alice.card.danl`, the card, which is the public half and
the line a relay registers you by.

Lay out the client root. The relay card must be named `<relay>.relay.danl`, and
the capsule directory `<name>@<relay>` must use the same `<relay>`; the content
itself goes in `files/` inside it:

```sh
mkdir -p client-root/keys client-root/self/notes@relay1/files
mv alice.dano             client-root/keys/node.dano
cp relay1.card.danl       client-root/keys/relay1.relay.danl
```

Put whatever you want to sync into `files/`, then publish:

```sh
echo "hello fex" > client-root/self/notes@relay1/files/note.txt

zig-out/bin/fex publish --root client-root
```

`publish` snapshots `files/`, uploads what the relay is missing and commits;
running it again with nothing changed is a no-op. To read the capsule back --
on this machine or on another one that holds the same identity -- ask what the
relay holds, then fetch what you want of it:

```sh
zig-out/bin/fex inventory --root client-root --name notes
zig-out/bin/fex fetch note.txt --root client-root --name notes
```

`inventory` prints a row per file, `<path>  <size>`. `fetch` puts one file back
at the path the relay holds it under, checked against its hash and moved into
place whole. Neither deletes anything, and fetching a file that is already right
downloads nothing.

Both work from `files/inventory.danl`, which every command refreshes first: the
capsule as the relay last accepted it, one record per file with the path leading
each line. It is a file of the capsule like any other, so `fex fetch
inventory.danl` fetches it and `cat` reads it out with the hashes -- but it is
the one path answered from the head rather than from a record, since an
inventory cannot carry a record of itself. Hence the reserved name (#8): it is
yours to read, not to write.

Capsule contents are regular files with lowercase ASCII names; symlinks,
special files and unrepresentable names abort a publication rather than being
silently skipped.

To see who else is on the relay, ask for its directory:

```sh
zig-out/bin/fex roster --root client-root --name notes
```

```
relay relay1, 2 record(s)
alice  c1456e845f7dd6ec  family photo archive
carol  d04336ea9d51fac7  a bystander
```

A row is a name, a fingerprint and whatever that member wrote about itself --
the card they handed the relay, which is the registry line itself. The file
lands at `client-root/peers/relay1/roster.danl` and is refreshed only when the
relay's copy has changed, so asking twice transfers nothing the second time.
It is the relay's own file, byte for byte: nothing is rendered at either end.

Run `fex help` for the full option list.

## License

Copyright (C) 2026 Andrei Ilin <ortfero@gmail.com>

fex is free software: you can redistribute it and/or modify it under the terms
of the GNU Affero General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version -- see [LICENSE](LICENSE).

Section 13 extends this to network use: if you run a modified fex that users
interact with over a network, you must offer them its Corresponding Source.

Of the vendored dependencies, dano is AGPL-3.0-or-later like fex; the rest keep
their own permissive terms (MIT, CC0, public domain).
