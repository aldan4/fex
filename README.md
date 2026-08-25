# fex

A capsule synchronization protocol over UDP. Each member owns exactly one
**capsule** -- a local directory published to a **relay** and restored back from
it, byte for byte. The relay stores capsules without interpreting their
contents; there is no access to other members' capsules and no anonymous
access.

Members are identified by an x25519 key pair. A channel key is derived locally
on both sides (`hash(dh(priv, pub))[0:16]`), so there is no handshake and no
durable channel state: the channel exists for as long as the member's card sits
in the relay's registry. Every datagram is sealed with ascon-aead128, and
publication is transactional -- a capsule on the relay always matches its
inventory, even across a crash mid-commit.

The protocol is specified in [doc/fex_spec.md](doc/fex_spec.md). The
implementation is header-only C++23 under `include/fex/`, with two thin
executables: `fexerver` (the relay) and `fex` (the client).

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
and end-to-end tests, `just smoke` for a full publish/restore run against the
real binaries, and `just check` for all of it.

## Running a relay

A relay needs its own identity and a directory of member cards. Generate the
identity anywhere and move it into place; `--addr` is what makes the generated
card a relay's card, and `--intro` is an optional public note.

```sh
zig-out/bin/fex generate relay1 --addr relay.example.net:4444 --intro "home relay"

mkdir -p relay-root/members
mv relay1.dano relay-root/node.dano       # secret, mode 0600, never share it
                                          # relay1.card.dano goes to your members
```

Register a member by dropping their card into `members/`. The **file name is
the member name**, and it becomes their capsule directory on disk:

```sh
cp alice.card.dano relay-root/members/alice.dano
```

Then serve:

```sh
zig-out/bin/fexerver --root relay-root --addr 0.0.0.0:4444
```

The relay keeps `members/` and `capsules/<name>/` under its root, and rereads
the registry when it changes -- adding or removing a member does not need a
restart. Ctrl-C stops it.

## Using a client

Generate an identity, hand the card to whoever runs the relay, and get the
relay's card back. Fingerprints are printed on generation: compare them over an
independent channel before trusting a card.

```sh
zig-out/bin/fex generate alice --intro "family photo archive"
```

Lay out the client root. The relay card must be named `<relay>.relay.dano`, and
the capsule directory `<name>@<relay>` must use the same `<relay>`:

```sh
mkdir -p client-root/keys client-root/self/notes@relay1
mv alice.dano             client-root/keys/node.dano
cp relay1.card.dano       client-root/keys/relay1.relay.dano
```

Put whatever you want to sync into the capsule, then publish and restore:

```sh
echo "hello fex" > client-root/self/notes@relay1/note.txt

zig-out/bin/fex publish --root client-root
zig-out/bin/fex restore --root client-root
```

`publish` snapshots the directory, uploads what the relay is missing and
commits; running it again with nothing changed is a no-op. `restore` makes the
local directory match the relay, downloading what is missing, copying files
that merely moved, and deleting what disappeared. On another machine, repeat
the layout with the same identity and run `restore --name notes`.

Capsule contents are regular files with lowercase ASCII names; symlinks,
special files and unrepresentable names abort a publication rather than being
silently skipped. Run `fex help` for the full option list.

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
