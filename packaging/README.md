# Running a relay as a service

`fexerver serve` is already shaped for supervision: it stays in the foreground,
says one line on startup, writes nothing per request, keeps everything under its
`--root`, and stops on `SIGTERM`. It does not daemonize, drop privileges, write
a pid file or reopen logs -- the service manager does all of that.

This directory carries the files for the three init systems. Registering
members needs nothing from here: `fexerver include` and `fexerver exclude` are
commands of the relay itself.

```
systemd/fexerver.service       systemd unit
systemd/fexerver.sysusers      sysusers.d fragment for the service user
openrc/fexerver.initd          OpenRC service (Alpine and friends)
openrc/fexerver.confd          its settings
runit/fexerver/                runit service directory (Void)
```

## What the relay needs

- **A writable root.** `capsules/` and `objects/` are created there, and every
  temporary file is written and renamed inside it. Nothing is written anywhere
  else -- no `/tmp`, no state outside the root. *Paths and access rights* below
  says who owns what.
- **`<root>/node.dano`**, the relay's identity, mode 0600, readable by the
  service user. It is a secret: it is what makes this relay *this* relay, and a
  lost one cannot be regenerated -- every member's card would have to be
  reissued.
- **`<root>/roster.danl`**, the member registry: one card per line. A missing
  file means a relay nobody is registered on yet, which starts fine; an
  unreadable one stops the relay from starting at all.
- **A UDP port.** 4444 by default, above 1024, so no capability is needed. If
  you move it below 1024, add `AmbientCapabilities=CAP_NET_BIND_SERVICE` (and
  the matching `CapabilityBoundingSet=`) to the unit.
- **Entropy**, through `getrandom(2)`. Nothing else: no DNS, no outbound
  connections, no writable `/tmp`, one thread, one socket.

## Install, on any of the three

Build for the target's libc -- **this is the one thing that differs between the
three** -- and put the binaries in place:

```sh
# Alpine, and any other musl distro (Void's musl flavour included)
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-musl --prefix /tmp/fex-out

# glibc distros: Debian, Fedora, Arch, Void's default flavour
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-gnu --prefix /tmp/fex-out

# an ARM board: swap x86_64 for aarch64 in either line

install -m 0755 /tmp/fex-out/bin/fexerver /usr/bin/fexerver
install -m 0755 /tmp/fex-out/bin/fex      /usr/bin/fex
```

A glibc build will not start on Alpine: it wants `/lib64/ld-linux-x86-64.so.2`,
which a musl system does not have. The musl build is **statically linked** --
that is zig's default for musl -- so it depends on no libc at all and will run
on a glibc distro too, which makes it the safe choice when you are not sure
what you are deploying to. `file` tells the two apart:

```
fexerver: ELF 64-bit LSB executable, x86-64, dynamically linked,
          interpreter /lib64/ld-linux-x86-64.so.2      <- glibc build
fexerver: ELF 64-bit LSB executable, x86-64, statically linked   <- musl build
```

Static linking costs nothing here that it usually costs: the relay resolves no
names, and the `fex` client's `getaddrinfo` works in a static musl binary
because musl reads `/etc/resolv.conf` itself, where a statically linked glibc
would need its NSS modules at runtime and fail.

`just build-release-musl` and `just build-release-linux` are the same two
builds, into `zig-out/<target>/bin`.

Create the service user (it needs no shell and no home of its own):

```sh
# systemd
install -m 0644 packaging/systemd/fexerver.sysusers /usr/lib/sysusers.d/fexerver.conf
systemd-sysusers

# Alpine (busybox adduser)
addgroup -S fexerver
adduser -S -D -H -h /var/lib/fexerver -s /sbin/nologin -G fexerver -g "fex capsule relay" fexerver

# Void (shadow)
useradd --system --no-create-home --home-dir /var/lib/fexerver \
        --shell /usr/bin/nologin --user-group fexerver
```

Lay out the root and give the relay an identity. `--addr` is what makes the
generated card a relay's card -- it is the address **members** will dial, so it
must be the public one, not the bind address:

```sh
install -d -o fexerver -g fexerver -m 0750 /var/lib/fexerver

fex generate relay1 --dir /tmp --addr relay.example.net:4444 --intro "home relay"
install -o fexerver -g fexerver -m 0600 /tmp/relay1.dano /var/lib/fexerver/node.dano
rm -f /tmp/relay1.dano                # the copy outside the root is not wanted
# /tmp/relay1.card.danl is the public half: that is what you hand to members
```

Compare the fingerprint printed by `generate` with your members over some
independent channel before they trust the card.

## Paths and access rights

Everything the relay owns lives under one directory, and one system user owns
that directory. Nothing else needs write access to anything.

| path | owner | mode | who makes it |
|---|---|---|---|
| `/usr/bin/fexerver` | `root:root` | `0755` | you, from the build |
| `/var/lib/fexerver` | `fexerver:fexerver` | `0750` | you, or `StateDirectory=` |
| `/var/lib/fexerver/node.dano` | `fexerver:fexerver` | `0600` | you, from `fex generate` |
| `/var/lib/fexerver/roster.danl` | any, readable by the service | `0644` | `fexerver include` |
| `/var/lib/fexerver/objects/` | `fexerver:fexerver` | umask | the relay, at first start |
| `/var/lib/fexerver/capsules/` | `fexerver:fexerver` | umask | the relay, at first start |
| `/var/log/fexerver.log` (OpenRC) | `fexerver:fexerver` | `0640` | `start_pre` |
| `/var/log/fexerver/` (runit) | `_log:_log` | `0750` | `log/run` |

What the relay makes for itself it makes `0755` and `0644`, filtered through the
service umask: under the shipped systemd unit, which sets `UMask=0077`, that
lands as `0700` and `0600`; under the OpenRC and runit scripts it follows
whatever umask the supervisor was started with, usually `0022`.

Either way the mode that matters is the root's. `0750` on `/var/lib/fexerver`
means no other user can traverse into it, so what the files inside say is moot
-- an `ls -l` showing `-rw-r--r--` on an object is not a leak. Tighten the root,
not the files under it.

`node.dano` is the exception that does not depend on any of this: it is written
`0600` outright, whatever the umask, and it is the one file whose loss cannot be
repaired.

`roster.danl` is public by design -- it is what the relay serves to its
members -- so `0644` is right, and it is the one file you edit. Run
`fexerver include`/`exclude` either as the service user or as root:

```sh
sudo -u fexerver fexerver include alice.card.danl --root /var/lib/fexerver
```

Run as root, the rewritten file ends up `root:root 0644`, which the relay reads
perfectly well -- it never writes that file, only reads it and serves its bytes.
Run as the service user, it stays `fexerver:fexerver`. Either is fine; what is
not fine is a root directory the service user cannot write, since the relay
creates `objects/` and `capsules/` itself and stages every upload inside them.

To check a root over:

```sh
sudo -u fexerver test -w /var/lib/fexerver && echo "writable by the service"
sudo -u fexerver test -r /var/lib/fexerver/node.dano && echo "identity readable"
stat -c '%U:%G %a %n' /var/lib/fexerver /var/lib/fexerver/node.dano
```

## systemd

```sh
install -m 0644 packaging/systemd/fexerver.service /etc/systemd/system/fexerver.service
systemctl daemon-reload
systemctl enable --now fexerver
systemctl status fexerver
journalctl -u fexerver
```

`StateDirectory=fexerver` creates and owns `/var/lib/fexerver`, so the
`install -d` above is only needed if you put the root elsewhere -- in which case
change `--root` and add `ReadWritePaths=` for it. Change settings with a
drop-in rather than by editing the unit:

```sh
systemctl edit fexerver     # [Service] / ExecStart= / ExecStart=/usr/bin/fexerver serve --root ...
```

The unit is hardened down to what the relay actually does: no capabilities, a
read-only system, `AF_INET`/`AF_INET6` only, `@system-service` syscalls. Check
it with `systemd-analyze security fexerver` after any local change.

## OpenRC (Alpine)

```sh
install -m 0755 packaging/openrc/fexerver.initd /etc/init.d/fexerver
install -m 0644 packaging/openrc/fexerver.confd /etc/conf.d/fexerver
rc-update add fexerver default
rc-service fexerver start
tail -f /var/log/fexerver.log
```

The service is run under `supervise-daemon`, since `fexerver` does not
background itself: OpenRC keeps it alive and restarts it after 2 s if it dies.
Settings live in `/etc/conf.d/fexerver`. `start_pre` refuses to start a relay
with no identity rather than letting it fail in the supervisor's loop.

## runit (Void)

```sh
cp -r packaging/runit/fexerver /etc/sv/fexerver
ln -s /etc/sv/fexerver /var/service/
sv status fexerver
tail -f /var/log/fexerver/current
```

`/etc/sv/fexerver/conf` holds the settings; `log/run` runs `svlogd -tt` as
`_log`, so output is rotated in `/var/log/fexerver/`. `sv stop fexerver` sends
`SIGTERM`, which is the clean stop.

## Registering members

The roster is the registry and the published directory at once, and every line
is a card -- so registering someone is their card added to it:

```sh
fexerver include /path/to/alice.card.danl --root /var/lib/fexerver
fexerver roster --root /var/lib/fexerver
fexerver exclude alice --root /var/lib/fexerver
```

`include` writes the card's line and nothing else, refusing a name or a key
already registered (#3) and an identity file handed over in a card's place. It
writes the whole file at once, so a relay reading it mid-change reads one state
or the other. `exclude` takes the line out and leaves `capsules/<name>/` alone:
what a member published is theirs.

Run them as the service user, or as root -- the file is rewritten in place with
the ownership it had:

```sh
install -d -o fexerver -g fexerver -m 0750 /var/lib/fexerver
sudo -u fexerver fexerver include alice.card.danl --root /var/lib/fexerver
```

The name the member goes by here is the `:name` in their card. Renaming someone
is editing that field in the line; the key is what the relay goes by.

The relay picks the change up on the next request it serves, and rereads the
file at most once a second -- adding or removing a member needs no restart and
no signal. `remove` takes the member out of the registry but leaves
`capsules/<name>/` on disk; delete it yourself if that is what you mean.

Hand-editing works too -- `cat alice.card.danl >> roster.danl` is the same
registration -- and the commands only save you from the ways that goes wrong: a
duplicate name or key, a capital letter in a name, uppercase hex, an identity
file pasted where a card was meant, or a half-written file. Any of those makes
the roster invalid, and an invalid roster is refused **whole** --
the relay keeps serving the registry it had before, so everyone already
registered carries on and the new member simply never appears. It says so once
per edit:

```
fexerver: warning: /var/lib/fexerver/roster.danl was not loaded (Invalid argument); the registry in force is the one before it
```

If a registration does not seem to take, that line -- and `fexerver roster` --
is where to look first.

## Backup, and what is worth backing up

- `node.dano` -- irreplaceable. Back it up once, offline, and guard it like a
  key, because it is one.
- `roster.danl` -- cheap to keep, tedious to rebuild (every member's key).
- `objects/` and `capsules/` -- member content. The relay is not the only copy
  by design (every member holds their own capsule), but a member who publishes
  and then loses their machine has only what the relay holds.

A missing object is reported at startup and never silently tolerated:

```
fexerver: warning: 3 pinned object(s) missing from /var/lib/fexerver/objects
```

That means content a capsule's inventory points at is gone from the store.
Nothing can bring it back; the member has to publish it again.

## Upgrading

Replace the binary and restart -- `systemctl restart fexerver`, `rc-service
fexerver restart`, `sv restart fexerver`. There is no on-the-wire state to
drain: a capsule on disk always matches its inventory, a commit interrupted
mid-flight is replayed at the next start, and clients retry. What a restart does
cost is the address cache: every member re-peeks before their next request.

## Firewall

```sh
# nftables
nft add rule inet filter input udp dport 4444 accept
# iptables
iptables -A INPUT -p udp --dport 4444 -j ACCEPT
# Alpine awall, Void iptables-restore: the same one rule
```

UDP only, one port, inbound. The relay never initiates a connection.

## Troubleshooting

**It says nothing after the startup line.** That is all it says. The relay logs
no traffic at all: one line at startup, a warning if pinned objects are missing,
a warning if a roster edit was refused, and nothing further. Silence is the
working state.

**`cannot start: ...`** names what it was doing and what went wrong, and is the
whole story. The relay exits 1 without binding the port, so the supervisor
reports a failed start rather than a relay that is up and serving nobody:

```
fexerver: cannot start: loading the roster /var/lib/fexerver/roster.danl: Invalid argument
fexerver: cannot start: reading the identity /var/lib/fexerver/node.dano: No such file or directory
fexerver: cannot start: binding 0.0.0.0:4444: Address already in use
```

An invalid roster is a refusal to start, not a warning -- the registry is read
before the socket is opened. Only an edit made to a roster that was **valid at
boot** leaves the relay running, on the registry it already had -- and it says
so, once, as described under *Registering members* above.

**A member gets nowhere.** Check they are in `fexerver roster` under the
name they use, that the card they hold is this relay's current one, and that
their clock is inside `--window` seconds of yours: a direct peek outside the
window is refused as a replay.
