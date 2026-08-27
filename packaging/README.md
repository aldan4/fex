# Running a relay as a service

`fexerver serve` is already shaped for supervision: it stays in the foreground,
says one line on startup, writes nothing per request, keeps everything under its
`--root`, and stops on `SIGTERM`. It does not daemonize, drop privileges, write
a pid file or reopen logs -- the service manager does all of that.

This directory carries the files for the three init systems. Registering
members needs nothing from here: `fexerver include` and `fexerver exclude` are
commands of the relay itself.

```
install.sh                     the whole setup, in one command
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

## Install, in one command

On the server, with the two binaries beside you (built there, or copied over --
see *Cross-compiling* below):

```sh
doas ./packaging/install.sh --addr relay.example.net:4444      # sudo, elsewhere
```

That is the whole of what the rest of this section spells out: it creates the
service user, installs `fexerver` and `fex`, makes the relay root, generates the
identity if there is none, and installs the service file for whichever init the
machine runs -- systemd, OpenRC or runit, detected rather than asked about. Then
it prints the three things left to do: hand out the relay's card, register a
member, start the service.

It is safe to run again: anything already in place is left alone, and an
identity that exists is **never** overwritten -- that file is the relay, and a
second one would leave every member holding a card for a node that is gone.
`--dry-run` prints what it would do and changes nothing; `--root`, `--user`,
`--bin-dir` and `--from` override the defaults.

`--addr` is the address **members** will dial -- your public one, not the bind
address. It is what goes in the relay's card.

The rest of this section is the same work done by hand, for a machine that wants
something other than the defaults.

## Install, step by step

Build one binary for all of Linux. zig links musl statically, so the result
depends on no libc at all and runs on Alpine, Void, Debian and everything else
of that architecture:

```sh
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-musl --prefix /tmp/fex-out
# an ARM board: aarch64-linux-musl

install -m 0755 /tmp/fex-out/bin/fexerver /usr/bin/fexerver
install -m 0755 /tmp/fex-out/bin/fex      /usr/bin/fex
```

The other direction does not work: a `x86_64-linux-gnu` build wants
`/lib64/ld-linux-x86-64.so.2`, which a musl system has not got, so Alpine
answers `not found` for a file that is plainly there. `file` tells the two
apart:

```
fexerver: ELF 64-bit LSB executable, x86-64, dynamically linked,
          interpreter /lib64/ld-linux-x86-64.so.2      <- glibc build
fexerver: ELF 64-bit LSB executable, x86-64, statically linked   <- musl build
```

Static costs nothing here that it usually costs. The relay resolves no names at
all, and the client's `getaddrinfo` works in a static musl binary because musl
reads `/etc/resolv.conf` itself -- a statically linked *glibc* would want its
NSS modules at runtime and fail, which is the usual reason not to do this.

Two things are worth a glibc build anyway (`-Dtarget=x86_64-linux-gnu`, and
`just build-release-linux`):

- **libc updates.** A static binary carries its own libc, so a libc fix reaches
  it when you rebuild and reinstall, not when the machine updates. For a daemon
  on a public port that is a standing errand you have taken on.
- **Name resolution through NSS**, for the client only. musl reads `/etc/hosts`
  and `/etc/resolv.conf` and nothing else, so a relay address that resolves
  through mDNS (`relay.local`), SSSD or another `/etc/nsswitch.conf` module
  will not resolve in a musl build. A plain hostname or an IP is unaffected.

Neither applies to the relay itself if you keep an eye on your own rebuilds, so
musl-static is the default here. `just build-release-musl` and
`just build-release-linux` are the two builds, into `zig-out/<target>/bin`.

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

## Cross-compiling, and copying it over

The server does not have to build anything. zig cross-compiles, and a musl build
is static, so what lands there is two files and no toolchain, no runtime, no
package to install. That is worth doing when the box is small (a 1 GB VPS has a
thin time linking a C++ binary), when you would rather not leave 300 MB of
compiler on a machine that faces the network, or when you want the same bytes on
several relays.

Build for the server's architecture:

```sh
just build-release-musl                       # x86_64, into zig-out/x86_64-linux-musl/bin
# an ARM board:
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux-musl --prefix zig-out/aarch64-linux-musl
```

Copy and install. The trailing **`:`** is what makes the destination remote --
without it scp writes a local file named after your server and says `No such
file or directory`:

```sh
scp -P 22222 zig-out/x86_64-linux-musl/bin/{fexerver,fex} ortfero@relay.example.net:

# on the server -- doas on Alpine, sudo elsewhere
doas install -m 0755 ~/fexerver /usr/bin/fexerver
doas install -m 0755 ~/fex      /usr/bin/fex
```

Check that what arrived is what you built, and that it is the build you think it
is:

```sh
sha256sum /usr/bin/fexerver     # against shasum -a 256 on the build machine
fexerver help | head -12        # a current build lists serve/include/exclude/roster
```

`fexerver version` prints the protocol version, which does not move between
builds -- so the `help` output, not the version, is what tells a stale binary
from a fresh one.

Installing over a running relay is safe: the running process keeps the old
inode and carries on. The new binary takes effect when you restart it --
`systemctl restart fexerver`, `rc-service fexerver restart`, `sv restart
fexerver` -- and *Upgrading* below says what that costs.

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
`fexerver include`/`exclude` **as root**:

```sh
doas fexerver include alice.card.danl --root /var/lib/fexerver     # sudo, elsewhere
```

The rewritten file ends up `root:root 0644`, which the relay reads perfectly
well: it never writes that file, only reads it and serves its bytes.

Do not reach for the service user to do it. `sudo -u fexerver` needs a sudoers
entry you probably have not written, and `su fexerver` cannot work at all --
that account is deliberately locked, with no password and `nologin` for a shell,
which is most of what makes it a service user. Root is the shorter road and
costs nothing here.

What is not fine is a relay root the service user cannot write: the relay
creates `objects/` and `capsules/` itself and stages every upload inside them.

To check a root over:

```sh
stat -c '%U:%G %a %n' /var/lib/fexerver /var/lib/fexerver/node.dano /var/lib/fexerver/roster.danl
doas fexerver roster --root /var/lib/fexerver     # reads what the relay reads
```

The relay itself is the better check than any permission probe: if it starts and
says how many members it has, everything it needs is readable.

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

Run them as root -- `doas` on Alpine, `sudo` elsewhere. Not as the service user:
that account is locked on purpose, so `su fexerver` will only tell you the
password is wrong.

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

One rule: **UDP 4444, inbound**. The relay never initiates a connection, so
nothing outbound needs opening, and no TCP port belongs to it at all.

### ufw

```sh
ufw allow 4444/udp
ufw status verbose
```

**Before `ufw enable` on a machine you reach over ssh, allow ssh first** --
including a port you have moved it to, which ufw knows nothing about:

```sh
ufw allow 22/tcp            # or: ufw allow 22222/tcp, if that is where yours is
ufw enable                  # only now
```

Enabling ufw with a default-deny policy and no ssh rule locks you out of a
remote box, and getting back in means the provider's serial console. To narrow
the relay's rule to the members you know, or to undo it:

```sh
ufw allow from 203.0.113.0/24 to any port 4444 proto udp
ufw delete allow 4444/udp
```

### nftables, iptables, awall

```sh
# nftables
nft add rule inet filter input udp dport 4444 accept

# iptables
iptables -A INPUT -p udp --dport 4444 -j ACCEPT

# Alpine awall: a policy file, the same one rule
#   {"filter": [{"in": "internet", "service": "fex", "action": "accept"}],
#    "service": {"fex": [{"proto": "udp", "port": 4444}]}}
```

If you moved the relay off 4444 with `--addr`, open that port instead -- and
remember the port in the relay's card is the one members dial, so the two have
to agree.

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
