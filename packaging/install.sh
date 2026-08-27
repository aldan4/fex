#!/bin/sh
# SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# fexerver, set up in one command: the service user, the root, the binaries, the
# identity and the service file for whichever init this machine runs.
#
#   doas ./packaging/install.sh --addr relay.example.net:4444
#
# It is safe to run twice: nothing already in place is touched, and an identity
# that exists is never overwritten -- that file is the relay, and a new one would
# make every member's card useless.

set -eu

addr=""
root=/var/lib/fexerver
user=fexerver
bindir=/usr/bin
from=""
dry=0

here=$(cd "$(dirname "$0")" && pwd)

usage() {
	cat <<'USAGE'
usage:
  install.sh --addr <host:port> [--root <path>] [--user <name>]
             [--from <dir>] [--bin-dir <path>] [--dry-run]

  --addr <host:port>  the address members will dial -- your public one, not the
                      bind address. Required the first time: it is what the
                      relay's card carries.
  --root <path>       relay root (default: /var/lib/fexerver)
  --user <name>       service user (default: fexerver)
  --from <dir>        where fexerver and fex are (default: alongside this
                      script's zig-out, then the current directory)
  --bin-dir <path>    where to install them (default: /usr/bin)
  --dry-run           print what would happen and change nothing
USAGE
}

die() { echo "install.sh: $*" >&2; exit 1; }
say() { echo "==> $*"; }

run() {
	if [ "$dry" -eq 1 ]; then
		echo "     $*"
	else
		"$@"
	fi
}

while [ $# -gt 0 ]; do
	case $1 in
		--addr) [ $# -ge 2 ] || die "--addr needs a value"; addr=$2; shift 2 ;;
		--root) [ $# -ge 2 ] || die "--root needs a value"; root=$2; shift 2 ;;
		--user) [ $# -ge 2 ] || die "--user needs a value"; user=$2; shift 2 ;;
		--from) [ $# -ge 2 ] || die "--from needs a value"; from=$2; shift 2 ;;
		--bin-dir) [ $# -ge 2 ] || die "--bin-dir needs a value"; bindir=$2; shift 2 ;;
		--dry-run|-n) dry=1; shift ;;
		-h|--help) usage; exit 0 ;;
		*) die "unknown option '$1'" ;;
	esac
done

[ "$dry" -eq 1 ] || [ "$(id -u)" = 0 ] || die "run this as root: doas $0 ... (or sudo)"

# -- where the binaries are ---------------------------------------------------

if [ -z "$from" ]; then
	for d in "$here/../zig-out/x86_64-linux-musl/bin" "$here/../zig-out/aarch64-linux-musl/bin" \
	         "$here/../zig-out/bin" "$here" "$PWD"; do
		if [ -x "$d/fexerver" ] && [ -x "$d/fex" ]; then from=$d; break; fi
	done
fi
[ -n "$from" ] || die "cannot find fexerver and fex; say --from <dir>"
[ -x "$from/fexerver" ] || die "no fexerver in $from"
[ -x "$from/fex" ] || die "no fex in $from"

# -- which init ---------------------------------------------------------------

if [ -d /run/systemd/system ]; then
	init=systemd
elif command -v rc-service >/dev/null 2>&1; then
	init=openrc
elif [ -d /etc/sv ] || command -v sv >/dev/null 2>&1; then
	init=runit
else
	init=none
fi
say "init: $init, binaries from $from"

# -- the service user ---------------------------------------------------------

if id "$user" >/dev/null 2>&1; then
	say "user $user is already there"
elif command -v adduser >/dev/null 2>&1 && adduser --help 2>&1 | grep -q "\-S"; then
	say "creating $user (busybox adduser)"
	run addgroup -S "$user" 2>/dev/null || true
	run adduser -S -D -H -h "$root" -s /sbin/nologin -G "$user" -g "fex capsule relay" "$user"
elif command -v useradd >/dev/null 2>&1; then
	say "creating $user (useradd)"
	for sh in /usr/sbin/nologin /sbin/nologin /usr/bin/nologin /bin/false; do
		[ -x "$sh" ] && break
	done
	run useradd --system --no-create-home --home-dir "$root" \
	    --shell "$sh" --user-group "$user"
elif [ "$dry" -eq 1 ]; then
	say "would create $user (no adduser or useradd on this machine)"
else
	die "no adduser or useradd here; create the user '$user' yourself and re-run"
fi

# -- binaries and root --------------------------------------------------------

say "installing fexerver and fex into $bindir"
run install -m 0755 "$from/fexerver" "$bindir/fexerver"
run install -m 0755 "$from/fex" "$bindir/fex"

say "relay root $root, owned by $user, mode 0750"
run install -d -o "$user" -g "$user" -m 0750 "$root"

# -- the identity -------------------------------------------------------------
#
# #3: never overwritten. A relay's identity is what makes it that relay, and a
# second one would leave every member holding a card for a node that is gone.

if [ -f "$root/node.dano" ]; then
	say "identity $root/node.dano is already there, left alone"
else
	[ -n "$addr" ] || die "no identity yet, so --addr <host:port> is needed to make one"
	tmp=$(mktemp -d)
	say "generating the relay identity for $addr"
	run "$bindir/fex" generate relay1 --dir "$tmp" --addr "$addr" --intro "fex relay"
	run install -o "$user" -g "$user" -m 0600 "$tmp/relay1.dano" "$root/node.dano"
	run install -m 0644 "$tmp/relay1.card.danl" "$root/relay1.card.danl"
	rm -rf "$tmp"
	card_made=1
fi

# -- the service --------------------------------------------------------------

case $init in
	systemd)
		say "installing the systemd unit"
		run install -m 0644 "$here/systemd/fexerver.service" /etc/systemd/system/fexerver.service
		if [ "$root" != /var/lib/fexerver ]; then
			say "note: the unit serves /var/lib/fexerver, not $root --"
			say "      systemctl edit fexerver, and add ReadWritePaths=$root"
		fi
		run systemctl daemon-reload
		next="systemctl enable --now fexerver"
		;;
	openrc)
		say "installing the OpenRC service"
		run install -m 0755 "$here/openrc/fexerver.initd" /etc/init.d/fexerver
		[ -f /etc/conf.d/fexerver ] \
			|| run install -m 0644 "$here/openrc/fexerver.confd" /etc/conf.d/fexerver
		next="rc-update add fexerver default && rc-service fexerver start"
		;;
	runit)
		say "installing the runit service directory"
		run cp -r "$here/runit/fexerver" /etc/sv/fexerver
		next="ln -s /etc/sv/fexerver /var/service/"
		;;
	*)
		say "no init system recognised: run '$bindir/fexerver serve --root $root' yourself"
		next=""
		;;
esac

echo
say "done. what is left:"
if [ -n "${card_made:-}" ]; then
	echo "     the relay's card is $root/relay1.card.danl -- hand that to your members"
fi
echo "     register one:  doas fexerver include <their.card.danl> --root $root"
echo "     see who is on: doas fexerver roster --root $root"
if [ -n "$next" ]; then
	echo "     start it:      $next"
fi
exit 0
