#!/bin/sh
# SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# fexerver, set up in one command: the service user, the root, the binaries, the
# identity and the service file for whichever init this machine runs -- and you,
# put in the service group, so that registering members afterwards needs
# neither doas nor a chown.
#
#   doas ./packaging/install.sh --addr relay.example.net:4444
#
# It is safe to run twice: nothing already in place is touched, and an identity
# that exists is never overwritten -- that file is the relay, and a new one would
# make every member's card useless.
#
# Every file is made by the user who is to own it: the identity is generated as
# the service user, straight into the root, so nothing is handed over afterwards.

set -eu

addr=""
root=/var/lib/fexerver
user=fexerver
name=relay1
operator=${DOAS_USER:-${SUDO_USER:-}}
bindir=/usr/bin
from=""
dry=0

here=$(cd "$(dirname "$0")" && pwd)

usage() {
	cat <<'USAGE'
usage:
  install.sh --addr <host:port> [--name <relay>] [--root <path>] [--user <name>]
             [--operator <login>] [--from <dir>] [--bin-dir <path>] [--dry-run]

  --addr <host:port>  the address members will dial -- your public one, not the
                      bind address. Required the first time: it is what the
                      relay's card carries.
  --name <relay>      the relay's name, which its card carries and members file
                      it under (default: relay1)
  --root <path>       relay root (default: /var/lib/fexerver)
  --user <name>       service user (default: fexerver)
  --operator <login>  who manages the roster: put in the service group
                      (default: whoever ran doas or sudo)
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

# one argument, single-quoted for sh -c
quote() {
	printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

# A command run as the service user. Its account is locked with nologin for a
# shell, which su takes no notice of when given a shell of its own.
as_user() {
	cmd=exec
	for a in "$@"; do cmd="$cmd $(quote "$a")"; done
	run su -s /bin/sh -c "cd / && $cmd" "$user"
}

in_group() { id -nG "$1" 2>/dev/null | tr ' ' '\n' | grep -qx "$2"; }

while [ $# -gt 0 ]; do
	case $1 in
		--addr) [ $# -ge 2 ] || die "--addr needs a value"; addr=$2; shift 2 ;;
		--name) [ $# -ge 2 ] || die "--name needs a value"; name=$2; shift 2 ;;
		--root) [ $# -ge 2 ] || die "--root needs a value"; root=$2; shift 2 ;;
		--user) [ $# -ge 2 ] || die "--user needs a value"; user=$2; shift 2 ;;
		--operator) [ $# -ge 2 ] || die "--operator needs a value"; operator=$2; shift 2 ;;
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

# -- the operator -------------------------------------------------------------
#
# The group is what lets you write the root: include and exclude replace
# roster.danl whole, by a rename inside the root, so they need the directory and
# nothing else -- and the relay only ever reads that file, whoever owns it.

if [ -z "$operator" ] || [ "$operator" = root ]; then
	say "no operator to add to $user: run this through doas or sudo, or say --operator <login>"
	operator=""
elif ! id "$operator" >/dev/null 2>&1; then
	die "no such user '$operator' for --operator"
elif in_group "$operator" "$user"; then
	say "$operator is already in the $user group"
	operator_ok=1
else
	say "adding $operator to the $user group"
	if command -v usermod >/dev/null 2>&1; then
		run usermod -aG "$user" "$operator"
	else
		run addgroup "$operator" "$user"
	fi
	operator_added=1
fi

# -- binaries and root --------------------------------------------------------

say "installing fexerver and fex into $bindir"
run install -m 0755 "$from/fexerver" "$bindir/fexerver"
run install -m 0755 "$from/fex" "$bindir/fex"

# 0770: the service user, and the operators in its group. Nobody else can
# traverse it, so what the files inside say is moot.
say "relay root $root, owned by $user, mode 0770"
run install -d -o "$user" -g "$user" -m 0770 "$root"

# -- the identity -------------------------------------------------------------
#
# #3: never overwritten. A relay's identity is what makes it that relay, and a
# second one would leave every member holding a card for a node that is gone.

if [ -f "$root/node.dano" ]; then
	say "identity $root/node.dano is already there, left alone"
else
	[ -n "$addr" ] || die "no identity yet, so --addr <host:port> is needed to make one"
	say "generating the relay identity for $addr, as $user"
	as_user "$bindir/fex" generate "$name" --dir "$root" --addr "$addr" --intro "fex relay"
	run mv "$root/$name.dano" "$root/node.dano"
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
		say "no init system recognised: run '$bindir/fexerver serve --root $root' as $user yourself"
		next=""
		;;
esac

echo
say "done. what is left:"
if [ -n "$next" ]; then
	echo "     start it:      $next"
fi
if [ -n "${operator_added:-}" ]; then
	echo "     log in again, $operator: the $user group counts from the next login"
fi
if [ -n "${card_made:-}" ]; then
	echo "     the relay's card is $root/$name.card.danl -- hand that to your members"
fi
if [ "$root" != /var/lib/fexerver ]; then
	echo "     the root is not the default, so tell the commands where it is:"
	echo "                    export FEXERVER_ROOT=$root"
fi
if [ -n "${operator_added:-}${operator_ok:-}" ]; then
	echo "     register one:  fexerver include <their.card.danl>"
	echo "       or remotely: ssh <this host> fexerver include < their.card.danl"
	echo "     see who is on: fexerver roster"
else
	echo "     register one:  doas fexerver include <their.card.danl>"
	echo "     see who is on: doas fexerver roster"
fi
exit 0
