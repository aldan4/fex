bin := "zig-out/bin/fexerver"
client_bin := "zig-out/bin/fex"
macos_target := "aarch64-macos"
linux_target := "x86_64-linux-gnu"
macos_out := "zig-out/" + macos_target
linux_out := "zig-out/" + linux_target
smoke_dir := "/tmp/fex-smoke"
smoke_port := "45444"

default: build

# Debug build
build:
    zig build

# Build debug and run the server
run: build
    {{bin}}

# Build debug and run the client
run-client: build
    {{client_bin}}

# Both platforms are built explicitly, so neither depends on which one is the host.
# Whichever is not the host also compile-checks that platform's poller backend:
# epoll on Linux, kqueue on macOS. Its binaries cannot be run here.

# Optimized builds for macOS and Linux
build-release: build-release-macos build-release-linux

# Optimized build for macOS, into {{macos_out}}/bin
build-release-macos:
    zig build -Doptimize=ReleaseFast -Dtarget={{macos_target}} --prefix {{macos_out}}

# Optimized build for Linux, into {{linux_out}}/bin
build-release-linux:
    zig build -Doptimize=ReleaseFast -Dtarget={{linux_target}} --prefix {{linux_out}}

# Optimized build for the host, into zig-out/bin (this is the one you can run)
build-release-host:
    zig build -Doptimize=ReleaseFast

# Build optimized (host only) and run the server
run-release: build-release-host
    {{bin}}

# Build optimized (host only) and run the client
run-release-client: build-release-host
    {{client_bin}}

# Build (debug) and run unit tests
test:
    zig build test

# Everything that can be verified locally
check: test smoke build-release

# Build (release, enforced in build.zig) and run microbenchmarks
bench:
    zig build bench

# Unlike `test`, which runs a relay in-process, this drives the shipped executables
# over loopback and exercises the on-disk layouts of #6 and #10.3. It generates keys,
# lays out a relay root and two client roots, then publishes, restores, mutates and
# converges. {{smoke_dir}} is removed on success and left behind for inspection on
# failure; the relay is stopped either way.
#
# It depends on build-release-host rather than build-release: the latter installs
# into {{macos_out}} and {{linux_out}}, leaving whatever happens to sit in
# zig-out/bin for {{bin}} to run.

# End-to-end check with the optimized binaries: publish, restore, mutate, converge
smoke: build-release-host
    #!/usr/bin/env bash
    set -euo pipefail
    demo="{{smoke_dir}}"
    addr="127.0.0.1:{{smoke_port}}"
    capsule="$demo/alice/self/notes@relay1"
    replica="$demo/alice2/self/notes@relay1"
    server=""
    cleanup() {
        if [ -n "$server" ]; then kill "$server" 2>/dev/null || true; fi
    }
    trap cleanup EXIT

    echo "==> identities"
    rm -rf "$demo"
    mkdir -p "$demo/keys"
    {{client_bin}} generate relay1 --dir "$demo/keys" --addr "$addr" --intro "smoke relay" >/dev/null
    {{client_bin}} generate alice  --dir "$demo/keys" --intro "smoke member" >/dev/null

    echo "==> relay root, two client roots"
    mkdir -p "$demo/relay/members" "$demo/alice/keys" "$capsule/docs" "$demo/alice2/keys"
    cp "$demo/keys/relay1.dano"       "$demo/relay/node.dano"
    cp "$demo/keys/alice.card.dano"   "$demo/relay/members/alice.dano"
    for root in alice alice2; do
        cp "$demo/keys/alice.dano"       "$demo/$root/keys/node.dano"
        cp "$demo/keys/relay1.card.dano" "$demo/$root/keys/relay1.relay.dano"
    done

    echo "==> content (a small file and a 2 MB one, so put/poll spans many chunks)"
    echo "hello fex" > "$capsule/docs/readme.txt"
    head -c 2000000 /dev/urandom > "$capsule/blob.bin"

    echo "==> relay on $addr"
    {{bin}} --root "$demo/relay" --addr "$addr" > "$demo/relay.log" 2>&1 &
    server=$!
    sleep 0.3
    if ! kill -0 "$server" 2>/dev/null; then
        echo "relay failed to start:"; cat "$demo/relay.log"; exit 1
    fi

    echo "==> publish"
    {{client_bin}} publish --root "$demo/alice" | tee "$demo/out" | sed "s/^/    /"
    grep -q "as seq 1" "$demo/out"

    echo "==> publish again is a no-op"
    {{client_bin}} publish --root "$demo/alice" | tee "$demo/out" | sed "s/^/    /"
    grep -q "already published" "$demo/out"

    echo "==> restore into a second root"
    {{client_bin}} restore --root "$demo/alice2" --name notes | sed "s/^/    /"
    diff -r "$capsule" "$replica"
    echo "    trees identical"

    echo "==> mutate: edit one file, delete one, add one"
    echo "hello fex, edited" > "$capsule/docs/readme.txt"
    rm "$capsule/blob.bin"
    mkdir -p "$capsule/new"
    echo "fresh" > "$capsule/new/note.txt"
    {{client_bin}} publish --root "$demo/alice" | tee "$demo/out" | sed "s/^/    /"
    grep -q "as seq 2" "$demo/out"

    echo "==> restore converges, deletion included"
    {{client_bin}} restore --root "$demo/alice2" --name notes | sed "s/^/    /"
    diff -r "$capsule" "$replica"
    test ! -e "$replica/blob.bin"
    echo "    trees identical"

    echo "==> relay state"
    sed "s/^/    /" "$demo/relay/capsules/alice/head.dano"
    sed "s/^/    /" "$demo/relay/capsules/alice/inventory.danl"

    rm -rf "$demo"
    echo "==> smoke ok"

# Debug build and launch the server under lldb
debug: build
    lldb {{bin}}

# Debug build and launch the client under lldb
debug-client: build
    lldb {{client_bin}}

# Fetch all dependencies from build.zig.zon
fetch:
    zig build --fetch=all

# Add or bump a dependency: just add doctest https://github.com/doctest/doctest/archive/refs/tags/v2.4.12.tar.gz
add name url:
    zig fetch --save={{name}} {{url}}
