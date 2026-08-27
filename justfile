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
# lays out a relay root and two client roots, then publishes, fetches, mutates and
# reads back again. {{smoke_dir}} is removed on success and left behind for
# inspection on failure; the relay is stopped either way.
#
# It depends on build-release-host rather than build-release: the latter installs
# into {{macos_out}} and {{linux_out}}, leaving whatever happens to sit in
# zig-out/bin for {{bin}} to run.

# End-to-end check with the optimized binaries: publish, inventory, fetch, mutate
smoke: build-release-host
    #!/usr/bin/env bash
    set -euo pipefail
    demo="{{smoke_dir}}"
    addr="127.0.0.1:{{smoke_port}}"
    capsule="$demo/alice/self/notes@relay1/files"
    replica="$demo/alice2/self/notes@relay1/files"
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
    mkdir -p "$demo/relay" "$demo/alice/keys" "$capsule/docs" "$demo/alice2/keys"
    cp "$demo/keys/relay1.dano"       "$demo/relay/node.dano"
    # registration (#3): a line in roster.danl, which is the registry and the
    # directory the relay publishes at once (#6)
    pub=$(sed -n 's/.*:pub "\([0-9a-f]*\)".*/\1/p' "$demo/keys/alice.card.dano")
    printf '{:kind "member" :name "alice" :pub "%s"}\n' "$pub" > "$demo/relay/roster.danl"
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

    echo "==> what the relay holds, from a second root"
    {{client_bin}} inventory --root "$demo/alice2" --name notes | tee "$demo/out" | sed "s/^/    /"
    grep -q "seq 1, 2 files" "$demo/out"
    grep -q "docs/readme.txt  10" "$demo/out"
    grep -q "blob.bin  2000000" "$demo/out"

    echo "==> the same file, fetched by name and read out with its hashes"
    {{client_bin}} fetch inventory.danl --root "$demo/alice2" --name notes | tee "$demo/out" | sed "s/^/    /"
    grep -q "already up to date" "$demo/out"   # the inventory command just fetched it
    sed "s/^/    /" "$replica/inventory.danl"
    grep -q ':path "docs/readme.txt" :size 10' "$replica/inventory.danl"
    grep -q ':path "blob.bin" :size 2000000' "$replica/inventory.danl"

    echo "==> fetch both files into it"
    {{client_bin}} fetch docs/readme.txt --root "$demo/alice2" --name notes | sed "s/^/    /"
    {{client_bin}} fetch blob.bin        --root "$demo/alice2" --name notes | sed "s/^/    /"
    diff -r "$capsule" "$replica"
    cmp "$capsule/inventory.danl" "$replica/inventory.danl"
    echo "    trees identical"

    echo "==> fetching an unchanged file downloads nothing"
    {{client_bin}} fetch blob.bin --root "$demo/alice2" --name notes | tee "$demo/out" | sed "s/^/    /"
    grep -q "already up to date" "$demo/out"

    echo "==> mutate: edit one file, delete one, add one"
    echo "hello fex, edited" > "$capsule/docs/readme.txt"
    rm "$capsule/blob.bin"
    mkdir -p "$capsule/new"
    echo "fresh" > "$capsule/new/note.txt"
    {{client_bin}} publish --root "$demo/alice" | tee "$demo/out" | sed "s/^/    /"
    grep -q "as seq 2" "$demo/out"

    echo "==> the inventory follows, and fetch takes nothing away"
    {{client_bin}} inventory --root "$demo/alice2" --name notes | tee "$demo/out" | sed "s/^/    /"
    grep -q "seq 2, 2 files" "$demo/out"
    ! grep -q "blob.bin" "$demo/out"
    ! grep -q "blob.bin" "$replica/inventory.danl"
    {{client_bin}} fetch docs/readme.txt --root "$demo/alice2" --name notes | sed "s/^/    /"
    {{client_bin}} fetch new/note.txt    --root "$demo/alice2" --name notes | sed "s/^/    /"
    cmp "$capsule/docs/readme.txt" "$replica/docs/readme.txt"
    cmp "$capsule/new/note.txt" "$replica/new/note.txt"
    cmp "$capsule/inventory.danl" "$replica/inventory.danl"
    test -e "$replica/blob.bin"          # what left the inventory is still standing
    test -z "$(ls "$demo/alice2/self/notes@relay1/state/staging")"
    echo "    what was asked for arrived, and nothing else moved"

    echo "==> the relay's directory (#6): list says where it stands, get brings it"
    {{client_bin}} roster --root "$demo/alice" --name notes | tee "$demo/roster" | sed "s/^/    /"
    grep -q "member  alice" "$demo/roster"
    test -f "$demo/alice/peers/relay1/roster.danl"      # #10.3: under the relay it came from
    ! grep -q ':addr' "$demo/alice/peers/relay1/roster.danl"   # identity only
    # asking again is a list and a local hash, not a transfer
    {{client_bin}} roster --root "$demo/alice" --name notes | grep -q "already up to date"

    echo "==> relay state: a head, and the objects it leads to (#6)"
    sed "s/^/    /" "$demo/relay/capsules/alice/head.dano"
    echo "    objects: $(ls "$demo/relay/objects" | wc -l | tr -d ' ')"
    # the head names the inventory, and the inventory is an object like the rest
    inv=$(sed -n 's/.*:hash "\([0-9a-f]*\)".*/\1/p' "$demo/relay/capsules/alice/head.dano")
    test -f "$demo/relay/objects/$inv"
    sed "s/^/    /" "$demo/relay/objects/$inv"
    # nothing is laid out by path any more
    test ! -e "$demo/relay/capsules/alice/tree"
    test ! -e "$demo/relay/capsules/alice/inventory.danl"

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
