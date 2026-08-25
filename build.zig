// SPDX-FileCopyrightText: 2026 Andrei Ilin <ortfero@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

const cxx_base_flags: []const []const u8 = &.{ "-std=c++23", "-Wall", "-Wextra", "-Wpedantic", "-fno-rtti", "-fno-exceptions" };
// doctest's REQUIRE family aborts the current test case by throwing, so the test target
// needs exceptions; RTTI comes along because doctest catches by type.
const cxx_test_flags: []const []const u8 = &.{ "-std=c++23", "-Wall", "-Wextra", "-Wpedantic" };
// nanobench throws internally, so the bench target cannot be built without exceptions.
const cxx_bench_flags: []const []const u8 = &.{ "-std=c++23", "-Wall", "-Wextra", "-Wpedantic", "-fno-rtti" };
const c_base_flags: []const []const u8 = &.{"-std=gnu11"};
// Release builds: full optimization plus debug info for profiling/crash analysis.
const release_extra: []const []const u8 = &.{ "-O3", "-g" };

fn concat(b: *std.Build, parts: []const []const []const u8) []const []const u8 {
    return std.mem.concat(b.allocator, []const u8, parts) catch @panic("OOM");
}

fn flagsFor(b: *std.Build, base: []const []const u8, optimize: std.builtin.OptimizeMode) []const []const u8 {
    return if (optimize == .Debug) base else concat(b, &.{ base, release_extra });
}

/// Everything an executable needs: the fex headers, header-only deps, and the
/// compiled crypto sources (ascon-c + TweetNaCl) built straight into it.
const Sources = struct {
    target: std.Build.ResolvedTarget,
    lib_deps: []const *std.Build.Dependency,
    ascon: *std.Build.Dependency,
    tweetnacl: *std.Build.Dependency,
};

fn addExe(
    b: *std.Build,
    name: []const u8,
    main: []const u8,
    cxx_flags: []const []const u8,
    optimize: std.builtin.OptimizeMode,
    src: Sources,
) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .target = src.target,
            .optimize = optimize,
            .link_libcpp = true,
            .strip = false,
        }),
    });
    const mod = exe.root_module;
    mod.addIncludePath(b.path("include"));
    for (src.lib_deps) |dep| mod.addIncludePath(dep.path("include"));
    mod.addCSourceFiles(.{
        .files = &.{main},
        .flags = flagsFor(b, cxx_flags, optimize),
    });
    addAsconSources(b, mod, src.ascon, optimize);
    addTweetNaclSources(b, mod, src.tweetnacl, optimize);
    return exe;
}

/// Ascon-Hash256, Ascon-CXOF128 and Ascon-AEAD128 from ascon-c. Each implementation
/// directory has its own same-named headers (api.h, ascon.h, ...) and exports generic
/// SUPERCOP entry points (crypto_hash, ...), so every file gets its own -I and a -D
/// renaming the entry points to unique fex_ascon_* symbols.
fn addAsconSources(b: *std.Build, mod: *std.Build.Module, ascon: *std.Build.Dependency, optimize: std.builtin.OptimizeMode) void {
    const variants = [_]struct { dir: []const u8, file: []const u8, defines: []const []const u8 }{
        .{ .dir = "crypto_hash/asconhash256/opt64", .file = "hash.c", .defines = &.{
            "-Dcrypto_hash=fex_ascon_hash256",
            "-Dascon_xof=fex_ascon_hash256_xof",
        } },
        .{ .dir = "crypto_cxof/asconcxof128/ref", .file = "hash.c", .defines = &.{
            "-Dcrypto_cxof=fex_ascon_cxof128",
            "-Dcrypto_hash=fex_ascon_cxof128_hash",
        } },
        .{ .dir = "crypto_aead/asconaead128/opt64", .file = "aead.c", .defines = &.{
            "-Dcrypto_aead_encrypt=fex_ascon_aead128_encrypt",
            "-Dcrypto_aead_decrypt=fex_ascon_aead128_decrypt",
        } },
    };
    const tests_inc = b.fmt("-I{s}", .{ascon.path("tests").getPath2(b, null)}); // crypto_*.h prototypes
    for (variants) |v| {
        const impl_inc = b.fmt("-I{s}", .{ascon.path(v.dir).getPath2(b, null)});
        mod.addCSourceFiles(.{
            .root = ascon.path(v.dir),
            .files = &.{v.file},
            .flags = concat(b, &.{ flagsFor(b, c_base_flags, optimize), &.{ impl_inc, tests_inc }, v.defines }),
        });
    }
}

/// X25519 and Ed25519 from TweetNaCl, plus the randombytes() hook the library requires
/// the application to define (see src/randombytes.c).
fn addTweetNaclSources(b: *std.Build, mod: *std.Build.Module, tweetnacl: *std.Build.Dependency, optimize: std.builtin.OptimizeMode) void {
    const flags = flagsFor(b, c_base_flags, optimize);
    mod.addCSourceFiles(.{
        .root = tweetnacl.path(""),
        .files = &.{"tweetnacl.c"}, // randombytes.c from the same package is deliberately unused
        // car25519 does `o[i] -= c << 16` with a negative c: formally UB, well-defined on
        // every two's-complement target, and untouchable in a frozen upstream release.
        // Debug builds enable UBSan for C, which would otherwise trap on it.
        .flags = concat(b, &.{ flags, &.{"-fno-sanitize=undefined"} }),
    });
    mod.addCSourceFiles(.{ .files = &.{"src/randombytes.c"}, .flags = flags });
    if (mod.resolved_target.?.result.os.tag == .windows) mod.linkSystemLibrary("bcrypt", .{});
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const doctest = b.dependency("doctest", .{});
    const nanobench = b.dependency("nanobench", .{});
    const unordered_dense = b.dependency("unordered_dense", .{});
    const dano = b.dependency("dano", .{});

    const src: Sources = .{
        .target = target,
        // header-only libraries: unordered_dense and dano back the fex headers,
        // flags parses the command line in the server and client mains
        .lib_deps = &.{ unordered_dense, dano, b.dependency("flags", .{}) },
        .ascon = b.dependency("ascon_c", .{}),
        .tweetnacl = b.dependency("tweetnacl", .{}),
    };

    // Server executable
    const exe = addExe(b, "fexerver", "src/fexerver.cpp", cxx_base_flags, optimize, src);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the server");
    run_step.dependOn(&run_cmd.step);

    // Client executable
    const client = addExe(b, "fex", "src/fex.cpp", cxx_base_flags, optimize, src);
    b.installArtifact(client);

    const run_client_cmd = b.addRunArtifact(client);
    run_client_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_client_cmd.addArgs(args);
    const run_client_step = b.step("run-client", "Run the client");
    run_client_step.dependOn(&run_client_cmd.step);

    // Unit tests (doctest)
    const tests = addExe(b, "fex-test", "test/test.cpp", cxx_test_flags, optimize, src);
    tests.root_module.addIncludePath(doctest.path(""));
    b.installArtifact(tests);

    const test_cmd = b.addRunArtifact(tests);
    if (b.args) |args| test_cmd.addArgs(args);
    const test_step = b.step("test", "Build and run unit tests");
    test_step.dependOn(&test_cmd.step);

    // Microbenchmarks (doctest runner + nanobench); always built optimized
    const bench = addExe(b, "fex-bench", "bench/bench.cpp", cxx_bench_flags, .ReleaseFast, src);
    bench.root_module.addIncludePath(doctest.path(""));
    bench.root_module.addIncludePath(nanobench.path("src/include"));
    b.installArtifact(bench);

    const bench_cmd = b.addRunArtifact(bench);
    if (b.args) |args| bench_cmd.addArgs(args);
    const bench_step = b.step("bench", "Build (ReleaseFast) and run microbenchmarks");
    bench_step.dependOn(&bench_cmd.step);
}
