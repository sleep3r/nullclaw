const std = @import("std");
const builtin = @import("builtin");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const sqlite_include: std.Build.LazyPath = .{
        .cwd_relative = b.option(
            []const u8,
            "sqlite-include",
            "Path to SQLite include directory (default: /opt/homebrew/opt/sqlite/include on macOS, /usr/include on Linux)",
        ) orelse switch (builtin.os.tag) {
            .macos => "/opt/homebrew/opt/sqlite/include",
            else => "/usr/include",
        },
    };
    const sqlite_lib: std.Build.LazyPath = .{
        .cwd_relative = b.option(
            []const u8,
            "sqlite-lib",
            "Path to SQLite lib directory (default: /opt/homebrew/opt/sqlite/lib on macOS, /usr/lib/x86_64-linux-gnu on Linux)",
        ) orelse switch (builtin.os.tag) {
            .macos => "/opt/homebrew/opt/sqlite/lib",
            else => "/usr/lib/x86_64-linux-gnu",
        },
    };

    // ---------- library module (importable by consumers) ----------
    const lib_mod = b.addModule("nullclaw", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addIncludePath(sqlite_include);

    // ---------- executable ----------
    const exe = b.addExecutable(.{
        .name = "nullclaw",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "nullclaw", .module = lib_mod },
            },
        }),
    });

    // Link SQLite on the compile step (not the module)
    exe.root_module.addLibraryPath(sqlite_lib);
    exe.linkSystemLibrary2("sqlite3", .{});
    exe.linkLibC();
    exe.dead_strip_dylibs = true;

    if (optimize != .Debug) {
        exe.root_module.strip = true;
        exe.root_module.unwind_tables = .none;
        exe.root_module.omit_frame_pointer = true;
    }

    b.installArtifact(exe);

    // macOS: strip local symbols post-install (Zig strip only removes debug info)
    if (optimize != .Debug and builtin.os.tag == .macos) {
        const strip_cmd = b.addSystemCommand(&.{ "strip", "-x", "zig-out/bin/nullclaw" });
        strip_cmd.step.dependOn(b.getInstallStep());
        b.default_step = &strip_cmd.step;
    }

    // ---------- run step ----------
    const run_step = b.step("run", "Run nullclaw");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // ---------- tests ----------
    const lib_tests = b.addTest(.{ .root_module = lib_mod });
    lib_tests.root_module.addLibraryPath(sqlite_lib);
    lib_tests.linkSystemLibrary2("sqlite3", .{});
    lib_tests.linkLibC();

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });

    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);
}
