const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const jwt_mod = b.addModule("jwt", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    setupTests(b, jwt_mod);

    setupExamples(b, target, optimize, jwt_mod);

    setupBenchmarks(b, target, optimize);
}

// credits to https://github.com/hendriknielaender/zBench/blob/main/build.zig
fn setupExamples(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, jwt_mod: *std.Build.Module) void {
    const example_step = b.step("examples", "Build examples");
    const example_names = [_][]const u8{
        "main",
    };

    for (example_names) |example_name| {
        const example = b.addExecutable(.{
            .name = example_name,
            .root_module = b.createModule(.{
                .root_source_file = .{ .src_path = .{ .owner = b, .sub_path = b.fmt("examples/{s}.zig", .{example_name}) } },
                .target = target,
                .optimize = optimize,
            }),
        });
        const install_example = b.addInstallArtifact(example, .{});
        example.root_module.addImport("jwt", jwt_mod);

        example_step.dependOn(&example.step);
        example_step.dependOn(&install_example.step);
    }
}

// fn setupBenchmarks(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, jwt_mod: *std.Build.Module) void {
//     const benchmark = b.dependency("benchmark", .{
//         .target = target,
//         .optimize = optimize,
//     }).module("benchmark");
//     jwt_mod.addImport("benchmark", benchmark);

//     const benchmark_tests = b.addTest(.{
//         .root_module = jwt_mod,
//         .filters = &.{"bench"},
//     });

//     const run_benchmark_tests = b.addRunArtifact(benchmark_tests);

//     const benchmark_step = b.step("bench", "Run benchmark tests");
//     benchmark_step.dependOn(&run_benchmark_tests.step);
// }
fn setupBenchmarks(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    const benchmark = b.dependency("benchmark", .{
        .target = target,
        .optimize = optimize,
    }).module("benchmark");

    const benchmark_mod = b.addModule("benchmark", .{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    benchmark_mod.addImport("benchmark", benchmark);

    const benchmark_exe = b.addExecutable(.{
        .name = "benchmark",
        .root_module = benchmark_mod,
    });

    const step = b.step("benchmark", "Run the benchmarks");

    const run = b.addRunArtifact(benchmark_exe);
    step.dependOn(&run.step);
}

fn setupTests(b: *std.Build, jwt_mod: *std.Build.Module) void {
    const lib_unit_tests = b.addTest(.{
        .root_module = jwt_mod,
    });

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
}
