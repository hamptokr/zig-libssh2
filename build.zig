const std = @import("std");

const version: std.SemanticVersion = .{ .major = 1, .minor = 11, .patch = 1 };

const CryptoBackend = enum {
    auto,
    openssl,
    mbedtls,
    libgcrypt,
    wincng,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const crypto_choice = b.option(CryptoBackend, "crypto-backend", "Crypto backend: auto|openssl|mbedtls|libgcrypt|wincng") orelse .auto;
    const zlib = b.option(bool, "zlib", "Enable SSH payload compression (links zlib)") orelse false;
    const strip = b.option(bool, "strip", "Omit debug information");
    const pic = b.option(bool, "pie", "Produce Position Independent Code");

    const libssh2_src = b.dependency("libssh2", .{});
    const libssh2_root = libssh2_src.path(".");

    const lib = b.addLibrary(.{
        .version = version,
        .name = "ssh2",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .strip = strip,
            .pic = pic,
        }),
    });

    const is_windows = target.result.os.tag == .windows;
    const features = b.addConfigHeader(
        .{
            .style = .{
                .cmake = libssh2_src.path("src/libssh2_config_cmake.h.in"),
            },
            .include_path = "libssh2_config.h",
        },
        .{
            .LIBSSH2_API = if (is_windows) "__declspec(dllexport)" else "",
            .LIBSSH2_HAVE_ZLIB = zlib,
            .HAVE_SYS_UIO_H = !is_windows,
            .HAVE_WRITEV = !is_windows,
            .HAVE_SYS_SOCKET_H = !is_windows,
            .HAVE_NETINET_IN_H = !is_windows,
            .HAVE_ARPA_INET_H = !is_windows,
            .HAVE_SYS_TYPES_H = !is_windows,
            .HAVE_INTTYPES_H = true,
            .HAVE_STDINT_H = true,
        },
    );

    lib.root_module.addCMacro("HAVE_CONFIG_H", "1");

    if (zlib) {
        if (b.systemIntegrationOption("zlib", .{})) {
            lib.root_module.linkSystemLibrary("zlib", .{});
        } else if (b.lazyDependency("zlib", .{
            .target = target,
            .optimize = optimize,
        })) |zlib_dependency| {
            lib.root_module.linkLibrary(zlib_dependency.artifact("z"));
        }
    }

    // Backend agnostic sources
    var sources = std.ArrayList([]const u8){};
    sources.appendSlice(b.allocator, &.{
        "src/agent.c",
        "src/bcrypt_pbkdf.c",
        "src/blowfish.c",
        "src/chacha.c",
        "src/channel.c",
        "src/cipher-chachapoly.c",
        "src/comp.c",
        "src/crypt.c",
        "src/global.c",
        "src/hostkey.c",
        "src/keepalive.c",
        "src/kex.c",
        "src/knownhost.c",
        "src/mac.c",
        "src/misc.c",
        "src/packet.c",
        "src/pem.c",
        "src/poly1305.c",
        "src/publickey.c",
        "src/scp.c",
        "src/session.c",
        "src/sftp.c",
        "src/transport.c",
        "src/userauth.c",
        "src/userauth_kbd_packet.c",
        "src/version.c",
    }) catch unreachable;

    switch (crypto_choice) {
        .openssl => {
            sources.appendSlice(b.allocator, &.{"src/openssl.c"}) catch unreachable;
            lib.root_module.addCMacro("LIBSSH2_OPENSSL", "1");
            lib.linkSystemLibrary("ssl");
            lib.linkSystemLibrary("crypto");
        },
        .mbedtls => {
            sources.appendSlice(b.allocator, &.{"src/mbedtls.c"}) catch unreachable;
            lib.root_module.addCMacro("LIBSSH2_MBEDTLS", "1");
            lib.linkSystemLibrary("mbedtls");
            lib.linkSystemLibrary("mbedcrypto");
            lib.linkSystemLibrary("mbedx509");
        },
        .libgcrypt => {
            sources.appendSlice(b.allocator, &.{"src/libgcrypt.c"}) catch unreachable;
            lib.root_module.addCMacro("LIBSSH2_LIBGCRYPT", "1");
            lib.linkSystemLibrary("gcrypt");
        },
        .wincng => {
            sources.appendSlice(b.allocator, &.{"src/wincng.c"}) catch unreachable;
            lib.root_module.addCMacro("LIBSSH2_WINCNG", "1");
            // Windows system libs (zig handles names)
            lib.linkSystemLibrary("bcrypt");
            lib.linkSystemLibrary("ncrypt");
        },
        .auto => {
            switch (target.result.os.tag) {
                .windows => {
                    sources.appendSlice(b.allocator, &.{"src/wincng.c"}) catch unreachable;
                    lib.root_module.addCMacro("LIBSSH2_WINCNG", "1");
                    // Windows system libs (zig handles names)
                    lib.linkSystemLibrary("bcrypt");
                    lib.linkSystemLibrary("ncrypt");
                },
                else => {
                    sources.appendSlice(b.allocator, &.{"src/openssl.c"}) catch unreachable;
                    lib.root_module.addCMacro("LIBSSH2_OPENSSL", "1");
                    lib.linkSystemLibrary("ssl");
                    lib.linkSystemLibrary("crypto");
                },
            }
        },
    }

    lib.addConfigHeader(features);
    lib.addIncludePath(libssh2_src.path("include"));

    const flags = [_][]const u8{};
    lib.addCSourceFiles(.{
        .root = libssh2_root,
        .files = sources.items,
        .flags = &flags,
    });

    lib.installHeadersDirectory(libssh2_src.path("include"), "", .{});
    b.installArtifact(lib);
}
