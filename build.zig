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
    const upstream = b.dependency("libssh2", .{});
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const linkage = b.option(std.builtin.LinkMode, "linkage", "Link mode") orelse .static;
    const strip = b.option(bool, "strip", "Omit debug information");
    const pic = b.option(bool, "pie", "Produce Position Independent Code");

    const crypto_choice = b.option(CryptoBackend, "crypto-backend", "Crypto backend: auto|openssl|mbedtls|libgcrypt|wincng") orelse .auto;
    const zlib = b.option(bool, "zlib", "Enable SSH payload compression (links zlib)") orelse false;

    const is_windows = target.result.os.tag == .windows;
    const mbedtls = crypto_choice == .mbedtls;
    const openssl = (crypto_choice == .auto and !is_windows) or crypto_choice == .openssl;
    const wincng = (crypto_choice == .auto and is_windows) or crypto_choice == .wincng;
    const libgcrypt = crypto_choice == .libgcrypt;

    const config_header = b.addConfigHeader(.{}, .{
        .LIBSSH2_API = switch (target.result.os.tag) {
            .windows => "__declspec(dllexport)",
            else => "",
        },
        .LIBSSH2_HAVE_ZLIB = zlib,
        .HAVE_SYS_UIO_H = !is_windows,
        .HAVE_WRITEV = !is_windows,
        .HAVE_SYS_SOCKET_H = !is_windows,
        .HAVE_NETINET_IN_H = !is_windows,
        .HAVE_ARPA_INET_H = !is_windows,
        .HAVE_SYS_TYPES_H = !is_windows,
        .HAVE_INTTYPES_H = true,
        .HAVE_STDINT_H = true,
    });

    const libssh2_src = b.dependency("libssh2", .{});

    const ssh2_lib = b.addLibrary(.{
        .version = version,
        .name = "ssh2",
        .linkage = linkage,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .strip = strip,
            .pic = pic,
        }),
    });
    b.installArtifact(ssh2_lib);
    ssh2_lib.installHeadersDirectory(libssh2_src.path("include"), "", .{});
    ssh2_lib.root_module.addConfigHeader(config_header);
    ssh2_lib.root_module.addIncludePath(upstream.path("include"));
    ssh2_lib.root_module.addCMacro("HAVE_CONFIG_H", "1");
    ssh2_lib.root_module.addCSourceFiles(.{ .files = ssh2_src, .root = upstream.path(""), .flags = ssh2_flags });

    if (mbedtls) {
        ssh2_lib.root_module.addCSourceFile(.{ .file = upstream.path("/src/mbedtls.c"), .flags = ssh2_flags });
        ssh2_lib.root_module.addCMacro("LIBSSH2_MBEDTLS", "1");
        ssh2_lib.linkSystemLibrary("mbedtls");
        ssh2_lib.linkSystemLibrary("mbedcrypto");
        ssh2_lib.linkSystemLibrary("mbedx509");
    }

    if (openssl) {
        ssh2_lib.root_module.addCSourceFile(.{ .file = upstream.path("/src/openssl.c"), .flags = ssh2_flags });
        ssh2_lib.root_module.addCMacro("LIBSSH2_OPENSSL", "1");
        ssh2_lib.linkSystemLibrary("ssl");
        ssh2_lib.linkSystemLibrary("crypto");
    }

    if (wincng) {
        ssh2_lib.root_module.addCSourceFile(.{ .file = upstream.path("/src/wincng.c"), .flags = ssh2_flags });
        ssh2_lib.root_module.addCMacro("LIBSSH2_WINCNG", "1");
        // Windows system libs (zig handles names)
        ssh2_lib.linkSystemLibrary("bcrypt");
        ssh2_lib.linkSystemLibrary("ncrypt");
    }

    if (libgcrypt) {
        ssh2_lib.root_module.addCSourceFile(.{ .file = upstream.path("/src/libgcrypt.c"), .flags = ssh2_flags });
        ssh2_lib.root_module.addCMacro("LIBSSH2_LIBGCRYPT", "1");
        ssh2_lib.linkSystemLibrary("gcrypt");
    }

    if (zlib) {
        if (b.systemIntegrationOption("zlib", .{})) {
            ssh2_lib.root_module.linkSystemLibrary("zlib", .{});
        } else if (b.lazyDependency("zlib", .{
            .target = target,
            .optimize = optimize,
        })) |zlib_dependency| {
            ssh2_lib.root_module.linkLibrary(zlib_dependency.artifact("z"));
        }
    }
}

pub const ssh2_src: []const []const u8 = &.{
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
};

pub const ssh2_flags: []const []const u8 = &.{};
