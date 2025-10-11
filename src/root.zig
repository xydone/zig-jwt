const std = @import("std");

pub const decode = @import("decode.zig").decode;
pub const decodeNoVerify = @import("decode.zig").decodeNoVerify;
pub const DecodingKey = @import("decode.zig").DecodingKey;
pub const Validation = @import("validation.zig").Validation;
pub const encode = @import("encode.zig").encode;
pub const EncodingKey = @import("encode.zig").EncodingKey;

/// A collection of commonly used signature algorithms which
/// JWT adopted from JOSE specifications.
///
/// For a fuller list, [this list](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms).
pub const Algorithm = enum {
    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,
    /// ECDSA using SHA-256
    ES256,
    /// ECDSA using SHA-384
    ES384,
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
    /// RSASSA-PSS using SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512
    PS512,
    /// Edwards-curve Digital Signature Algorithm (EdDSA)
    EdDSA,

    pub fn jsonStringify(
        self: @This(),
        out: anytype,
    ) !void {
        try out.write(@tagName(self));
    }
};

pub const Header = struct {
    alg: Algorithm,
    typ: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    jku: ?[]const u8 = null,
    jwk: ?[]const u8 = null,
    kid: ?[]const u8 = null,
    x5t: ?[]const u8 = null,
    @"x5t#S256": ?[]const u8 = null,

    // todo add others
    //
    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var out = std.json.writeStream(writer, .{ .emit_null_optional_fields = false });
        defer out.deinit();
        try out.write(self);
    }
};

pub fn JWT(comptime ClaimSet: type) type {
    return struct {
        arena: *std.heap.ArenaAllocator,
        header: Header,
        claims: ClaimSet,

        pub fn deinit(self: *@This()) void {
            const child = self.arena.child_allocator;
            self.arena.deinit();
            child.destroy(self.arena);
        }
    };
}

// ES256 tests

const TestES256Data = struct {
    allocator: std.mem.Allocator,
    token: []const u8,
    validation: Validation,
    pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,

    fn init(allocator: std.mem.Allocator) !TestES256Data {
        const validation: Validation = .{
            .now = struct {
                fn func() u64 {
                    return 1722441274; // Wednesday, July 31, 2024 3:54:34 PM - in seconds
                }
            }.func,
        };

        // predicable key generation
        var seed: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(seed[0..], "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
        const pair = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(seed);

        const token = try encode(
            allocator,
            .{ .alg = .ES256 },
            .{ .sub = "test", .exp = validation.now() + 60 },
            .{ .es256 = pair.secret_key },
        );
        return .{ .token = token, .validation = validation, .pair = pair, .allocator = allocator };
    }

    fn deinit(self: TestES256Data) void {
        self.allocator.free(self.token);
    }
};

test {
    _ = @import("bench.zig");
}

test "ES256.roundtrip" {
    const allocator = std.testing.allocator;
    const data = try TestES256Data.init(allocator);
    defer data.deinit();

    try std.testing.expectEqualStrings("eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzIyNDQxMzM0fQ.0ZiqWyJd3TKN2yB01Xhg91p8qmW-L0XrZunsHwkr2L3D79T45g8Imrqk5V5AhfLbBjqd2NPuZHcChpsSxiGtNw", data.token);

    var jwt = try decode(
        allocator,
        struct { sub: []const u8 },
        data.token,
        .{ .es256 = data.pair.public_key },
        data.validation,
    );
    defer jwt.deinit();
    try std.testing.expectEqualStrings("test", jwt.claims.sub);
}

test "ES256.roundtrip.invalidsignature" {
    const allocator = std.testing.allocator;
    const data = try TestES256Data.init(allocator);
    defer data.deinit();

    const invalid_token = try std.fmt.allocPrint(allocator, "{s}ab", .{data.token});
    defer allocator.free(invalid_token);

    var jwt = decode(
        allocator,
        struct { sub: []const u8 },
        invalid_token,
        .{ .es256 = data.pair.public_key },
        data.validation,
    ) catch |err| {
        return try std.testing.expect(err == error.InvalidSignature);
    };
    defer jwt.deinit();

    return error.TestUnexpectedResult;
}

test "ES256.malformedjwt" {
    const allocator = std.testing.allocator;
    const data = try TestES256Data.init(allocator);
    defer data.deinit();

    var jwt = decode(
        allocator,
        struct { sub: []const u8 },
        "a",
        .{ .es256 = data.pair.public_key },
        data.validation,
    ) catch |err| {
        return try std.testing.expect(err == error.MalformedJWT);
    };
    defer jwt.deinit();

    return error.TestUnexpectedResult;
}

// ES384 tests

const TestES384Data = struct {
    allocator: std.mem.Allocator,
    token: []const u8,
    validation: Validation,
    pair: std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair,

    fn init(allocator: std.mem.Allocator) !TestES384Data {
        const validation: Validation = .{
            .now = struct {
                fn func() u64 {
                    return 1722441274; // Wednesday, July 31, 2024 3:54:34 PM - in seconds
                }
            }.func,
        };

        // predicable key generation
        var seed: [48]u8 = undefined;
        _ = try std.fmt.hexToBytes(seed[0..], "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
        const pair = try std.crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair.generateDeterministic(seed);

        const token = try encode(
            allocator,
            .{ .alg = .ES384 },
            .{ .sub = "test", .exp = validation.now() + 60 },
            .{ .es384 = pair.secret_key },
        );
        return .{ .allocator = allocator, .token = token, .pair = pair, .validation = validation };
    }

    fn deinit(self: TestES384Data) void {
        self.allocator.free(self.token);
    }
};

test "ES384.roundtrip" {
    const allocator = std.testing.allocator;
    const data = try TestES384Data.init(allocator);
    defer data.deinit();
    try std.testing.expectEqualStrings("eyJhbGciOiJFUzM4NCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzIyNDQxMzM0fQ.2ZdUkqVjxip97kY-oWdMUXa6ryahNwHUSqWv2iO3k6dtcIHdD3tD3cO2uh8UGFncJBc4n6lCT-F9Q357pazj1uG0Obvr7whnSt_Suc9mP-MwPuCXyQrnb-QGw1lHBKlj", data.token);

    var jwt = try decode(
        allocator,
        struct { sub: []const u8 },
        data.token,
        .{ .es384 = data.pair.public_key },
        data.validation,
    );
    defer jwt.deinit();
    try std.testing.expectEqualStrings("test", jwt.claims.sub);
}

test "ES384.roundtrip.invalidsignature" {
    const allocator = std.testing.allocator;
    const data = try TestES384Data.init(allocator);
    defer data.deinit();

    const invalid_token = try std.fmt.allocPrint(allocator, "{s}abc", .{data.token});
    defer allocator.free(invalid_token);

    var jwt = decode(
        allocator,
        struct { sub: []const u8 },
        invalid_token,
        .{ .es384 = data.pair.public_key },
        data.validation,
    ) catch |err| {
        return try std.testing.expect(err == error.InvalidSignature);
    };
    defer jwt.deinit();

    return error.TestUnexpectedResult;
}

test "ES384.malformedjwt" {
    const allocator = std.testing.allocator;
    const data = try TestES384Data.init(allocator);
    defer data.deinit();

    var jwt = decode(
        allocator,
        struct { sub: []const u8 },
        "a",
        .{ .es384 = data.pair.public_key },
        data.validation,
    ) catch |err| {
        return try std.testing.expect(err == error.MalformedJWT);
    };
    defer jwt.deinit();

    return error.TestUnexpectedResult;
}

// EdDSA tests

const TestEdDSAData = struct {
    token: []const u8,
    pair: std.crypto.sign.Ed25519.KeyPair,
    validation: Validation,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !TestEdDSAData {
        const validation: Validation = .{
            .now = struct {
                fn func() u64 {
                    return 1722441274; // Wednesday, July 31, 2024 3:54:34 PM - in seconds
                }
            }.func,
        };

        // predicable key generation
        var seed: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(seed[0..], "8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166");
        const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);

        const token = try encode(
            allocator,
            .{ .alg = .EdDSA },
            .{ .sub = "test", .exp = validation.now() + 60 },
            .{ .edsa = pair.secret_key },
        );
        return .{ .token = token, .pair = pair, .validation = validation, .allocator = allocator };
    }

    fn deinit(self: TestEdDSAData) void {
        self.allocator.free(self.token);
    }
};

test "EdDSA.roundtrip" {
    const allocator = std.testing.allocator;
    const data = try TestEdDSAData.init(allocator);
    defer data.deinit();

    try std.testing.expectEqualStrings("eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxNzIyNDQxMzM0fQ.qV1oOiw9DmKfaxVv3_W6zn878ke6D-G70bzAMTtNB4-3dCk5reLaqrXEMluP-0vjgfdQaJc-J0XANMP2CVymDQ", data.token);

    var jwt = try decode(
        allocator,
        struct { sub: []const u8 },
        data.token,
        .{ .edsa = data.pair.public_key },
        data.validation,
    );
    defer jwt.deinit();
    try std.testing.expectEqualStrings("test", jwt.claims.sub);
}

test "EdDSA.roundtrip.invalidsignature" {
    const allocator = std.testing.allocator;
    const data = try TestEdDSAData.init(allocator);
    defer data.deinit();

    const invalid_token = try std.fmt.allocPrint(allocator, "{s}ab", .{data.token});
    defer allocator.free(invalid_token);

    var jwt = decode(
        allocator,
        struct { sub: []const u8 },
        invalid_token,
        .{ .edsa = data.pair.public_key },
        data.validation,
    ) catch |err| {
        return try std.testing.expect(err == error.InvalidSignature);
    };
    defer jwt.deinit();

    return error.TestUnexpectedResult;
}

test "EdDSA.malformedjwt" {
    const allocator = std.testing.allocator;
    const data = try TestEdDSAData.init(allocator);
    defer data.deinit();

    var jwt = decode(
        allocator,
        struct { sub: []const u8 },
        "a",
        .{ .edsa = data.pair.public_key },
        data.validation,
    ) catch |err| {
        return try std.testing.expect(err == error.MalformedJWT);
    };
    defer jwt.deinit();

    return error.TestUnexpectedResult;
}

// HS256 tests

const TestHS256Data = struct {
    allocator: std.mem.Allocator,
    token: []const u8,
    validation: Validation,

    fn init(allocator: std.mem.Allocator) !TestHS256Data {
        const validation: Validation = .{
            .now = struct {
                fn func() u64 {
                    return 1722441274; // Wednesday, July 31, 2024 3:54:34 PM - in seconds
                }
            }.func,
        };
        const token = try encode(allocator, .{ .alg = .HS256 }, .{ .sub = "test", .exp = validation.now() + 60 }, .{ .secret = "secret" });
        return .{ .token = token, .validation = validation, .allocator = allocator };
    }
    fn deinit(self: TestHS256Data) void {
        self.allocator.free(self.token);
    }
};

test "HS256.roundtrip" {
    const allocator = std.testing.allocator;
    const data = try TestHS256Data.init(allocator);
    defer data.deinit();

    var jwt = try decode(
        std.testing.allocator,
        struct { sub: []const u8 },
        data.token,
        .{ .secret = "secret" },
        data.validation,
    );
    defer jwt.deinit();
    try std.testing.expectEqualStrings("test", jwt.claims.sub);
}

test "HS256.roundtrip.invalidsignature" {
    const allocator = std.testing.allocator;
    const data = try TestHS256Data.init(allocator);
    defer data.deinit();

    const invalid_token = try std.fmt.allocPrint(allocator, "{s}a", .{data.token});
    defer allocator.free(invalid_token);
    var jwt = decode(
        std.testing.allocator,
        struct { sub: []const u8 },
        invalid_token,
        .{ .secret = "secret" },
        data.validation,
    ) catch |err| {
        return try std.testing.expect(err == error.InvalidSignature);
    };
    defer jwt.deinit();

    return error.TestUnexpectedResult;
}

test "HS256.malformedjwt" {
    const allocator = std.testing.allocator;
    const data = try TestHS256Data.init(allocator);
    defer data.deinit();

    var jwt = decode(
        std.testing.allocator,
        struct { sub: []const u8 },
        "a",
        .{ .secret = "secret" },
        data.validation,
    ) catch |err| {
        return try std.testing.expect(err == error.MalformedJWT);
    };
    defer jwt.deinit();

    return error.TestUnexpectedResult;
}

test {
    std.testing.refAllDecls(@This());
}
