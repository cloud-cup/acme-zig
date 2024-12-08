const std = @import("std");
const jwk = @import("jwk.zig");
const SecretKey = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;

const Key = struct {
    kty: []const u8,
    crv: []const u8,
    x: []const u8,
    y: []const u8,
};

pub const Account = struct {
    status: []const u8,
    createdAt: []const u8,
    contact: []const []const u8,
    key: Key,

    // NewAccount creates a new account on the ACME server.
    //
    // "A client creates a new account with the server by sending a POST
    // request to the server's newAccount URL." §7.3
    pub fn new(
        http_client: *std.http.Client,
        allocator: std.mem.Allocator,
        new_account: []const u8,
        payload: []const u8,
    ) !std.json.Parsed(Account) {
        const uri = try std.Uri.parse(new_account);
        var buf: [4096]u8 = undefined;
        var req = try http_client.open(.POST, uri, .{ .server_header_buffer = &buf });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = payload.len };
        req.headers.content_type = .{ .override = "application/jose+json" };

        try req.send();
        var wtr = req.writer();
        try wtr.writeAll(payload);
        try req.finish();
        try req.wait();

        const response = try req.reader().readAllAlloc(allocator, 4096);
        defer allocator.free(response);

        if (req.response.status != .created) {
            std.log.err("{s}\n", .{response});
            return error.FailedRequest;
        }

        return try std.json.parseFromSlice(
            Account,
            allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );
    }
};
