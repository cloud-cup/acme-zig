const std = @import("std");
const jwk = @import("jwk.zig");
const Account = @import("account.zig").Account;
const Directory = @import("directory.zig").Directory;

const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;

const CA = enum {
    LetsEncryptProductionCA,
};

pub const Acme = struct {
    http_client: *std.http.Client,
    allocator: std.mem.Allocator,
    json_directory: std.json.Parsed(Directory),
    json_account: ?std.json.Parsed(Account) = null,

    pub fn init(allocator: std.mem.Allocator, http_client: *std.http.Client, ca: CA) !Acme {
        const json_dir = try Directory.getDirectory(http_client, allocator, getCAUrl(ca));

        return Acme{
            .http_client = http_client,
            .allocator = allocator,
            .json_directory = json_dir,
        };
    }

    pub fn deinit(self: *Acme) void {
        self.json_directory.deinit();
        if (self.json_account) |ja| {
            ja.deinit();
        }
    }

    pub fn newAccount(self: *Acme, emails: []const []const u8) !Account {
        const key_pair = try KeyPair.create(null);
        const nonce = try self.getNonce();

        var payload_buffer: [4096]u8 = undefined;
        const payload = try jwk.encodeJSON(
            &payload_buffer,
            "ES256",
            nonce,
            self.json_directory.value.newAccount,
            null,
            emails,
            key_pair,
        );

        const json_account = try Account.new(
            self.http_client,
            self.allocator,
            self.json_directory.value.newAccount,
            payload,
        );
        self.json_account = json_account;
        return json_account.value;
    }

    fn getNonce(self: Acme) ![]const u8 {
        var buf_header: [4096]u8 = undefined;
        var req = try self.http_client.open(
            .GET,
            try std.Uri.parse(self.json_directory.value.newNonce),
            .{ .server_header_buffer = &buf_header },
        );
        defer req.deinit();
        try req.send();
        try req.finish();
        try req.wait();

        const response = try req.reader().readAllAlloc(self.allocator, 4096);
        defer self.allocator.free(response);

        if (req.response.status != .no_content) {
            std.log.err("{s}\n", .{response});
            return error.FailedRequest;
        }

        var iter = req.response.iterateHeaders();
        var replay_nonce: ?[]const u8 = null;
        while (iter.next()) |header| {
            if (std.mem.eql(u8, "Replay-Nonce", header.name)) {
                replay_nonce = header.value;
                break;
            }
        }
        if (replay_nonce) |rn| {
            return rn;
        }
        return error.nonceNotFound;
    }
};

fn getCAUrl(ca: CA) []const u8 {
    return switch (ca) {
        .LetsEncryptProductionCA => "https://acme-staging-v02.api.letsencrypt.org/directory",
    };
}
