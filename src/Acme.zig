const std = @import("std");
const jwk = @import("jwk.zig");
const utils = @import("utils.zig");
const Account = @import("account.zig").Account;
const Directory = @import("directory.zig").Directory;

const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;

const CA = enum {
    LetsEncryptProductionCA,
};

pub const Acme = struct {
    http_client: *std.http.Client,
    allocator: std.mem.Allocator,
    directory: std.json.Parsed(Directory),
    account: ?Account = null,
    nonce: []const u8 = "",

    pub fn init(allocator: std.mem.Allocator, http_client: *std.http.Client, ca: CA) !Acme {
        const json_dir = try Directory.getDirectory(http_client, allocator, getCAUrl(ca));
        return Acme{
            .http_client = http_client,
            .allocator = allocator,
            .directory = json_dir,
        };
    }

    pub fn deinit(self: *Acme) void {
        self.directory.deinit();
        if (self.account) |ja| {
            ja.body.deinit();
        }
    }

    pub fn newAccount(self: *Acme, emails: []const []const u8) !Account {
        const key_pair = try KeyPair.create(null);
        self.account = try Account.new(self, emails, key_pair);
        return self.account.?;
    }

    pub fn getNonce(self: *Acme) ![]const u8 {
        if (self.nonce.len != 0) {
            return self.nonce;
        }

        var buf_header: [4096]u8 = undefined;
        var req = try self.http_client.open(
            .GET,
            try std.Uri.parse(self.directory.value.newNonce),
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
        self.nonce = try utils.getHeader(req.response, "Replay-Nonce");

        return self.nonce;
    }
};

fn getCAUrl(ca: CA) []const u8 {
    return switch (ca) {
        .LetsEncryptProductionCA => "https://acme-staging-v02.api.letsencrypt.org/directory",
    };
}
