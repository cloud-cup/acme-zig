const std = @import("std");
const jwk = @import("jwk.zig");

const CA = enum {
    LetsEncryptProductionCA,
};

pub const Acme = struct {
    http_client: *std.http.Client,
    json_dir: std.json.Parsed(std.json.Value),
    dir: Directory,
    nonces: *std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator, http_client: *std.http.Client, nonces: *std.ArrayList([]const u8), ca: CA) !Acme {
        const uri = try std.Uri.parse(getCAUrl(ca));
        var buf: [4096]u8 = undefined;
        var req = try http_client.open(.GET, uri, .{ .server_header_buffer = &buf });
        defer req.deinit();
        try req.send();
        try req.finish();
        try req.wait();

        if (req.response.status != .ok) {
            return error.failedResponse;
        }
        var buffer: [4096]u8 = undefined;
        const res = try req.reader().read(&buffer);

        const json_dir = try std.json.parseFromSlice(std.json.Value, allocator, buffer[0..res], .{});

        return Acme{
            .http_client = http_client,
            .json_dir = json_dir,
            .nonces = nonces,
            .dir = Directory.fromJSON(json_dir.value.object),
        };
    }

    pub fn deinit(self: *Acme) void {
        self.json_dir.deinit();
    }

    pub fn newAccount(self: Acme, emails: []const []const u8) !void {
        const pub_key = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.create(null);

        var payload_buffer: [4096]u8 = undefined;
        const payload = try jwk.encodeJSON(
            &payload_buffer,
            "ES256",
            try self.nonce(),
            self.dir.new_account,
            null,
            emails,
            pub_key,
        );

        const uri = try std.Uri.parse(self.dir.new_account);
        var buf: [4096]u8 = undefined;
        var req = try self.http_client.open(.POST, uri, .{ .server_header_buffer = &buf });
        defer req.deinit();

        req.transfer_encoding = .{ .content_length = payload.len };
        req.headers.content_type = .{ .override = "application/jose+json" };

        try req.send();
        var wtr = req.writer();
        try wtr.writeAll(payload);
        try req.finish();
        try req.wait();

        var allocator = std.heap.page_allocator;

        var rdr = req.reader();
        const body = try rdr.readAllAlloc(allocator, 1024 * 1024 * 4);
        defer allocator.free(body);
        // todo
        std.debug.print("Body:\n{s}\n", .{body});
    }

    fn nonce(self: Acme) ![]const u8 {
        if (self.nonces.popOrNull()) |n| {
            return n;
        }

        var buf_header: [4096]u8 = undefined;
        var req_nonce = try self.http_client.open(
            .GET,
            try std.Uri.parse(self.dir.new_nonce),
            .{ .server_header_buffer = &buf_header },
        );
        defer req_nonce.deinit();
        try req_nonce.send();
        try req_nonce.finish();
        try req_nonce.wait();

        var iter = req_nonce.response.iterateHeaders();
        var replay_nonce: []const u8 = undefined;
        while (iter.next()) |header| {
            if (std.mem.eql(u8, "Replay-Nonce", header.name)) {
                replay_nonce = header.value;
                break;
            }
        }
        return replay_nonce;
    }
};

fn getCAUrl(ca: CA) []const u8 {
    return switch (ca) {
        .LetsEncryptProductionCA => "https://acme-staging-v02.api.letsencrypt.org/directory",
    };
}

const Directory = struct {
    key_change: []const u8,
    new_account: []const u8,
    new_nonce: []const u8,
    new_order: []const u8,
    revoke_cert: []const u8,

    pub fn fromJSON(json: std.json.ObjectMap) Directory {
        return Directory{
            .key_change = json.get("keyChange").?.string,
            .new_account = json.get("newAccount").?.string,
            .new_nonce = json.get("newNonce").?.string,
            .new_order = json.get("newOrder").?.string,
            .revoke_cert = json.get("revokeCert").?.string,
        };
    }
};
