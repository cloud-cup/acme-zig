const std = @import("std");
const utils = @import("utils.zig");
const Acme = @import("Acme.zig").Acme;

pub const Nonce = struct {
    nonces: *std.ArrayList([]u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, nonces: *std.ArrayList([]u8)) Nonce {
        return Nonce{
            .allocator = allocator,
            .nonces = nonces,
        };
    }

    pub fn deinit(self: Nonce) void {
        for (self.nonces.items) |nonce| {
            self.allocator.free(nonce);
        }
    }
    pub fn free(self: Nonce, nonce: []u8) void {
        self.allocator.free(nonce);
    }

    pub fn get(self: Nonce, http_client: *std.http.Client, new_nonce: []const u8) ![]u8 {
        if (self.nonces.popOrNull()) |nonce| {
            return nonce;
        }
        var buf_header: [4096]u8 = undefined;
        var req = try http_client.open(
            .GET,
            try std.Uri.parse(new_nonce),
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
        const nonce = try utils.getHeader(req.response, "Replay-Nonce");
        return try self.allocator.dupe(u8, nonce);
    }

    pub fn new(self: Nonce, nonce: []const u8) !void {
        try self.nonces.append(try self.allocator.dupe(u8, nonce));
    }
};
