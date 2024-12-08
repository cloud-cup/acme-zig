const std = @import("std");

const JsonDirectory = std.json.Parsed(Directory);

const meta = struct {
    caaIdentities: []const []const u8,
    termsOfService: []const u8,
    website: []const u8,
};

pub const Directory = struct {
    keyChange: []const u8,
    meta: meta,
    newAccount: []const u8,
    newNonce: []const u8,
    newOrder: []const u8,
    renewalInfo: []const u8,
    revokeCert: []const u8,

    pub fn getDirectory(
        http_client: *std.http.Client,
        allocator: std.mem.Allocator,
        dir_url: []const u8,
    ) !JsonDirectory {
        const uri = try std.Uri.parse(dir_url);
        var buf: [4096]u8 = undefined;
        var req = try http_client.open(.GET, uri, .{ .server_header_buffer = &buf });
        defer req.deinit();
        try req.send();
        try req.finish();
        try req.wait();

        const response = try req.reader().readAllAlloc(allocator, 4096);
        defer allocator.free(response);

        if (req.response.status != .ok) {
            std.log.err("{s}\n", .{response});
            return error.FailedRequest;
        }

        return try std.json.parseFromSlice(
            Directory,
            allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );
    }
};
