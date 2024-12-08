const std = @import("std");
const jwk = @import("jwk.zig");
const Acme = @import("Acme.zig").Acme;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    var http_client = std.http.Client{
        .allocator = allocator,
    };
    defer http_client.deinit();

    var client = try Acme.init(allocator, &http_client, .LetsEncryptProductionCA);
    defer client.deinit();

    const acc = try client.newAccount(&[_][]const u8{
        "aliamer@gmail.com",
    });
    std.debug.print("status: {s}", .{acc.status});
}
