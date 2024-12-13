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
    var nonces = std.ArrayList([]u8).init(allocator);
    defer nonces.deinit();

    var client = try Acme.init(allocator, &http_client, &nonces, .LetsEncryptProductionCA);
    defer client.deinit();

    try client.newAccount(&[_][]const u8{"aliamer@gmail.com"});
    try client.newOrder(&[_][]const u8{"cloud-cup.duckdns.org"}, .{ .type = .poll, .challenge = .ChallengeTypeHTTP01 });
}
