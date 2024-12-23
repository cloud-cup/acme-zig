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
    try client.newOrder(&[_][]const u8{"cloud-cup.duckdns.org"});
    const challenge = try client.authorize(.ChallengeTypeHTTP01);

    // Prompt user to indicate when they have completed setting up the challenge
    try std.io.getStdOut().writer().print("Set up the challenge and press ENTER to continue...\n", .{});

    const stdin = std.io.getStdIn().reader();
    var buf: [1]u8 = undefined;
    _ = try stdin.readUntilDelimiterOrEof(buf[0..], '\n');
    try client.pollAuthorization();

    for (client.authorization.authorizations) |authz| {
        std.debug.print("Challenge result: {s}\n", .{authz.value.status});
    }

    // Verify the challenge after user input
    try client.verfiyChallenge(challenge);

    var buffer: [5120]u8 = undefined;
    const file = try std.fs.cwd().openFile("./csr.txt", .{});
    const size = try file.reader().readAll(&buffer);
    try client.finalizeOrder(buffer[0..size]);
}
