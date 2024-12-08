const std = @import("std");
const jwk = @import("jwk.zig");
const utils = @import("utils.zig");
const Acme = @import("Acme.zig").Acme;
const SecretKey = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;
const Base64urlEncoder = std.base64.url_safe_no_pad.Encoder;

const Key = struct {
    kty: []const u8,
    crv: []const u8,
    x: []const u8,
    y: []const u8,
};

const AccountBody = struct {
    status: []const u8,
    createdAt: []const u8,
    contact: []const []const u8,
    key: Key,
};

pub const Account = struct {
    body: std.json.Parsed(AccountBody) = undefined,
    location: []const u8 = "",

    // NewAccount creates a new account on the ACME server.
    //
    // "A client creates a new account with the server by sending a POST
    // request to the server's newAccount URL." §7.3
    pub fn new(
        acme: *Acme,
        emails: []const []const u8,
        key_pair: KeyPair,
    ) !Account {
        const new_account = acme.directory.value.newAccount;
        const uri = try std.Uri.parse(new_account);
        var buf: [4096]u8 = undefined;
        var req = try acme.http_client.open(.POST, uri, .{ .server_header_buffer = &buf });
        defer req.deinit();
        const nonce = try acme.getNonce();
        var payload_buf: [1024]u8 = undefined;
        const payload = try accountPayload(&payload_buf, emails);
        var body_buffer: [4096]u8 = undefined;
        const body = try jwk.encodeJSON(
            &body_buffer,
            "ES256",
            nonce,
            new_account,
            null,
            payload,
            key_pair,
        );

        req.transfer_encoding = .{ .content_length = body.len };
        req.headers.content_type = .{ .override = "application/jose+json" };

        try req.send();
        var wtr = req.writer();
        try wtr.writeAll(body);
        try req.finish();
        try req.wait();

        const response = try req.reader().readAllAlloc(acme.allocator, 4096);
        defer acme.allocator.free(response);

        if (req.response.status != .created) {
            std.log.err("{s}\n", .{response});
            return error.FailedRequest;
        }

        var account = Account{};
        account.body = try std.json.parseFromSlice(
            AccountBody,
            acme.allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );

        account.location = try utils.getHeader(req.response, "Location");

        return account;
    }
};

fn accountPayload(payload_buffer: []u8, emails: []const []const u8) ![]const u8 {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var jw = std.json.writeStream(fbs.writer(), .{});

    var mailto_buf: [1024]u8 = undefined;

    try jw.beginObject();
    try jw.objectField("termsOfServiceAgreed");
    try jw.write(true);
    try jw.objectField("contact");
    try jw.beginArray();
    for (emails) |email| {
        const mailto_email = try std.fmt.bufPrint(&mailto_buf, "mailto:{s}", .{email});
        try jw.write(mailto_email);
    }
    try jw.endArray();

    try jw.endObject();
    return Base64urlEncoder.encode(payload_buffer, fbs.getWritten());
}
