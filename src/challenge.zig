const std = @import("std");
const jwk = @import("jwk.zig");
const Nonce = @import("nonce.zig").Nonce;
const Directory = @import("directory.zig").Directory;
const utils = @import("utils.zig");
const Base64urlEncoder = std.base64.url_safe_no_pad.Encoder;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;
// Challenge holds information about an ACME challenge.
//
// "An ACME challenge object represents a server's offer to validate a
// client's possession of an identifier in a specific way.  Unlike the
// other objects listed above, there is not a single standard structure
// for a challenge object.  The contents of a challenge object depend on
// the validation method being used.  The general structure of challenge
// objects and an initial set of validation methods are described in
// Section 8." §7.1.5
pub const Challenge = struct {
    // "Challenge objects all contain the following basic fields..." §8

    // type (required, string):  The type of challenge encoded in the
    // object.
    type: []const u8,
    // url (required, string):  The URL to which a response can be posted.
    url: []const u8,
    // status (required, string):  The status of this challenge.  Possible
    // values are "pending", "processing", "valid", and "invalid" (see
    // Section 7.1.6).
    status: []const u8,
    // "The token for a challenge is a string comprised entirely of
    // characters in the URL-safe base64 alphabet." §8.1
    //
    // Used by the http-01, tls-alpn-01, and dns-01 challenges.
    token: []const u8,

    // validated (optional, string):  The time at which the server validated
    // this challenge, encoded in the format specified in [RFC3339].
    // This field is REQUIRED if the "status" field is "valid".
    validated: []const u8 = "",

    // HTTP01ResourcePath returns the URI path for solving the http-01 challenge.
    //
    // "The path at which the resource is provisioned is comprised of the
    // fixed prefix '/.well-known/acme-challenge/', followed by the 'token'
    // value in the challenge." §8.3
    pub fn http01ResourcePath(self: Challenge, buf: []u8) ![]const u8 {
        return try std.fmt.bufPrint(buf, "/.well-known/acme-challenge/{s}", .{
            self.token,
        });
    }

    // A key authorization is a string that concatenates the token for the
    // challenge with a key fingerprint, separated by a "." character (§8.1):
    //
    //     keyAuthorization = token || '.' || base64url(Thumbprint(accountKey))
    //
    // This client package automatically assembles and sets this value for you.
    pub fn keyAuthorization(self: Challenge, buf: []u8, key_pair: KeyPair) ![]const u8 {
        var thumb_buffer: [1024]u8 = undefined;
        const accountThumbprint = try jwk.jwkThumbprint(&thumb_buffer, key_pair);
        return try std.fmt.bufPrint(buf, "{s}.{s}", .{ self.token, accountThumbprint });
    }

    // dns01TXTRecordName returns the name of the TXT record to create for
    // solving the dns-01 challenge.
    //
    // "The client constructs the validation domain name by prepending the
    // label '_acme-challenge' to the domain name being validated, then
    // provisions a TXT record with the digest value under that name." §8.4
    pub fn dns01TXTRecordName(self: Challenge, buf: []u8, identifier: []const u8) ![]const u8 {
        _ = self;
        return try std.fmt.bufPrint(buf, "_acme-challenge.{s}", .{identifier});
    }

    //  dns01TXTRecordValue encodes a key authorization value to be used
    // in a TXT record for the _acme-challenge DNS record.
    //
    // "A client fulfills this challenge by constructing a key authorization
    // from the 'token' value provided in the challenge and the client's
    // account key.  The client then computes the SHA-256 digest [FIPS180-4]
    // of the key authorization.
    //
    // The record provisioned to the DNS contains the base64url encoding of
    // this digest." §8.4
    pub fn dns01TXTRecordValue(self: Challenge, buf: []u8, keyAuthz: []const u8) []const u8 {
        _ = self;
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        var out: [32]u8 = undefined;
        h.update(keyAuthz);
        h.final(out[0..]);
        return Base64urlEncoder.encode(buf, out[0..]);
    }

    // InitiateChallenge "indicates to the server that it is ready for the challenge
    // validation by sending an empty JSON body ('{}') carried in a POST request to
    // the challenge URL (not the authorization URL)." §7.5.1
    pub fn initiateChallenge(
        self: Challenge,
        key_pair: KeyPair,
        http_client: *std.http.Client,
        nonce: Nonce,
        directory: Directory,
        allocator: std.mem.Allocator,
        location: []const u8,
    ) !std.json.Parsed(Challenge) {
        const uri = try std.Uri.parse(self.url);
        var buf: [4096]u8 = undefined;
        var req = try http_client.open(.POST, uri, .{ .server_header_buffer = &buf });
        defer req.deinit();

        const current_nonce = try nonce.get(http_client, directory.newNonce);
        defer nonce.free(current_nonce);

        var body_buffer: [4096]u8 = undefined;
        var payload_buf: [1024]u8 = undefined;
        const body = try jwk.encodeJSON(
            &body_buffer,
            "ES256",
            current_nonce,
            self.url,
            location,
            Base64urlEncoder.encode(&payload_buf, "{}"),
            key_pair,
        );

        req.transfer_encoding = .{ .content_length = body.len };
        req.headers.content_type = .{ .override = "application/jose+json" };

        try req.send();
        var wtr = req.writer();
        try wtr.writeAll(body);
        try req.finish();
        try req.wait();

        const response = try req.reader().readAllAlloc(allocator, 4096);
        defer allocator.free(response);

        if (req.response.status != .ok) {
            std.log.err("{s}\n", .{response});
            return error.FailedRequest;
        }
        const new_nonce = try utils.getHeader(req.response, "Replay-Nonce");
        try nonce.new(new_nonce);
        std.debug.print("response: {s}\n", .{response});

        return try std.json.parseFromSlice(
            Challenge,
            allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );
    }
};
