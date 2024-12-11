const std = @import("std");
const jwk = @import("jwk.zig");

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
};
