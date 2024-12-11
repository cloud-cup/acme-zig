const std = @import("std");
const jwk = @import("jwk.zig");
const utils = @import("utils.zig");

const Identifier = @import("order.zig").Identifier;
const Challenge = @import("challenge.zig").Challenge;
const Directory = @import("directory.zig").Directory;
const Nonce = @import("nonce.zig").Nonce;

const Base64urlEncoder = std.base64.url_safe_no_pad.Encoder;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;

const CHALLENGE = enum {
    ChallengeTypeHTTP01,
    ChallengeTypeDNS01,
};

// Authorization "represents a server's authorization for
// an account to represent an identifier.  In addition to the
// identifier, an authorization includes several metadata fields, such
// as the status of the authorization (e.g., 'pending', 'valid', or
// 'revoked') and which challenges were used to validate possession of
// the identifier." §7.1.4
pub const Authorization = struct {
    // challenges (required, array of objects):  For pending authorizations,
    // the challenges that the client can fulfill in order to prove
    // possession of the identifier.  For valid authorizations, the
    // challenge that was validated.  For invalid authorizations, the
    // challenge that was attempted and failed.  Each array entry is an
    // object with parameters required to validate the challenge.  A
    // client should attempt to fulfill one of these challenges, and a
    // server should consider any one of the challenges sufficient to
    // make the authorization valid.
    challenges: []Challenge,

    // identifier (required, object):  The identifier that the account is
    // authorized to represent.
    identifier: Identifier,
    // expires (optional, string):  The timestamp after which the server
    // will consider this authorization invalid, encoded in the format
    // specified in [RFC3339].  This field is REQUIRED for objects with
    // "valid" in the "status" field.
    expires: []const u8,
    // status (required, string):  The status of this authorization.
    // Possible values are "pending", "valid", "invalid", "deactivated",
    // "expired", and "revoked".  See Section 7.1.6.
    status: []const u8,

    pub fn authorize(self: Authorization, key_pair: KeyPair, challenge: CHALLENGE) !void {
        const chall = findChallenge(self.challenges, challenge);
        var keyAuthz_buf: [1024]u8 = undefined;
        const key_authz = try chall.keyAuthorization(&keyAuthz_buf, key_pair);
        if (challenge == .ChallengeTypeHTTP01) {
            var http01_buf: [1024]u8 = undefined;
            const http01_path = try chall.http01ResourcePath(&http01_buf);
            std.debug.print("Path:{s}\n", .{http01_path});
            std.debug.print("Content:{s}\n", .{key_authz});
        }
        if (challenge == .ChallengeTypeDNS01) {
            var dns_name_buf: [1024]u8 = undefined;
            var dns_value_buf: [1024]u8 = undefined;
            const txt_record_name = try chall.dns01TXTRecordName(&dns_name_buf, self.identifier.value);
            const txt_record_value = chall.dns01TXTRecordValue(&dns_value_buf, key_authz);
            std.debug.print("TXT Record Name: {s}\n", .{txt_record_name});
            std.debug.print("TXT Record Value: {s}\n", .{txt_record_value});
        }
    }
};

fn findChallenge(challenges: []Challenge, selected_challenge: CHALLENGE) Challenge {
    for (challenges) |chall| {
        if (std.mem.eql(u8, chall.type, getChallenge(selected_challenge))) {
            return chall;
        }
    }
    unreachable;
}

fn getChallenge(chall: CHALLENGE) []const u8 {
    return switch (chall) {
        .ChallengeTypeHTTP01 => "http-01",
        .ChallengeTypeDNS01 => "dns-01",
    };
}
