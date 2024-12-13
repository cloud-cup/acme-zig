const std = @import("std");
const jwk = @import("jwk.zig");
const utils = @import("utils.zig");
const acme = @import("Acme.zig");

const Identifier = @import("order.zig").Identifier;
const Challenge = @import("challenge.zig").Challenge;
const Directory = @import("directory.zig").Directory;
const Nonce = @import("nonce.zig").Nonce;
const Order = @import("order.zig").Order;

const Base64urlEncoder = std.base64.url_safe_no_pad.Encoder;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;
const JsonAuthz = std.json.Parsed(AuthorizationBody);
const AuthzOps = acme.AuthorizationOption;
const CHALLENGE = acme.CHALLENGE;

const AuthorizationBody = struct {
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
};

// Authorization "represents a server's authorization for
// an account to represent an identifier.  In addition to the
// identifier, an authorization includes several metadata fields, such
// as the status of the authorization (e.g., 'pending', 'valid', or
// 'revoked') and which challenges were used to validate possession of
// the identifier." §7.1.4
pub const Authorization = struct {
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    directory: Directory,
    nonce: Nonce,
    key_pair: KeyPair,
    authorizations: []JsonAuthz = &[_]JsonAuthz{},

    pub fn init(
        allocator: std.mem.Allocator,
        http_client: *std.http.Client,
        directory: Directory,
        nonce: Nonce,
        key_pair: KeyPair,
    ) Authorization {
        return Authorization{
            .allocator = allocator,
            .http_client = http_client,
            .directory = directory,
            .nonce = nonce,
            .key_pair = key_pair,
        };
    }

    pub fn deinit(self: Authorization) void {
        for (self.authorizations) |authz| {
            authz.deinit();
        }
        self.allocator.free(self.authorizations);
    }

    pub fn new(self: Authorization, location: []const u8, authz_urls: []const []const u8, authzOption: AuthzOps) !Authorization {
        const authorizations = try self.allocator.alloc(JsonAuthz, authz_urls.len);
        errdefer self.deinit();

        for (authz_urls, 0..) |authz_url, i| {
            const result = self.getAuthoriztions(location, authz_url) catch |err| {
                for (0..i) |j| {
                    authorizations[j].deinit();
                }
                self.allocator.free(authorizations);
                return err;
            };
            authorizations[i] = result;
            try self.authorize(result.value.challenges, result.value.identifier, authzOption.challenge);
        }
        if (authzOption.type == .poll) {
            for (authz_urls, 0..) |authz_url, i| {
                const result = self.pollAuthorization(location, authz_url) catch |err| {
                    for (0..authz_urls.len) |j| {
                        authorizations[j].deinit();
                    }
                    self.allocator.free(authorizations);
                    return err;
                };
                authorizations[i].deinit();
                authorizations[i] = result;
            }
        }

        var authz = self;
        authz.authorizations = authorizations;
        return authz;
    }

    // PollAuthorization polls the authorization resource endpoint until the authorization is
    // considered "finalized" which means that it either succeeded, failed, or was abandoned.
    // It blocks until that happens or until the configured timeout.
    //
    // "Usually, the validation process will take some time, so the client
    // will need to poll the authorization resource to see when it is
    // finalized."
    //
    // "For challenges where the client can tell when the server
    // has validated the challenge (e.g., by seeing an HTTP or DNS request
    // from the server), the client SHOULD NOT begin polling until it has
    // seen the validation request from the server." §7.5.1
    fn pollAuthorization(self: Authorization, location: []const u8, auth_url: []const u8) !JsonAuthz {
        const start = std.time.nanoTimestamp();
        const interval = 250 * std.time.ns_per_ms; // 250 ms in nanoseconds
        const max_duration = 5 * std.time.s_per_min * std.time.ns_per_s; // 5 minutes in nanoseconds
        var json_authz = try self.getAuthoriztions(location, auth_url);

        while (std.time.nanoTimestamp() - start < max_duration) {
            if (authzIsFinalized(json_authz.value.status)) {
                return json_authz;
            }
            // Sleep before the next poll
            std.time.sleep(interval);
            json_authz.deinit();
            // Refresh the authorization object
            json_authz = try self.getAuthoriztions(location, auth_url);
        }

        json_authz.deinit();
        return error.Timeout; // Return a timeout error if max duration is exceeded
    }

    // post
    fn getAuthoriztions(self: Authorization, location: []const u8, auth_url: []const u8) !JsonAuthz {
        const uri = try std.Uri.parse(auth_url);
        var buf: [4096]u8 = undefined;
        var req = try self.http_client.open(.POST, uri, .{ .server_header_buffer = &buf });
        defer req.deinit();

        const current_nonce = try self.nonce.get(self.http_client, self.directory.newNonce);
        defer self.nonce.free(current_nonce);

        var body_buffer: [4096]u8 = undefined;
        const body = try jwk.encodeJSON(
            &body_buffer,
            "ES256",
            current_nonce,
            auth_url,
            location,
            "",
            self.key_pair,
        );

        req.transfer_encoding = .{ .content_length = body.len };
        req.headers.content_type = .{ .override = "application/jose+json" };

        try req.send();
        var wtr = req.writer();
        try wtr.writeAll(body);
        try req.finish();
        try req.wait();

        const response = try req.reader().readAllAlloc(self.allocator, 4096);
        defer self.allocator.free(response);

        if (req.response.status != .ok) {
            std.log.err("{s}\n", .{response});
            return error.FailedRequest;
        }
        const new_nonce = try utils.getHeader(req.response, "Replay-Nonce");
        try self.nonce.new(new_nonce);

        return try std.json.parseFromSlice(
            AuthorizationBody,
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );
    }

    fn authorize(self: Authorization, challenges: []Challenge, identifier: Identifier, challenge: CHALLENGE) !void {
        const chall = findChallenge(challenges, challenge);
        var keyAuthz_buf: [1024]u8 = undefined;
        const key_authz = try chall.keyAuthorization(&keyAuthz_buf, self.key_pair);
        if (challenge == .ChallengeTypeHTTP01) {
            var http01_buf: [1024]u8 = undefined;
            const http01_path = try chall.http01ResourcePath(&http01_buf);
            std.debug.print("Path:{s}\n", .{http01_path});
            std.debug.print("Content:{s}\n", .{key_authz});
        }
        if (challenge == .ChallengeTypeDNS01) {
            var dns_name_buf: [1024]u8 = undefined;
            var dns_value_buf: [1024]u8 = undefined;
            const txt_record_name = try chall.dns01TXTRecordName(&dns_name_buf, identifier.value);
            const txt_record_value = chall.dns01TXTRecordValue(&dns_value_buf, key_authz);
            std.debug.print("TXT Record Name: {s}\n", .{txt_record_name});
            std.debug.print("TXT Record Value: {s}\n", .{txt_record_value});
        }
    }
};

// authzIsFinalized returns true if the authorization is finished,
// whether successfully or not. If not, an error will be returned.
// Post-valid statuses that make an authz unusable are treated as
// errors.
fn authzIsFinalized(status: []const u8) bool {
    if (stringEgl(status, "pending")) {
        // "Authorization objects are created in the 'pending' state." §7.1.6
        return false;
    }
    if (stringEgl(status, "valid")) {
        // "If one of the challenges listed in the authorization transitions
        // to the 'valid' state, then the authorization also changes to the
        // 'valid' state." §7.1.6
        return true;
    }
    if (stringEgl(status, "invalid")) {
        // "If the client attempts to fulfill a challenge and fails, or if
        // there is an error while the authorization is still pending, then
        // the authorization transitions to the 'invalid' state." §7.1.6

        // todo: get error message for each domain
        std.log.err("authorization failed: {s}", .{status});
        return true;
    }
    if (stringEgl(status, "expired") or stringEgl(status, "deactivated") or stringEgl(status, "revoked")) {
        // Once the authorization is in the 'valid' state, it can expire
        // ('expired'), be deactivated by the client ('deactivated', see
        // Section 7.5.2), or revoked by the server ('revoked')." §7.1.6
        std.log.err("authorization : {s}", .{status});
        return true;
    }
    if (stringEgl(status, "")) {
        std.log.err("status unknown", .{});
        return false;
    }
    std.log.err("server set unrecognized authorization status: {s}", .{status});
    return true;
}

fn findChallenge(challenges: []Challenge, selected_challenge: CHALLENGE) Challenge {
    for (challenges) |chall| {
        if (stringEgl(chall.type, getChallenge(selected_challenge))) {
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
inline fn stringEgl(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
