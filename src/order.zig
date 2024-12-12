const std = @import("std");
const jwk = @import("jwk.zig");
const utils = @import("utils.zig");
const Directory = @import("directory.zig").Directory;
const Nonce = @import("nonce.zig").Nonce;
const Authorization = @import("authorization.zig").Authorization;
const Base64urlEncoder = std.base64.url_safe_no_pad.Encoder;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;

const JsonAuthz = std.json.Parsed(Authorization);

pub const Identifier = struct {
    type: []const u8,
    value: []const u8,
};

const OrderBody = struct {
    status: []const u8,
    expires: []const u8,
    identifiers: []Identifier,
    authorizations: []const []const u8,
    finalize: []const u8,
};

pub const Order = struct {
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    directory: Directory,
    nonce: Nonce,
    key_pair: KeyPair,
    body: ?std.json.Parsed(OrderBody) = null,
    authorization: []JsonAuthz = &[_]JsonAuthz{},

    pub fn init(
        allocator: std.mem.Allocator,
        http_client: *std.http.Client,
        directory: Directory,
        nonce: Nonce,
        key_pair: KeyPair,
    ) Order {
        return Order{
            .allocator = allocator,
            .http_client = http_client,
            .directory = directory,
            .nonce = nonce,
            .key_pair = key_pair,
        };
    }
    pub fn deinit(self: Order) void {
        if (self.body) |order| {
            order.deinit();
        }
        for (self.authorization) |authz| {
            authz.deinit();
        }
        self.allocator.free(self.authorization);
    }

    // NewOrder creates a new order with the server.
    //
    // "The client begins the certificate issuance process by sending a POST
    // request to the server's newOrder resource." §7.4
    pub fn new(
        self: Order,
        location: []const u8,
        identifiers: []const []const u8,
    ) !Order {
        const dir = self.directory;
        const uri = try std.Uri.parse(dir.newOrder);
        var buf: [4096]u8 = undefined;
        var req = try self.http_client.open(.POST, uri, .{ .server_header_buffer = &buf });
        defer req.deinit();

        const current_nonce = try self.nonce.get(self.http_client, dir.newNonce);
        defer self.nonce.free(current_nonce);

        var payload_buf: [1024]u8 = undefined;
        const payload = try orderPayload(&payload_buf, identifiers);
        var body_buffer: [4096]u8 = undefined;
        const body = try jwk.encodeJSON(
            &body_buffer,
            "ES256",
            current_nonce,
            dir.newOrder,
            location,
            payload,
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

        if (req.response.status != .created) {
            std.log.err("{s}\n", .{response});
            return error.FailedRequest;
        }

        var order = self;
        const new_nonce = try utils.getHeader(req.response, "Replay-Nonce");
        try self.nonce.new(new_nonce);

        order.body = try std.json.parseFromSlice(
            OrderBody,
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );

        order.authorization = try order.getAuthoriztions(location);
        return order;
    }
    fn getAuthoriztions(self: Order, location: []const u8) ![]JsonAuthz {
        if (self.body == null or self.body.?.value.authorizations.len == 0) {
            return error.noAuthorizationLink;
        }
        const authz_urls = self.body.?.value.authorizations;
        const authorizations = try self.allocator.alloc(JsonAuthz, authz_urls.len);
        errdefer self.deinit();

        for (authz_urls, 0..) |authz_url, i| {
            const result = self.getAuthz(location, authz_url) catch |err| {
                for (0..i) |j| {
                    authorizations[j].deinit();
                }
                self.allocator.free(authorizations);
                return err;
            };
            authorizations[i] = result;
        }
        return authorizations;
    }

    fn getAuthz(self: Order, location: []const u8, auth_url: []const u8) !JsonAuthz {
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
            Authorization,
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );
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
    pub fn pollAuthorization(self: Order, location: []const u8, auth_url: []const u8) !JsonAuthz {
        const start = std.time.nanoTimestamp();
        const interval = 250 * std.time.ns_per_ms; // 250 ms in nanoseconds
        const max_duration = 5 * std.time.s_per_min * std.time.ns_per_s; // 5 minutes in nanoseconds

        var json_authz = try self.getAuthz(location, auth_url);

        while (std.time.nanoTimestamp() - start < max_duration) {
            if (authzIsFinalized(json_authz.value.status)) {
                return json_authz;
            }

            // Sleep before the next poll
            std.time.sleep(interval);

            // Refresh the authorization object
            json_authz = try self.getAuthz(location, auth_url);
        }

        return error.Timeout; // Return a timeout error if max duration is exceeded
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

fn orderPayload(payload_buffer: []u8, identifiers: []const []const u8) ![]const u8 {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var jw = std.json.writeStream(fbs.writer(), .{});

    try jw.beginObject();
    try jw.objectField("identifiers");
    try jw.beginArray();
    for (identifiers) |identifier| {
        try jw.beginObject();
        try jw.objectField("type");
        try jw.write("dns");
        try jw.objectField("value");
        try jw.write(identifier);
        try jw.endObject();
    }
    try jw.endArray();

    try jw.endObject();
    return Base64urlEncoder.encode(payload_buffer, fbs.getWritten());
}

inline fn stringEgl(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
