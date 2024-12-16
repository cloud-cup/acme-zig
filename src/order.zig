const std = @import("std");
const jwk = @import("jwk.zig");
const utils = @import("utils.zig");
const Directory = @import("directory.zig").Directory;
const Nonce = @import("nonce.zig").Nonce;
const Authorization = @import("authorization.zig").Authorization;
const Base64urlEncoder = std.base64.url_safe_no_pad.Encoder;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;

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
    certificate: ?[]const u8 = null,
};

pub const Order = struct {
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    directory: Directory,
    nonce: Nonce,
    key_pair: KeyPair,
    body: ?std.json.Parsed(OrderBody) = null,
    location: ?[]const u8 = null,

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

        order.location = try utils.getHeader(req.response, "Location");
        order.body = try std.json.parseFromSlice(
            OrderBody,
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );
        return order;
    }

    // FinalizeOrder finalizes the order with the server and polls under the server has
    // updated the order status. The CSR must be in ASN.1 DER-encoded format. If this
    // succeeds, the certificate is ready to download once this returns.
    //
    // "Once the client believes it has fulfilled the server's requirements,
    // it should send a POST request to the order resource's finalize URL." §7.4
    pub fn finalizeOrder(self: Order, location: []const u8, csrASN1DER: []u8) !Order {
        var new_order = try self.postFinalize(self.body.?.value.finalize, location, csrASN1DER);
        if (orderIsFinished(new_order.body.?.value.status)) {
            return new_order;
        }
        const start = std.time.nanoTimestamp();
        const interval = 250 * std.time.ns_per_ms; // 250 ms in nanoseconds
        const max_duration = 5 * std.time.s_per_min * std.time.ns_per_s; // 5 minutes in nanoseconds

        while (std.time.nanoTimestamp() - start < max_duration) {
            if (orderIsFinished(new_order.body.?.value.status)) {
                return new_order;
            }

            std.debug.print("order is {s}\n", .{new_order.body.?.value.status});

            // Sleep before the next poll
            std.time.sleep(interval);
            new_order.deinit();

            // Refresh the authorization object
            new_order = try self.postFinalize(new_order.location.?, location, csrASN1DER);
        }
        if (!orderIsFinished(new_order.body.?.value.status)) {
            new_order.deinit();
            return error.Timeout;
        }
        return new_order;
    }

    fn postFinalize(self: Order, url: []const u8, location: []const u8, csrASN1DER: []u8) !Order {
        const uri = try std.Uri.parse(url);
        var buf: [4096]u8 = undefined;
        var req = try self.http_client.open(.POST, uri, .{ .server_header_buffer = &buf });
        defer req.deinit();

        const current_nonce = try self.nonce.get(self.http_client, self.directory.newNonce);
        defer self.nonce.free(current_nonce);

        var payload_buf: [7168]u8 = undefined;
        const payload = try finalizesBody(&payload_buf, csrASN1DER);
        var body_buffer: [10240]u8 = undefined;
        const body = try jwk.encodeJSON(
            &body_buffer,
            "ES256",
            current_nonce,
            url,
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

        std.debug.print("response:: {s}\n", .{response});

        if (req.response.status != .created) {
            std.log.err("{s}\n", .{response});
            return error.FailedRequest;
        }

        var order = self;
        const new_nonce = try utils.getHeader(req.response, "Replay-Nonce");
        try self.nonce.new(new_nonce);
        order.location = try utils.getHeader(req.response, "Location");

        const order_body = try std.json.parseFromSlice(
            OrderBody,
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );
        errdefer order_body.deinit();
        order.body = order_body;

        return order;
    }
};

fn finalizesBody(payload_buf: []u8, csr: []u8) ![]const u8 {
    var buf: [6144]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var jw = std.json.writeStream(fbs.writer(), .{});

    try jw.beginObject();
    try jw.objectField("csr");
    try jw.write(csr);
    try jw.endObject();

    return Base64urlEncoder.encode(payload_buf, fbs.getWritten());
}

// orderIsFinished returns true if the order processing is complete,
// regardless of success or failure. If this function returns true,
// polling an order status should stop. If there is an error with the
// order, an error will be returned. This function should be called
// only after a request to finalize an order. See §7.4.
fn orderIsFinished(status: []const u8) bool {
    if (stringEgl(status, "invalid")) {
        // "invalid": The certificate will not be issued.  Consider this
        //      order process abandoned.
        return true;
    }
    if (stringEgl(status, "pending")) {
        // "pending": The server does not believe that the client has
        //      fulfilled the requirements.  Check the "authorizations" array for
        //      entries that are still pending.
        return true;
    }
    if (stringEgl(status, "ready")) {
        // "ready": The server agrees that the requirements have been
        //      fulfilled, and is awaiting finalization.  Submit a finalization
        //      request.
        // (we did just submit a finalization request, so this is an error)
        return true;
    }
    if (stringEgl(status, "processing")) {
        // "processing": The certificate is being issued.  Send a GET request
        //      after the time given in the "Retry-After" header field of the
        //      response, if any.
        return false;
    }
    if (stringEgl(status, "valid")) {
        // "valid": The server has issued the certificate and provisioned its
        //      URL to the "certificate" field of the order.  Download the
        //      certificate.
        return true;
    }
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
