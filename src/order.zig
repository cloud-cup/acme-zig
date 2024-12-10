const std = @import("std");
const jwk = @import("jwk.zig");
const utils = @import("utils.zig");
const Acme = @import("Acme.zig").Acme;
const Account = @import("account.zig").Account;
const Directory = @import("directory.zig").Directory;
const Nonce = @import("nonce.zig").Nonce;
const Base64urlEncoder = std.base64.url_safe_no_pad.Encoder;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;

const Identifier = struct {
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

        order.body = try std.json.parseFromSlice(
            OrderBody,
            self.allocator,
            response,
            .{ .ignore_unknown_fields = true, .allocate = .alloc_always },
        );
        return order;
    }
};

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
