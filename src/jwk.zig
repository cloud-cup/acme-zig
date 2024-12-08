const std = @import("std");
const Base64urlEncoder = std.base64.url_safe_no_pad.Encoder;
const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;

pub fn encodeJSON(
    buf: []u8,
    alg: []const u8,
    nonce: []const u8,
    url: []const u8,
    kid: ?[]const u8,
    emails: []const []const u8,
    key_pair: KeyPair,
) ![]const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    var jw = std.json.writeStream(fbs.writer(), .{});
    try jw.beginObject();

    try jw.objectField("protected");
    var protected_buffer: [1024]u8 = undefined;
    const protected = try jwsHead(&protected_buffer, alg, nonce, url, kid, key_pair);
    try jw.write(protected);

    try jw.objectField("payload");
    var payload_buffer: [1024]u8 = undefined;
    const payload = try jwsPayload(&payload_buffer, emails);
    try jw.write(payload);

    try jw.objectField("signature");
    var signature_buffer: [1024]u8 = undefined;
    const sig = try jwsSignature(&signature_buffer, protected, payload, key_pair);
    try jw.write(sig);

    try jw.endObject();

    return fbs.getWritten();
}

fn jwsHead(
    protected_buffer: []u8,
    alg: []const u8,
    nonce: []const u8,
    url: []const u8,
    kid: ?[]const u8,
    key_pair: KeyPair,
) ![]const u8 {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    var jw = std.json.writeStream(fbs.writer(), .{});
    try jw.beginObject();

    try jw.objectField("alg");
    try jw.write(alg);

    if (kid) |k| {
        try jw.objectField("kid");
        try jw.write(k);
    } else {
        try jw.objectField("jwk");
        try jwkEncodeP256(&jw, key_pair);
    }
    try jw.objectField("nonce");
    try jw.write(nonce);
    try jw.objectField("url");
    try jw.write(url);

    try jw.endObject();

    return Base64urlEncoder.encode(protected_buffer, fbs.getWritten());
}

fn jwsPayload(payload_buffer: []u8, emails: []const []const u8) ![]const u8 {
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

fn jwsSignature(
    sig_buffer: []u8,
    protected: []const u8,
    payload: []const u8,
    key_pair: KeyPair,
) ![]const u8 {
    var buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();
    try writer.writeAll(protected);
    try writer.writeAll(".");
    try writer.writeAll(payload);

    var signer = try key_pair.signer(null);
    signer.update(fbs.getWritten());
    const sig = try signer.finalize();
    return Base64urlEncoder.encode(sig_buffer, &sig.toBytes());
}

fn jwkEncodeP256(
    jw: anytype,
    key_pair: KeyPair,
) !void {
    const uncompressed_key = key_pair.public_key.toUncompressedSec1();
    const x_bytes = uncompressed_key[1..33];
    const y_bytes = uncompressed_key[33..65];

    try jw.beginObject();

    try jw.objectField("crv");
    try jw.write("P-256");

    try jw.objectField("kty");
    try jw.write("EC");

    try jw.objectField("x");
    var buf_x: [64]u8 = undefined;
    const encoded_x = Base64urlEncoder.encode(&buf_x, x_bytes[0..]);
    try jw.write(encoded_x);

    try jw.objectField("y");
    var buf_y: [64]u8 = undefined;
    const encoded_y = Base64urlEncoder.encode(&buf_y, y_bytes[0..]);
    try jw.write(encoded_y);

    try jw.endObject();
}
