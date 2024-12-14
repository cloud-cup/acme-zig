const std = @import("std");
const jwk = @import("jwk.zig");
const utils = @import("utils.zig");
const Directory = @import("directory.zig").Directory;
const Nonce = @import("nonce.zig").Nonce;
const Account = @import("account.zig").Account;
const Order = @import("order.zig").Order;
const Challenge = @import("challenge.zig").Challenge;
const Authorization = @import("authorization.zig").Authorization;

const KeyPair = std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair;
const JsonAuthz = std.json.Parsed(Authorization);
const CA = enum {
    LetsEncryptProductionCA,
};

pub const CHALLENGE = enum {
    ChallengeTypeHTTP01,
    ChallengeTypeDNS01,
};

pub const Acme = struct {
    allocator: std.mem.Allocator,
    http_client: *std.http.Client,
    key_pair: KeyPair,
    directory: std.json.Parsed(Directory),
    nonce: Nonce,
    account: Account,
    order: Order,
    authorization: Authorization,
    challenge: ?std.json.Parsed(Challenge) = null,

    pub fn init(
        allocator: std.mem.Allocator,
        http_client: *std.http.Client,
        nonces: *std.ArrayList([]u8),
        ca: CA,
    ) !Acme {
        const key_pair = try KeyPair.create(null);
        const json_dir = try Directory.init(http_client, allocator, getCAUrl(ca));
        const nonce = Nonce.init(allocator, nonces);
        const account = Account.init(allocator, http_client, json_dir.value, nonce, key_pair);
        const order = Order.init(allocator, http_client, json_dir.value, nonce, key_pair);
        const authz = Authorization.init(allocator, http_client, json_dir.value, nonce, key_pair);
        return Acme{
            .http_client = http_client,
            .allocator = allocator,
            .key_pair = key_pair,
            .directory = json_dir,
            .nonce = nonce,
            .account = account,
            .order = order,
            .authorization = authz,
        };
    }

    pub fn deinit(self: *Acme) void {
        self.directory.deinit();
        self.account.deinit();
        self.order.deinit();
        self.nonce.deinit();
        self.authorization.deinit();
        if (self.challenge) |c| {
            c.deinit();
        }
    }

    pub fn getNonce(self: Acme) ![]u8 {
        return try self.nonce.get(self.http_client, self.directory.value.newNonce);
    }

    pub fn newAccount(self: *Acme, emails: []const []const u8) !void {
        self.account = try self.account.new(emails);
    }

    pub fn newOrder(self: *Acme, identifiers: []const []const u8) !void {
        if (self.account.body == null or self.account.location == null) {
            return error.noAccountCreated;
        }
        self.order = try self.order.new(self.account.location.?, identifiers);
        self.authorization = try self.authorization.new(self.account.location.?, self.order.body.?.value.authorizations);
    }

    pub fn verfiyChallenge(self: *Acme, challenge: Challenge) !void {
        if (self.account.body == null or self.account.location == null) {
            return error.noAccountCreated;
        }
        self.challenge = try challenge.initiateChallenge(
            self.key_pair,
            self.http_client,
            self.nonce,
            self.directory.value,
            self.allocator,
            self.account.location.?,
        );
    }

    pub fn getAuthorization(self: *Acme) !void {
        self.authorization = try self.authorization.getAuthorization();
    }

    pub fn pollAuthorization(self: *Acme) !void {
        self.authorization = try self.authorization.pollAuthorization();
    }

    // for testing
    // todo: remove it
    pub fn authorize(self: *Acme, challenge: CHALLENGE) !Challenge {
        for (self.authorization.authorizations) |authz| {
            const chall = findChallenge(authz.value.challenges, challenge);
            var keyAuthz_buf: [1024]u8 = undefined;
            const key_authz = try chall.keyAuthorization(&keyAuthz_buf, self.key_pair);
            if (challenge == .ChallengeTypeHTTP01) {
                var http01_buf: [1024]u8 = undefined;
                const http01_path = try chall.http01ResourcePath(&http01_buf);
                std.debug.print("Path:{s}\n", .{http01_path});
                std.debug.print("Content:{s}\n", .{key_authz});
                return chall;
            }

            if (challenge == .ChallengeTypeDNS01) {
                var dns_name_buf: [1024]u8 = undefined;
                var dns_value_buf: [1024]u8 = undefined;
                const txt_record_name = try chall.dns01TXTRecordName(&dns_name_buf, authz.value.identifier.value);
                const txt_record_value = chall.dns01TXTRecordValue(&dns_value_buf, key_authz);
                std.debug.print("TXT Record Name: {s}\n", .{txt_record_name});
                std.debug.print("TXT Record Value: {s}\n", .{txt_record_value});
                return chall;
            }
            return error.UnsupportChallenge;
        }
        return error.UnsupportChallenge;
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

fn getCAUrl(ca: CA) []const u8 {
    return switch (ca) {
        .LetsEncryptProductionCA => "https://acme-staging-v02.api.letsencrypt.org/directory",
    };
}
