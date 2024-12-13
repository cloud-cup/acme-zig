const std = @import("std");
const jwk = @import("jwk.zig");
const utils = @import("utils.zig");
const Directory = @import("directory.zig").Directory;
const Nonce = @import("nonce.zig").Nonce;
const Account = @import("account.zig").Account;
const Order = @import("order.zig").Order;
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

pub const AuthorizationOption = struct {
    challenge: CHALLENGE = .ChallengeTypeDNS01,
    type: enum {
        one_time,
        poll,
    } = .one_time,
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
    }

    pub fn getNonce(self: Acme) ![]u8 {
        return try self.nonce.get(self.http_client, self.directory.value.newNonce);
    }

    pub fn newAccount(self: *Acme, emails: []const []const u8) !void {
        self.account = try self.account.new(emails);
    }

    pub fn newOrder(self: *Acme, identifiers: []const []const u8, authorzOption: AuthorizationOption) !void {
        if (self.account.body == null or self.account.location == null) {
            return error.noAccountCreated;
        }
        self.order = try self.order.new(self.account.location.?, identifiers);
        self.authorization = try self.authorization.new(self.account.location.?, self.order.body.?.value.authorizations, authorzOption);
    }
};

fn getCAUrl(ca: CA) []const u8 {
    return switch (ca) {
        .LetsEncryptProductionCA => "https://acme-staging-v02.api.letsencrypt.org/directory",
    };
}
