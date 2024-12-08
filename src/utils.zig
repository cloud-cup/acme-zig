const std = @import("std");

pub fn getHeader(response: std.http.Client.Response, key: []const u8) ![]const u8 {
    var iter = response.iterateHeaders();
    while (iter.next()) |header| {
        if (std.mem.eql(u8, key, header.name)) {
            return header.value;
        }
    }
    return error.HeaderNotFound;
}
