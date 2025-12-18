const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const assert = std.debug.assert;

/// FLOE encryption using AES-256-GCM for authenticated encryption and SHA-384 for key derivation.
/// This is the recommended configuration for most use cases.
pub const Aes256GcmSha384 = Floe(AeadConfigs.Aes256Gcm, HashConfigs.Sha384);

/// Errors that can occur during FLOE encryption/decryption operations.
pub const Error = error{
    InvalidKeyLength,
    InvalidHeaderLength,
    InvalidHeaderParams,
    InvalidHeaderTag,
    InvalidSegmentLength,
    InvalidPlaintextLength,
    InvalidSegmentPrefix,
    Closed,
    CounterOverflow,
    SegmentLengthTooSmall,
} || crypto.errors.AuthenticationError;

const AeadConfigs = struct {
    const Aes256Gcm = struct {
        pub const Cipher = crypto.aead.aes_gcm.Aes256Gcm;
        pub const id: u8 = 0;
        pub const rotation_mask_bits: u6 = 20;
        pub const max_segments: u64 = 1 << 40;
    };
};

const HashConfigs = struct {
    const Sha384 = struct {
        pub const Hmac = crypto.auth.hmac.sha2.HmacSha384;
        pub const id: u8 = 0;
    };
};

const segment_length_prefix_length = 4;
const internal_segment_marker: u32 = 0xFFFFFFFF;

fn Floe(comptime Aead: type, comptime Hash: type) type {
    return struct {
        /// Length of the encryption key in bytes (32 for AES-256).
        pub const key_length = Aead.Cipher.key_length;
        /// Nonce length
        pub const nonce_length = Aead.Cipher.nonce_length;
        /// Tag length
        pub const tag_length = Aead.Cipher.tag_length;
        /// Overhead per encrypted segment: nonce + tag + length prefix
        pub const overhead = nonce_length + tag_length + segment_length_prefix_length;

        /// Configuration parameters for FLOE encryption.
        pub const Params = struct {
            /// Size of each encrypted segment in bytes, including overhead (nonce + tag + length prefix).
            /// Must be at least 33 bytes to accommodate the 32-byte overhead plus 1 byte of plaintext.
            encrypted_segment_length: u32,
            /// Length of the initialization vector in bytes. Default is 32.
            iv_length: u32 = default_iv_length,
            /// Optional override for the key rotation mask. When set, keys rotate every 2^N segments
            /// where N is this value. Default uses the cipher's rotation_mask_bits (20 for AES-GCM).
            override_rotation_mask: ?u6 = null,

            const encoded_length = 10;
            const default_iv_length = 32;
            const header_tag_length = 32;

            /// Preset: 4KB segments with 256-bit IV. Good for small to medium files.
            pub const gcm256_iv256_4k: Params = .{ .encrypted_segment_length = 4 * 1024 };
            /// Preset: 1MB segments with 256-bit IV. Better throughput for large files.
            pub const gcm256_iv256_1m: Params = .{ .encrypted_segment_length = 1024 * 1024 };

            /// Returns the maximum plaintext size that fits in one segment.
            pub fn plaintext_segment_length(self: Params) usize {
                return self.encrypted_segment_length - overhead;
            }

            /// Returns the size of the header that must be transmitted before encrypted segments.
            pub fn header_length(self: Params) usize {
                return encoded_length + self.iv_length + header_tag_length;
            }

            fn get_rotation_mask(self: Params) u64 {
                const bits = self.override_rotation_mask orelse Aead.rotation_mask_bits;
                return ~((@as(u64, 1) << bits) - 1);
            }

            fn encode(self: Params) [encoded_length]u8 {
                var result: [encoded_length]u8 = undefined;
                result[0] = Aead.id;
                result[1] = Hash.id;
                mem.writeInt(u32, result[2..6], self.encrypted_segment_length, .big);
                mem.writeInt(u32, result[6..10], self.iv_length, .big);
                return result;
            }

            fn validate(self: Params) Error!void {
                if (self.encrypted_segment_length < overhead + 1) {
                    return Error.SegmentLengthTooSmall;
                }
            }
        };

        fn hkdf_expand(out: []u8, prk: []const u8, info_parts: []const []const u8) void {
            assert(out.len <= Hash.Hmac.mac_length * 255);
            var i: usize = 0;
            var counter: u8 = 1;
            var prev: [Hash.Hmac.mac_length]u8 = undefined;

            while (i < out.len) : (i += Hash.Hmac.mac_length) {
                var hmac = Hash.Hmac.init(prk);
                if (counter > 1) hmac.update(&prev);
                for (info_parts) |part| hmac.update(part);
                hmac.update(&[_]u8{counter});
                hmac.final(&prev);

                const to_copy = @min(out.len - i, Hash.Hmac.mac_length);
                @memcpy(out[i..][0..to_copy], prev[0..to_copy]);
                counter +%= 1;
            }
        }

        fn floe_kdf(out: []u8, key: []const u8, params: Params, iv: []const u8, ad: []const u8, purpose: []const u8) void {
            const encoded = params.encode();
            hkdf_expand(out, key, &.{ &encoded, iv, purpose, ad });
        }

        fn derive_segment_key(key: []const u8, params: Params, iv: []const u8, ad: []const u8, masked: u64) [key_length]u8 {
            var purpose: [12]u8 = "DEK:????????".*;
            mem.writeInt(u64, purpose[4..12], masked, .big);
            var dek: [key_length]u8 = undefined;
            floe_kdf(&dek, key, params, iv, ad, &purpose);
            return dek;
        }

        const State = struct {
            params: Params,
            message_key: [Hash.Hmac.mac_length]u8,
            iv: [Params.default_iv_length]u8,
            ad: []const u8,
            counter: u64 = 0,
            closed: bool = false,
            cached_dek: [key_length]u8 = undefined,
            cached_masked: u64 = std.math.maxInt(u64),

            fn get_iv(self: *const State) []const u8 {
                return self.iv[0..self.params.iv_length];
            }

            fn ensure_key(self: *State) void {
                const masked = self.counter & self.params.get_rotation_mask();
                if (masked != self.cached_masked) {
                    self.cached_dek = derive_segment_key(&self.message_key, self.params, self.get_iv(), self.ad, masked);
                    self.cached_masked = masked;
                }
            }

            fn make_segment_ad(self: *const State, is_last: bool) [9]u8 {
                var ad: [9]u8 = undefined;
                mem.writeInt(u64, ad[0..8], self.counter, .big);
                ad[8] = if (is_last) 0x01 else 0x00;
                return ad;
            }
        };

        /// Streaming encryptor for FLOE. Encrypts data segment by segment with bounded memory usage.
        ///
        /// Usage:
        /// 1. Create with `init()`
        /// 2. Send `get_header()` to the recipient
        /// 3. Call `encrypt_segment()` for each full-size plaintext chunk
        /// 4. Call `encrypt_last_segment()` for the final chunk (can be smaller)
        pub const Encryptor = struct {
            state: State,
            header: [Params.encoded_length + Params.default_iv_length + Params.header_tag_length]u8,
            header_len: usize,

            /// Creates a new encryptor with the given parameters, key, and associated data.
            /// The associated data is authenticated but not encrypted.
            pub fn init(params: Params, key: [key_length]u8, ad: []const u8) Error!Encryptor {
                try params.validate();

                var self: Encryptor = .{
                    .state = .{ .params = params, .ad = ad, .message_key = undefined, .iv = undefined },
                    .header = undefined,
                    .header_len = params.header_length(),
                };
                crypto.random.bytes(&self.state.iv);
                const iv = self.state.get_iv();

                const encoded = params.encode();
                @memcpy(self.header[0..Params.encoded_length], &encoded);
                @memcpy(self.header[Params.encoded_length..][0..params.iv_length], iv);

                var header_tag: [Params.header_tag_length]u8 = undefined;
                floe_kdf(&header_tag, &key, params, iv, ad, "HEADER_TAG:");
                @memcpy(self.header[Params.encoded_length + params.iv_length ..][0..Params.header_tag_length], &header_tag);

                floe_kdf(&self.state.message_key, &key, params, iv, ad, "MESSAGE_KEY:");
                return self;
            }

            /// Returns the header bytes that must be sent before any encrypted segments.
            /// The header contains the IV and a key-commitment tag.
            pub fn get_header(self: *const Encryptor) []const u8 {
                return self.header[0..self.header_len];
            }

            fn encrypt_impl(self: *Encryptor, m: []const u8, out: []u8, is_last: bool) Error!usize {
                if (self.state.closed) return Error.Closed;

                const pt_seg_len = self.state.params.plaintext_segment_length();
                const out_len = if (is_last) overhead + m.len else self.state.params.encrypted_segment_length;

                if (is_last) {
                    if (m.len > pt_seg_len) return Error.InvalidPlaintextLength;
                } else {
                    if (m.len != pt_seg_len) return Error.InvalidPlaintextLength;
                    if (self.state.counter >= Aead.max_segments - 1) return Error.CounterOverflow;
                }
                if (out.len < out_len) return Error.InvalidSegmentLength;

                self.state.ensure_key();

                var nonce: [nonce_length]u8 = undefined;
                crypto.random.bytes(&nonce);
                const segment_ad = self.state.make_segment_ad(is_last);

                mem.writeInt(u32, out[0..4], if (is_last) @intCast(out_len) else internal_segment_marker, .big);
                @memcpy(out[4..][0..nonce_length], &nonce);

                var tag: [tag_length]u8 = undefined;
                Aead.Cipher.encrypt(out[segment_length_prefix_length + nonce_length ..][0..m.len], &tag, m, &segment_ad, nonce, self.state.cached_dek);
                @memcpy(out[segment_length_prefix_length + nonce_length + m.len ..][0..tag_length], &tag);

                self.state.counter += 1;
                if (is_last) self.state.closed = true;
                return out_len;
            }

            /// Encrypts a full plaintext segment. The plaintext must be exactly `params.plaintext_segment_length()` bytes.
            /// Returns the number of bytes written to `out` (always `params.encrypted_segment_length`).
            pub fn encrypt_segment(self: *Encryptor, m: []const u8, out: []u8) Error!usize {
                return self.encrypt_impl(m, out, false);
            }

            /// Encrypts the final segment. The plaintext can be 0 to `params.plaintext_segment_length()` bytes.
            /// After calling this, the encryptor is closed and cannot encrypt more data.
            /// Returns the number of bytes written to `out`.
            pub fn encrypt_last_segment(self: *Encryptor, m: []const u8, out: []u8) Error!usize {
                return self.encrypt_impl(m, out, true);
            }

            /// Returns true if `encrypt_last_segment` has been called.
            pub fn is_closed(self: *const Encryptor) bool {
                return self.state.closed;
            }
        };

        /// Streaming decryptor for FLOE. Decrypts data segment by segment with bounded memory usage.
        ///
        /// Usage:
        /// 1. Create with `init()`, passing the header received from the encryptor
        /// 2. Call `decrypt_segment()` for each ciphertext segment (auto-detects the last segment)
        ///    OR call `decrypt_last_segment()` explicitly for the final segment
        pub const Decryptor = struct {
            state: State,

            /// Creates a new decryptor with the given parameters, key, associated data, and header.
            /// Returns `InvalidHeaderTag` if the key or associated data don't match what was used for encryption.
            pub fn init(params: Params, key: [key_length]u8, ad: []const u8, header: []const u8) Error!Decryptor {
                try params.validate();
                if (header.len < params.header_length()) return Error.InvalidHeaderLength;

                const encoded = params.encode();
                if (!mem.eql(u8, header[0..Params.encoded_length], &encoded)) return Error.InvalidHeaderParams;

                var self: Decryptor = .{
                    .state = .{ .params = params, .ad = ad, .message_key = undefined, .iv = undefined },
                };
                @memcpy(self.state.iv[0..params.iv_length], header[Params.encoded_length..][0..params.iv_length]);
                const iv = self.state.get_iv();

                const received_tag = header[Params.encoded_length + params.iv_length ..][0..Params.header_tag_length];
                var expected_tag: [Params.header_tag_length]u8 = undefined;
                floe_kdf(&expected_tag, &key, params, iv, ad, "HEADER_TAG:");
                if (!crypto.timing_safe.eql([Params.header_tag_length]u8, received_tag.*, expected_tag)) {
                    return Error.InvalidHeaderTag;
                }

                floe_kdf(&self.state.message_key, &key, params, iv, ad, "MESSAGE_KEY:");
                return self;
            }

            fn decrypt_impl(self: *Decryptor, c: []const u8, out: []u8, is_last: bool) Error!usize {
                if (self.state.closed) return Error.Closed;

                const pt_len = if (is_last) c.len - overhead else self.state.params.plaintext_segment_length();

                if (is_last) {
                    if (c.len < overhead) return Error.InvalidSegmentLength;
                    if (c.len > self.state.params.encrypted_segment_length) return Error.InvalidSegmentLength;
                    if (mem.readInt(u32, c[0..4], .big) != c.len) return Error.InvalidSegmentPrefix;
                } else {
                    if (c.len != self.state.params.encrypted_segment_length) return Error.InvalidSegmentLength;
                    if (mem.readInt(u32, c[0..4], .big) != internal_segment_marker) return Error.InvalidSegmentPrefix;
                    if (self.state.counter >= Aead.max_segments - 1) return Error.CounterOverflow;
                }
                if (out.len < pt_len) return Error.InvalidSegmentLength;

                self.state.ensure_key();

                const nonce = c[4..][0..nonce_length].*;
                const segment_ad = self.state.make_segment_ad(is_last);
                const ciphertext = c[segment_length_prefix_length + nonce_length ..][0..pt_len];
                const tag = c[segment_length_prefix_length + nonce_length + pt_len ..][0..tag_length].*;

                Aead.Cipher.decrypt(out[0..pt_len], ciphertext, tag, &segment_ad, nonce, self.state.cached_dek) catch {
                    return Error.AuthenticationFailed;
                };

                self.state.counter += 1;
                if (is_last) self.state.closed = true;
                return pt_len;
            }

            /// Decrypts a ciphertext segment, auto-detecting whether it's the last segment.
            /// For internal segments, `c` must be exactly `params.encrypted_segment_length` bytes.
            /// Returns the number of plaintext bytes written to `out`.
            pub fn decrypt_segment(self: *Decryptor, c: []const u8, out: []u8) Error!usize {
                if (c.len == self.state.params.encrypted_segment_length and mem.readInt(u32, c[0..4], .big) == c.len) {
                    return self.decrypt_impl(c, out, true);
                }
                return self.decrypt_impl(c, out, false);
            }

            /// Explicitly decrypts the final segment. Use this when you know this is the last segment.
            /// After calling this, the decryptor is closed.
            /// Returns the number of plaintext bytes written to `out`.
            pub fn decrypt_last_segment(self: *Decryptor, c: []const u8, out: []u8) Error!usize {
                return self.decrypt_impl(c, out, true);
            }

            /// Returns true if the last segment has been decrypted.
            pub fn is_closed(self: *const Decryptor) bool {
                return self.state.closed;
            }
        };
    };
}

const testing = std.testing;

test "params encoding" {
    const F = Aes256GcmSha384;
    const params_4k = F.Params.gcm256_iv256_4k;
    const encoded = params_4k.encode();
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x20 }, &encoded);

    const params_1m = F.Params.gcm256_iv256_1m;
    const encoded_1m = params_1m.encode();
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20 }, &encoded_1m);
}

test {
    _ = @import("tests.zig");
}
