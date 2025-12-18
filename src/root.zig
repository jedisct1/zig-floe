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
        const nonce_length = Aead.Cipher.nonce_length;
        const tag_length = Aead.Cipher.tag_length;
        const overhead = nonce_length + tag_length + segment_length_prefix_length;

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
const F = Aes256GcmSha384;

test "params encoding" {
    const params_4k = F.Params.gcm256_iv256_4k;
    const encoded = params_4k.encode();
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x20 }, &encoded);

    const params_1m = F.Params.gcm256_iv256_1m;
    const encoded_1m = params_1m.encode();
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20 }, &encoded_1m);
}

test "plaintext segment length" {
    const params = F.Params.gcm256_iv256_4k;
    try testing.expectEqual(@as(usize, 4064), params.plaintext_segment_length());
}

test "round trip single segment" {
    const params = F.Params.gcm256_iv256_4k;
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "test aad";

    var encryptor = try F.Encryptor.init(params, key, ad);
    const header = encryptor.get_header();

    const plaintext = "Hello, FLOE!";
    var ciphertext: [params.encrypted_segment_length]u8 = undefined;
    const ct_len = try encryptor.encrypt_last_segment(plaintext, &ciphertext);

    var decryptor = try F.Decryptor.init(params, key, ad, header);

    var decrypted: [params.plaintext_segment_length()]u8 = undefined;
    const pt_len = try decryptor.decrypt_last_segment(ciphertext[0..ct_len], &decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
    try testing.expect(encryptor.is_closed());
    try testing.expect(decryptor.is_closed());
}

test "round trip multiple segments" {
    const params = F.Params{ .encrypted_segment_length = 64 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    const pt_seg_len = comptime params.plaintext_segment_length();

    var plaintext: [pt_seg_len * 2 + 10]u8 = undefined;
    for (&plaintext, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var encryptor = try F.Encryptor.init(params, key, ad);
    const header = encryptor.get_header();

    const enc_seg_len = params.encrypted_segment_length;
    var ciphertext: [enc_seg_len * 3]u8 = undefined;
    var ct_offset: usize = 0;

    ct_offset += try encryptor.encrypt_segment(plaintext[0..pt_seg_len], ciphertext[ct_offset..]);
    ct_offset += try encryptor.encrypt_segment(plaintext[pt_seg_len..][0..pt_seg_len], ciphertext[ct_offset..]);
    ct_offset += try encryptor.encrypt_last_segment(plaintext[pt_seg_len * 2 ..], ciphertext[ct_offset..]);

    var decryptor = try F.Decryptor.init(params, key, ad, header);
    var decrypted: [plaintext.len]u8 = undefined;
    var pt_offset: usize = 0;

    pt_offset += try decryptor.decrypt_segment(ciphertext[0..enc_seg_len], decrypted[pt_offset..]);
    pt_offset += try decryptor.decrypt_segment(ciphertext[enc_seg_len..][0..enc_seg_len], decrypted[pt_offset..]);
    const last_ct_start = enc_seg_len * 2;
    pt_offset += try decryptor.decrypt_last_segment(ciphertext[last_ct_start..ct_offset], decrypted[pt_offset..]);

    try testing.expectEqualSlices(u8, &plaintext, decrypted[0..pt_offset]);
}

test "empty plaintext" {
    const params = F.Params.gcm256_iv256_4k;
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "";

    var encryptor = try F.Encryptor.init(params, key, ad);
    const header = encryptor.get_header();

    var ciphertext: [params.encrypted_segment_length]u8 = undefined;
    const ct_len = try encryptor.encrypt_last_segment("", &ciphertext);

    var decryptor = try F.Decryptor.init(params, key, ad, header);
    var decrypted: [params.plaintext_segment_length()]u8 = undefined;
    const pt_len = try decryptor.decrypt_last_segment(ciphertext[0..ct_len], &decrypted);

    try testing.expectEqual(@as(usize, 0), pt_len);
}

test "invalid header tag" {
    const params = F.Params.gcm256_iv256_4k;
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const wrong_key: [F.key_length]u8 = [_]u8{1} ** F.key_length;
    const ad = "test";

    var encryptor = try F.Encryptor.init(params, key, ad);
    const header = encryptor.get_header();

    const result = F.Decryptor.init(params, wrong_key, ad, header);
    try testing.expectError(Error.InvalidHeaderTag, result);
}

test "segment authentication failure" {
    const params = F.Params.gcm256_iv256_4k;
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "test";

    var encryptor = try F.Encryptor.init(params, key, ad);
    const header = encryptor.get_header();

    var ciphertext: [params.encrypted_segment_length]u8 = undefined;
    const ct_len = try encryptor.encrypt_last_segment("Hello", &ciphertext);

    ciphertext[20] ^= 0xFF;

    var decryptor = try F.Decryptor.init(params, key, ad, header);
    var decrypted: [params.plaintext_segment_length()]u8 = undefined;
    const result = decryptor.decrypt_last_segment(ciphertext[0..ct_len], &decrypted);
    try testing.expectError(Error.AuthenticationFailed, result);
}

fn hex_decode(comptime hex: []const u8) [hex.len / 2]u8 {
    @setEvalBranchQuota(hex.len * 100);
    var result: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, hex) catch unreachable;
    return result;
}

fn decrypt_kat(
    comptime params: F.Params,
    key: [F.key_length]u8,
    ad: []const u8,
    c: []const u8,
    expected_plaintext: []const u8,
) !void {
    const header_len = params.header_length();
    var decryptor = try F.Decryptor.init(params, key, ad, c[0..header_len]);

    var decrypted: [16384]u8 = undefined;
    var pt_offset: usize = 0;
    var ct_offset: usize = header_len;

    const enc_seg_len = params.encrypted_segment_length;

    while (ct_offset < c.len) {
        const remaining = c.len - ct_offset;
        if (remaining <= enc_seg_len) {
            const pt_len = try decryptor.decrypt_last_segment(c[ct_offset..], decrypted[pt_offset..]);
            pt_offset += pt_len;
            break;
        } else {
            const pt_len = try decryptor.decrypt_segment(c[ct_offset..][0..enc_seg_len], decrypted[pt_offset..]);
            pt_offset += pt_len;
            ct_offset += enc_seg_len;
        }
    }

    try testing.expectEqualSlices(u8, expected_plaintext, decrypted[0..pt_offset]);
    try testing.expect(decryptor.is_closed());
}

test "KAT: GCM256_IV256_64" {
    const params = F.Params{ .encrypted_segment_length = 64 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    const m = hex_decode("b7f54726b914b689881ab315b032a633b452c1c59a43f430c1cc00a39d1a5eb4773dbc6b5f26255e0d3714694c9c9ffbfa8adb998aecbb0601a4cade83764b8b13ccaa");
    const c = hex_decode("00000000004000000020b57c157a4855bdb2500cf55af49648e0fea0bfbac93407bc6b4fca9c471b018f869339a3eccec33fe43c2e124caadbf083e53390f9b2f1cd5d612cd50f2592affffffffff10bc888c8e6f0c6308feb9143a161347a94ac632e2381acb5f2fca4b554bc0a2eb47bfea26edda9ec26298b797ebda8571cb28e1d9ccb59687c2e78ffffffff829f847d58257efdd08766aebb6ada17795c39605acbc683928f2e7e822916147be7af0aa19f1d7e32b3d9038ee437dc566cf8980df2b85e9037a19d000000236ddde6266ddd8519ccb76228f4929eca37ca5c2df92a1b2004d615f191ad7d");

    try decrypt_kat(params, key, ad, &c, &m);
}

test "KAT: GCM256_IV256_64 2" {
    const params = F.Params{ .encrypted_segment_length = 64 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    const m = hex_decode("060704a0818fd875cdcd46c1a0f04c256a4d82f92b2d84b4db172e8e816a2caeb895102aa8f21d4cdd5a076bf66c179729b0de8cbf4adce527bc9d0042da3b78c101401ce078b1419c08167df00aecf21588e179ca7e340e8080ed6c3eea03b6d78007fc25994758c355b82b415092f15f79a49473d9f5a3e9f74ea099b897b1b5cb8b");
    const c = hex_decode("000000000040000000201a07d077d2a8a5440beb942a1f9de0c7bbe37703a3534ef6c5df8a07fa435c91be615d25a403b2c509af546c74d6d4f9f4a77c7705b10618eb88f0bfb2437f6cffffffff01274defbffdd8af94328d2986504b084e0a8376cef4222ab2510f67ddc540ccb1b868a2d16b107689a44504cb1e4d0184ad30aeb54a1e1249e8cd33ffffffff985053251020b53fb281b58e5dbe47dac42d75120439b17b9e76b2d35116a8aca15b0d234d9447141d697f47058bdf3be07d9903b6f8b92ba0b523a5ffffffff0847ca28d5904b3d0d697890a36c5f46ada10a7cb85194808424948e0391459be072a2db0c18403cef2d0a276a5440410c8fb11b554764eff1f5f956ffffffff87fa4535fed0721460160ada080fc574641fdf6ea4216ce5510c1eca0749e30a28e74763ee8495f65350851f8badb9e9e04a40b29efe41972f16b15300000023b42ad157c2a14839fa5715e1320ecc03d9de26942829633521bce691be01f7");

    try decrypt_kat(params, key, ad, &c, &m);
}

test "single segment small params" {
    const params = F.Params{ .encrypted_segment_length = 40 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    var encryptor = try F.Encryptor.init(params, key, ad);
    const header = encryptor.get_header();

    const plaintext = "test123";
    var ciphertext: [params.encrypted_segment_length]u8 = undefined;
    const ct_len = try encryptor.encrypt_last_segment(plaintext, &ciphertext);

    var decryptor = try F.Decryptor.init(params, key, ad, header);
    var decrypted: [params.plaintext_segment_length()]u8 = undefined;
    const pt_len = try decryptor.decrypt_last_segment(ciphertext[0..ct_len], &decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}

test "single segment with rotation params" {
    const params = F.Params{ .encrypted_segment_length = 40, .override_rotation_mask = 2 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    var encryptor = try F.Encryptor.init(params, key, ad);
    const header = encryptor.get_header();

    const plaintext = "test123";
    var ciphertext: [params.encrypted_segment_length]u8 = undefined;
    const ct_len = try encryptor.encrypt_last_segment(plaintext, &ciphertext);

    var decryptor = try F.Decryptor.init(params, key, ad, header);
    var decrypted: [params.plaintext_segment_length()]u8 = undefined;
    const pt_len = try decryptor.decrypt_last_segment(ciphertext[0..ct_len], &decrypted);

    try testing.expectEqualSlices(u8, plaintext, decrypted[0..pt_len]);
}

test "two segments with rotation params" {
    const params = F.Params{ .encrypted_segment_length = 40, .override_rotation_mask = 2 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    const pt_seg_len = comptime params.plaintext_segment_length();
    const enc_seg_len = params.encrypted_segment_length;

    var plaintext: [pt_seg_len + 3]u8 = undefined;
    for (&plaintext, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var encryptor = try F.Encryptor.init(params, key, ad);
    const header = encryptor.get_header();

    var ciphertext: [enc_seg_len * 2]u8 = undefined;
    var ct_offset: usize = 0;

    ct_offset += try encryptor.encrypt_segment(plaintext[0..pt_seg_len], ciphertext[ct_offset..]);
    ct_offset += try encryptor.encrypt_last_segment(plaintext[pt_seg_len..], ciphertext[ct_offset..]);

    var decryptor = try F.Decryptor.init(params, key, ad, header);
    var decrypted: [plaintext.len]u8 = undefined;
    var pt_offset: usize = 0;

    pt_offset += try decryptor.decrypt_segment(ciphertext[0..enc_seg_len], decrypted[pt_offset..]);
    pt_offset += try decryptor.decrypt_last_segment(ciphertext[enc_seg_len..ct_offset], decrypted[pt_offset..]);

    try testing.expectEqualSlices(u8, &plaintext, decrypted[0..pt_offset]);
}

test "segments crossing rotation boundary" {
    const params = F.Params{ .encrypted_segment_length = 40, .override_rotation_mask = 2 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    const pt_seg_len = comptime params.plaintext_segment_length();
    const enc_seg_len = params.encrypted_segment_length;

    var plaintext: [pt_seg_len * 4 + 3]u8 = undefined;
    for (&plaintext, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var encryptor = try F.Encryptor.init(params, key, ad);
    const header = encryptor.get_header();

    var ciphertext: [enc_seg_len * 5]u8 = undefined;
    var ct_offset: usize = 0;

    inline for (0..4) |seg| {
        ct_offset += try encryptor.encrypt_segment(plaintext[seg * pt_seg_len ..][0..pt_seg_len], ciphertext[ct_offset..]);
    }
    ct_offset += try encryptor.encrypt_last_segment(plaintext[4 * pt_seg_len ..], ciphertext[ct_offset..]);

    var decryptor = try F.Decryptor.init(params, key, ad, header);
    var decrypted: [plaintext.len]u8 = undefined;
    var pt_offset: usize = 0;

    inline for (0..4) |seg| {
        pt_offset += try decryptor.decrypt_segment(ciphertext[seg * enc_seg_len ..][0..enc_seg_len], decrypted[pt_offset..]);
    }
    pt_offset += try decryptor.decrypt_last_segment(ciphertext[4 * enc_seg_len .. ct_offset], decrypted[pt_offset..]);

    try testing.expectEqualSlices(u8, &plaintext, decrypted[0..pt_offset]);
}

test "KAT: rotation" {
    const params = F.Params{ .encrypted_segment_length = 40, .override_rotation_mask = 2 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    const m = hex_decode("baec5a3d05e96837d3672de18881ddf7454528cf2c8e604dc09e5e08c3233bba59f8c0359db60547ef988903e36bcc80dce0f693c04c757a664e030246b15bccf6309663d5264d22654b0f86616d6c4c6611fa");
    const c = hex_decode("00000000002800000020610a063caa02c2dc556e770a48209279c8e50c9ed036c75318c4d49ac3f56c42fca17e47d1c4ff0a3ffdb011c09edf1a23d939f8bd9fe75f3855136049c63cacfffffffffcef546df28fc7832bb0a54d1cd3d7441134dc55d2626273a66b6049d5f9b7513f5ee67dfffffffff63eecd7ca42bc1fbddc08ded336741aba7eb620787e940b510d3bedb88026de49a15e2affffffff480fe016d8a3d3ce5001cbae97a24a39afba66575728fce3d1bc764aae2e6725adfa7c8dffffffffa595b5f465389875ad0e2819f9d77302de4a9f21d5479f3d618b5f94c83d61ca173a56faffffffffc8a81a1686ee058082ce79da0b749fb598fcb94eff598f45935f3c7401ddc89d4d10a686ffffffffe8c16f5df03c2de4fbbf6148865af82f8fd0a997211d332671ba5bd5fe52192deb913210ffffffff8772fe21691f21c16316d39f1434c568aa5e7f907723079d18abc7e9badc7704031aa4acffffffff53617a2d9306fe824c7eebd6f4bd4f14ce53821b9cfd5bd18c26d72e528219a1f4f21df1ffffffff08aea31e3dbf99daf7641702522e66892d8e6ad4feb966285cdfe2cdbcb9408f27ccf0fdffffffff8233aa972c0ea26937e93d66be01ccd001ce5a418ab97feeac6660cbef42c9cb51e9247300000023c10574a601b813286915cb7cbe536c736be345830006e66e79ba4cde058e58");

    try decrypt_kat(params, key, ad, &c, &m);
}

test "KAT: rotation2" {
    const params = F.Params{ .encrypted_segment_length = 40, .override_rotation_mask = 2 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    const m = hex_decode("1c79058d26a13b0cac41256ca000c75b8938f2378c76e2d01308d9a9e2240ea4d30086565a748049fa45efcbdaf51c317f3f403747b09f856e4e516624906a347a2bae2a5079576eb340ac4367611439c40d54");
    const c = hex_decode("00000000002800000020bcff1ac58da5913ecd816a609cd111829060413f4e6fc975fcd7924865bf57e8ce413a9820327c6cb03a613b9208bdcb8941c3b9ed7698a47cbf540ff20dbe7effffffff1d46a3b8256de57fd4cc768c57f1eb0d04daff23edf52629979c06e55a8c3a188252d159ffffffff122818aa0f01912d473e414ca6b16009cdcf437802aa7f7abcc6aa0e0567b55027f26fc2ffffffff7b3c05915ff86d433f96fe003e0874666c0691cbdf827702927f46d072bf40e82e0c1d01ffffffff138c8a17e461985bbd1952fc8fcdf0470ab8bc3dfef8413e7fef8e18e592c7697a2814c7ffffffff1851eb4596328bb46f8e1f51a8079590fef03a2dd36175ead47fc2de8d3d7eb2c24e829cffffffff2a0b2ea2edb81889b8ba78cea4a1090ba759de7e2ed660e01530729f5e2e8a39fe34435effffffff5681b49f7e01cc19aeec4858e607443239b2e7ade1f8beeb8833a9640fa0a9d3f8a5617effffffff5517335d118b8c5fd8b7e1a45ca801338778dd451ff2175b168f77d8deeac011a12cfcd4ffffffff38fd26287078599380825bc5e6a58c232147603721a76475b3b110dbb7e9a53ef815468effffffff905ea3ae3074a8f1548185dd9bf11ced3cd3bce3e0c0e5f1d331136da1db68874a99a0e500000023f83701a68fb679ad1d8fd4c3b9721bd8df4f1c6acd466a4b110a6f7a90b8b0");

    try decrypt_kat(params, key, ad, &c, &m);
}

test "KAT: rotation3" {
    const params = F.Params{ .encrypted_segment_length = 40, .override_rotation_mask = 2 };
    const key: [F.key_length]u8 = [_]u8{0} ** F.key_length;
    const ad = "This is AAD";

    const m = hex_decode("71444e9093e66a14af70396e5446ce0e987f5477759627a0f45f36a9d811c6bcb1c07243e3ed2294657fdf9270775fcfe7d3dc6b529d99aa12969556fed5226a35cb54c8ebff2fef7721c81ab732e65ffdba4e");
    const c = hex_decode("00000000002800000020e8ea6a4346648779d21a18109d5671afbac8cd123d7b9b5aafaac1c05d399c8278038be78c77a6adad7361d73983254ea4e2f32fc37ab97e25d10ac4ae53a704ffffffffb43da3e3d1543d9676220e71baba14622ff32acec1c06abeb05e0aa1b7bdf78bfb6c2b1fffffffffb99d1f34291aa2d18b92b22a0a989fa976de41180961c4e73dcd108f02ba8c257966d972ffffffffbd16ee95bf046568723647c65a9a40e61fa3ee71556df75000a83e73f224aa6a6d78efaeffffffff8c9d9a60c44d735ab76c1aa1e00b58668d42c916e5bb230ac0ebfbe957cf94881173dd88ffffffff25e0927e8a44cdcd4e82b14ce7a3c844a750fea545f8d30ecf8c61f063a7e43658c0f507ffffffff198ef8cbb7b30f32bac492a88abf1d569f84b683ec403a68ca932c436c275bb904f514baffffffffa7c7dbe1fae9a2a317e1370c00553d9e5a44ba6c3770e055065e50ace6d1386005cbfd33ffffffff7c9e12e5b4ca3e60c7f25f363ad39f40d2595875db378a97ca846e359e85503af4ff8da8ffffffff6fce493dae4e39f011d0880fca124bd5b0939c31cf434af9736e646a227e05be55d4ac11ffffffffdffab8054c39eb056a87df19c4d5caee8f7e2914c93e097ea5be753be5fbebf27cbf0ff10000002393f12b4662fd40164b135df9317bfdd177acc439f10a0c5e4de0365d029ff9");

    try decrypt_kat(params, key, ad, &c, &m);
}
