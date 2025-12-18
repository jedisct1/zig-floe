# zig-floe

A Zig implementation of FLOE (Fast Lightweight Online Encryption), a streaming authenticated encryption scheme designed by Snowflake.

## What is FLOE?

FLOE is a segment-based encryption scheme that lets you encrypt and decrypt large files with constant memory usage. Unlike traditional authenticated encryption that requires loading the entire file into memory, FLOE processes data in fixed-size segments while maintaining full authentication guarantees.

Key properties:

- Bounded memory: Process files of any size with fixed memory footprint
- Streaming: Encrypt/decrypt data as it arrives, no need to buffer everything
- Authenticated: Tampered or truncated data is detected and rejected
- Key commitment: The header cryptographically binds the key to the ciphertext
- FIPS-compatible: Uses only AES-GCM-256 and HMAC-SHA384

## Installation

Requires Zig 0.15.1 or later.

Add the dependency using `zig fetch`:

```sh
zig fetch --save git+https://github.com/jedisct1/zig-floe
```

Then in your `build.zig`:

```zig
const floe = b.dependency("floe", .{});
exe.root_module.addImport("floe", floe.module("zig_floe"));
```

Or just copy `src/root.zig` into your project.

## Quick Start

### Encrypting a small message

```zig
const std = @import("std");
const floe = @import("floe");
const Floe = floe.Aes256GcmSha384;

pub fn main() !void {
    // 32-byte encryption key (use crypto.random.bytes in production)
    const key: [Floe.key_length]u8 = @splat(0);

    // Associated data - authenticated but not encrypted
    const associated_data = "user-id:12345";

    // Use 4KB segments (good for small-medium files)
    const params = Floe.Params.gcm256_iv256_4k;

    // Create encryptor
    var encryptor = try Floe.Encryptor.init(params, key, associated_data);

    // Get header (must be sent/stored before ciphertext)
    const header = encryptor.get_header();

    // Encrypt the message
    const plaintext = "Hello, FLOE!";
    var ciphertext: [params.encrypted_segment_length]u8 = undefined;
    const ct_len = try encryptor.encrypt_last_segment(plaintext, &ciphertext);

    // Now header[0..header.len] and ciphertext[0..ct_len] can be transmitted/stored
    _ = header;
    _ = ct_len;
}
```

### Decrypting a message

```zig
const std = @import("std");
const floe = @import("floe");
const Floe = floe.Aes256GcmSha384;

pub fn decrypt(header: []const u8, ciphertext: []const u8) ![]const u8 {
    const key: [Floe.key_length]u8 = @splat(0);
    const associated_data = "user-id:12345";
    const params = Floe.Params.gcm256_iv256_4k;

    // Create decryptor (validates header tag)
    var decryptor = try Floe.Decryptor.init(params, key, associated_data, header);

    // Decrypt
    var plaintext: [params.plaintext_segment_length()]u8 = undefined;
    const pt_len = try decryptor.decrypt_last_segment(ciphertext, &plaintext);

    return plaintext[0..pt_len];
}
```

### Streaming encryption of large data

For data larger than one segment, encrypt in chunks:

```zig
const std = @import("std");
const floe = @import("floe");
const Floe = floe.Aes256GcmSha384;

pub fn encrypt_file(reader: anytype, writer: anytype) !void {
    const key: [Floe.key_length]u8 = @splat(0);
    const params = Floe.Params.gcm256_iv256_1m; // 1MB segments for large files

    var encryptor = try Floe.Encryptor.init(params, key, "");

    // Write header first
    try writer.writeAll(encryptor.get_header());

    const pt_seg_len = params.plaintext_segment_length();
    var plaintext_buf: [1024 * 1024]u8 = undefined; // Must match segment size
    var ciphertext_buf: [params.encrypted_segment_length]u8 = undefined;

    while (true) {
        const bytes_read = try reader.readAll(plaintext_buf[0..pt_seg_len]);

        if (bytes_read < pt_seg_len) {
            // Last segment (can be any size from 0 to pt_seg_len)
            const ct_len = try encryptor.encrypt_last_segment(
                plaintext_buf[0..bytes_read],
                &ciphertext_buf,
            );
            try writer.writeAll(ciphertext_buf[0..ct_len]);
            break;
        } else {
            // Full segment
            const ct_len = try encryptor.encrypt_segment(
                plaintext_buf[0..pt_seg_len],
                &ciphertext_buf,
            );
            try writer.writeAll(ciphertext_buf[0..ct_len]);
        }
    }
}
```

### Streaming decryption

```zig
const std = @import("std");
const floe = @import("floe");
const Floe = floe.Aes256GcmSha384;

pub fn decrypt_file(reader: anytype, writer: anytype) !void {
    const key: [Floe.key_length]u8 = @splat(0);
    const params = Floe.Params.gcm256_iv256_1m;

    // Read header
    var header: [params.header_length()]u8 = undefined;
    try reader.readNoEof(&header);

    var decryptor = try Floe.Decryptor.init(params, key, "", &header);

    const enc_seg_len = params.encrypted_segment_length;
    var ciphertext_buf: [enc_seg_len]u8 = undefined;
    var plaintext_buf: [params.plaintext_segment_length()]u8 = undefined;

    while (!decryptor.is_closed()) {
        const bytes_read = try reader.readAll(&ciphertext_buf);

        if (bytes_read == 0) {
            return error.UnexpectedEndOfFile;
        }

        // decrypt_segment auto-detects the last segment by checking the length prefix
        const pt_len = try decryptor.decrypt_segment(
            ciphertext_buf[0..bytes_read],
            &plaintext_buf,
        );
        try writer.writeAll(plaintext_buf[0..pt_len]);
    }
}
```

## Ciphertext Format

FLOE ciphertext consists of:

1. Header (74 bytes with default IV):
   - 10 bytes: Encoded parameters
   - 32 bytes: Random IV
   - 32 bytes: Header tag (key commitment)

2. Segments (one or more):
   - 4 bytes: Length prefix (`0xFFFFFFFF` for internal segments, actual length for final)
   - 12 bytes: Random nonce
   - Variable: Ciphertext (same length as plaintext)
   - 16 bytes: Authentication tag

Overhead per segment: 32 bytes (4 + 12 + 16)

## Choosing Segment Size

| Segment Size | Use Case                             | Memory per Segment |
| ------------ | ------------------------------------ | ------------------ |
| 4 KB         | Small files, low-memory environments | ~8 KB              |
| 64 KB        | General purpose                      | ~130 KB            |
| 1 MB         | Large files, high-throughput         | ~2 MB              |

Smaller segments = less memory, more overhead. Larger segments = more memory, better throughput.
