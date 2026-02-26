//! Hex encoding and decoding utilities.
//!
//! All operations work on fixed-size stack buffers — no heap allocation.

/// Decode a hex string (ASCII) into raw bytes.
/// Writes into `out` and returns the number of bytes written.
/// Returns None if the hex string is invalid or `out` is too small.
pub fn decode_hex(hex: &[u8], out: &mut [u8]) -> bool {
    if hex.len() % 2 != 0 {
        return false;
    }
    let byte_len = hex.len() / 2;
    if byte_len > out.len() {
        return false;
    }
    for i in 0..byte_len {
        let hi = match hex_digit(hex[i * 2]) {
            Some(v) => v,
            None => return false,
        };
        let lo = match hex_digit(hex[i * 2 + 1]) {
            Some(v) => v,
            None => return false,
        };
        out[i] = (hi << 4) | lo;
    }
    true
}

/// Convert a single ASCII hex character to its 4-bit value.
fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Encode raw bytes as a lowercase hex string into `out`.
/// Returns the number of ASCII bytes written (always input.len() * 2).
/// Returns None if `out` is too small.
pub fn encode_hex(input: &[u8], out: &mut [u8]) -> Option<usize> {
    let needed = input.len() * 2;
    if needed > out.len() {
        return None;
    }
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    for (i, &byte) in input.iter().enumerate() {
        out[i * 2] = HEX_CHARS[(byte >> 4) as usize];
        out[i * 2 + 1] = HEX_CHARS[(byte & 0x0f) as usize];
    }
    Some(needed)
}
