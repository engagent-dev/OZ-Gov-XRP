//! ASCII number parsing and formatting utilities.
//!
//! Operates on raw byte slices without heap allocation.

/// Parse a single ASCII digit (0-9) from a byte slice.
/// Returns None if the slice is empty, has multiple chars, or isn't a digit.
pub fn parse_u8_digit(data: &[u8]) -> Option<u8> {
    if data.len() == 1 && data[0] >= b'0' && data[0] <= b'9' {
        Some(data[0] - b'0')
    } else {
        None
    }
}

/// Parse a u32 from ASCII decimal bytes.
/// Returns None if the slice is empty or contains non-digit characters.
pub fn parse_u32(data: &[u8]) -> Option<u32> {
    if data.is_empty() {
        return None;
    }
    let mut result: u32 = 0;
    for &b in data {
        if b < b'0' || b > b'9' {
            return None;
        }
        result = result.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(result)
}

/// Format a u32 as ASCII decimal into a buffer. Returns number of bytes written.
pub fn format_u32(mut value: u32, out: &mut [u8]) -> usize {
    if value == 0 {
        if !out.is_empty() {
            out[0] = b'0';
            return 1;
        }
        return 0;
    }

    let mut len = 0;
    while value > 0 && len < out.len() {
        out[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    out[..len].reverse();
    len
}
