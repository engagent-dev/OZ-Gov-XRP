//! Contract data format: semicolon-delimited key=value store.
//!
//! The escrow's Data field uses this format:
//!   "notary_count=2;threshold=2;notary_0=abcd...;approval_count=1"
//!
//! All operations work on raw byte slices without heap allocation.

/// Find a value for a given key in semicolon-delimited "key=value" data.
/// Returns the byte slice of the value, or None if key not found.
///
/// Example: find_value(b"a=1;b=2;c=3", b"b") returns Some(b"2")
pub fn find_value<'a>(data: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let mut pos = 0;
    while pos < data.len() {
        let entry_end = data[pos..].iter().position(|&b| b == b';')
            .map(|p| pos + p)
            .unwrap_or(data.len());

        let entry = &data[pos..entry_end];

        if let Some(eq_pos) = entry.iter().position(|&b| b == b'=') {
            let entry_key = &entry[..eq_pos];
            let entry_value = &entry[eq_pos + 1..];

            if entry_key == key {
                return Some(entry_value);
            }
        }

        pos = entry_end + 1;
    }
    None
}

/// Build a key like "notary_0", "approval_12", etc. into a buffer.
/// Returns the number of bytes written.
/// Fix #7: Supports multi-digit indices (0-255).
pub fn build_indexed_key(prefix: &[u8], index: u8, out: &mut [u8]) -> usize {
    let plen = prefix.len();
    if plen >= out.len() {
        return 0;
    }
    out[..plen].copy_from_slice(prefix);
    // Format index as multi-digit ASCII
    let idx_len = if index >= 100 {
        if plen + 3 > out.len() { return 0; }
        out[plen] = b'0' + (index / 100);
        out[plen + 1] = b'0' + ((index / 10) % 10);
        out[plen + 2] = b'0' + (index % 10);
        3
    } else if index >= 10 {
        if plen + 2 > out.len() { return 0; }
        out[plen] = b'0' + (index / 10);
        out[plen + 1] = b'0' + (index % 10);
        2
    } else {
        if plen + 1 > out.len() { return 0; }
        out[plen] = b'0' + index;
        1
    };
    plen + idx_len
}

/// Write a key=value pair into data at the given position.
/// Returns the new position after writing.
pub fn write_entry(data: &mut [u8], pos: usize, key: &[u8], value: &[u8]) -> usize {
    let needed = key.len() + 1 + value.len();
    if pos + needed > data.len() {
        return pos;
    }
    data[pos..pos + key.len()].copy_from_slice(key);
    data[pos + key.len()] = b'=';
    data[pos + key.len() + 1..pos + needed].copy_from_slice(value);
    pos + needed
}

/// Write a semicolon separator. Returns new position.
pub fn write_separator(data: &mut [u8], pos: usize) -> usize {
    if pos < data.len() {
        data[pos] = b';';
        pos + 1
    } else {
        pos
    }
}
