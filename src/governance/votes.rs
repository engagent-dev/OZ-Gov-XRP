//! GovernorVotes + GovernorVotesQuorumFraction — voting power module
//!
//! Mirrors OpenZeppelin's:
//! - GovernorVotes.sol: Extracts voting weight from token balances
//! - GovernorVotesQuorumFraction.sol: Quorum as % of total supply
//!
//! On XRPL, voting power is derived from XRP/token balance snapshots
//! stored in the contract's data field, rather than from ERC20Votes.
//!
//! ## Data Format
//!
//! Member records:
//!   member_count=3;member_0=<hex>:1000000:5;member_1=<hex>:2000000:1;...
//!
//! Format: member_N=<account_hex>:<voting_power>:<role_bitmask>

use crate::foundation::config::*;
use crate::foundation::data::*;
use crate::crypto::hex::encode_hex;
use crate::governance::governor::{parse_u64, format_u64};

/// Get voting power of an account. Mirrors Governor.getVotes().
pub fn get_votes(data: &[u8], account: &[u8; ACCOUNT_ID_SIZE]) -> u64 {
    match find_member(data, account) {
        Some((_idx, _hex, power, _roles)) => power,
        None => 0,
    }
}

/// Get roles bitmask for an account.
pub fn get_roles(data: &[u8], account: &[u8; ACCOUNT_ID_SIZE]) -> u8 {
    match find_member(data, account) {
        Some((_idx, _hex, _power, roles)) => roles,
        None => 0,
    }
}

/// Check if account has a specific role.
pub fn has_role(data: &[u8], account: &[u8; ACCOUNT_ID_SIZE], role: u8) -> bool {
    get_roles(data, account) & role != 0
}

/// Get total voting power of all members. Used for quorum calculation.
/// Mirrors token.totalSupply() as used by GovernorVotesQuorumFraction.
/// Fix #6: Uses saturating_add to prevent overflow.
pub fn get_total_voting_power(data: &[u8]) -> u64 {
    let member_count = read_member_count(data);

    let mut total: u64 = 0;
    let mut key_buf = [0u8; 16];

    for i in 0..member_count {
        let klen = build_member_key(i, &mut key_buf);
        if let Some(val) = find_value(data, &key_buf[..klen]) {
            if let Some((_hex, power, _roles)) = parse_member_record(val) {
                total = total.saturating_add(power);
            }
        }
    }
    total
}

/// Calculate quorum required for a given total voting power.
/// Mirrors GovernorVotesQuorumFraction.quorum().
pub fn quorum(total_voting_power: u64) -> u64 {
    (total_voting_power / 100).saturating_mul(QUORUM_PERCENTAGE as u64)
}

/// Get number of registered members. Supports multi-digit counts (0-99).
pub fn get_member_count(data: &[u8]) -> u8 {
    read_member_count(data)
}

/// Read member_count supporting multi-digit values.
fn read_member_count(data: &[u8]) -> u8 {
    find_value(data, b"member_count")
        .and_then(|v| {
            if v.is_empty() { return None; }
            let mut result: u8 = 0;
            for &b in v {
                if b < b'0' || b > b'9' { return None; }
                result = result.checked_mul(10)?.checked_add(b - b'0')?;
            }
            Some(result)
        })
        .unwrap_or(0)
}

/// Add or update a member. Returns updated data.
pub fn set_member(
    data: &[u8],
    data_len: usize,
    account: &[u8; ACCOUNT_ID_SIZE],
    voting_power: u64,
    roles: u8,
) -> Result<([u8; 4096], usize), i32> {
    let member_count = get_member_count(data);

    // Build the member value: <hex>:<power>:<roles>
    let mut val_buf = [0u8; 64];
    let vlen = build_member_value(account, voting_power, roles, &mut val_buf);

    // Check if member already exists
    if let Some((idx, _, _, _)) = find_member(data, account) {
        // Update existing member
        let mut key_buf = [0u8; 16];
        let klen = build_member_key(idx, &mut key_buf);
        return update_data_field(data, data_len, &key_buf[..klen], &val_buf[..vlen]);
    }

    // New member — check capacity
    if member_count as usize >= MAX_MEMBERS {
        return Err(ERR_BAD_CONFIG);
    }

    // Append new member
    let mut new_data = [0u8; 4096];
    let mut pos = 0;
    let mut scan = 0;

    while scan < data_len {
        let entry_end = data[scan..data_len].iter()
            .position(|&b| b == b';')
            .map(|p| scan + p)
            .unwrap_or(data_len);

        let entry = &data[scan..entry_end];

        // Skip old member_count
        let skip = if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            &entry[..eq] == b"member_count"
        } else { false };

        if !skip && !entry.is_empty() {
            if pos > 0 { pos = write_separator(&mut new_data, pos); }
            let elen = entry.len();
            if pos + elen <= new_data.len() {
                new_data[pos..pos + elen].copy_from_slice(entry);
                pos += elen;
            }
        }

        scan = entry_end + 1;
    }

    // Write updated member_count (multi-digit safe)
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let mut count_buf = [0u8; 3];
    let count_len = crate::governance::governor::format_u8(member_count + 1, &mut count_buf);
    pos = write_entry(&mut new_data, pos, b"member_count", &count_buf[..count_len]);

    // Write new member entry
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let mut key_buf = [0u8; 16];
    let klen = build_member_key(member_count, &mut key_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..klen], &val_buf[..vlen]);

    Ok((new_data, pos))
}

/// Grant a role to an account (OR with existing roles).
pub fn grant_role(
    data: &[u8],
    data_len: usize,
    account: &[u8; ACCOUNT_ID_SIZE],
    role: u8,
) -> Result<([u8; 4096], usize), i32> {
    let current_roles = get_roles(data, account);
    let power = get_votes(data, account);
    set_member(data, data_len, account, power, current_roles | role)
}

/// Revoke a role from an account (AND NOT with existing roles).
pub fn revoke_role(
    data: &[u8],
    data_len: usize,
    account: &[u8; ACCOUNT_ID_SIZE],
    role: u8,
) -> Result<([u8; 4096], usize), i32> {
    let current_roles = get_roles(data, account);
    let power = get_votes(data, account);
    set_member(data, data_len, account, power, current_roles & !role)
}

// ——— Internal helpers ———

/// Build "member_N" key — supports multi-digit indices (0-99).
/// Fix #7: replaces single-digit `b'0' + index` with proper formatting.
fn build_member_key(index: u8, out: &mut [u8]) -> usize {
    let prefix = b"member_";
    let plen = prefix.len();
    out[..plen].copy_from_slice(prefix);
    let idx_len = crate::governance::governor::format_u8(index, &mut out[plen..]);
    plen + idx_len
}

/// Build member value: "<hex40>:<power>:<roles>"
fn build_member_value(
    account: &[u8; ACCOUNT_ID_SIZE],
    voting_power: u64,
    roles: u8,
    out: &mut [u8],
) -> usize {
    let mut pos = 0;
    let mut hex_buf = [0u8; 40];
    encode_hex(account, &mut hex_buf);
    out[pos..pos + 40].copy_from_slice(&hex_buf);
    pos += 40;
    out[pos] = b':';
    pos += 1;
    let plen = format_u64(voting_power, &mut out[pos..]);
    pos += plen;
    out[pos] = b':';
    pos += 1;
    out[pos] = b'0' + roles;
    pos += 1;
    pos
}

/// Find a member by account. Returns (index, hex_slice, power, roles).
fn find_member<'a>(
    data: &'a [u8],
    account: &[u8; ACCOUNT_ID_SIZE],
) -> Option<(u8, &'a [u8], u64, u8)> {
    let mut hex_buf = [0u8; 40];
    encode_hex(account, &mut hex_buf);

    let member_count = read_member_count(data);

    let mut key_buf = [0u8; 16];

    for i in 0..member_count {
        let klen = build_member_key(i, &mut key_buf);
        if let Some(val) = find_value(data, &key_buf[..klen]) {
            if val.len() >= 40 && &val[..40] == &hex_buf[..] {
                if let Some((_hex, power, roles)) = parse_member_record(val) {
                    return Some((i, &val[..40], power, roles));
                }
            }
        }
    }
    None
}

/// Parse "hex40:power:roles" → (hex_slice, power, roles)
fn parse_member_record(val: &[u8]) -> Option<(&[u8], u64, u8)> {
    if val.len() < 44 { return None; } // 40 hex + : + at least 1 digit + : + 1 digit
    if val[40] != b':' { return None; }

    let rest = &val[41..];
    let colon2 = rest.iter().position(|&b| b == b':')?;
    let power = parse_u64(&rest[..colon2])?;
    let roles_byte = rest.get(colon2 + 1)?;
    let roles = roles_byte.checked_sub(b'0')?;

    Some((&val[..40], power, roles))
}

/// Generic data field update helper
fn update_data_field(
    data: &[u8],
    data_len: usize,
    target_key: &[u8],
    new_value: &[u8],
) -> Result<([u8; 4096], usize), i32> {
    let mut new_data = [0u8; 4096];
    let mut pos = 0;
    let mut scan = 0;
    let mut found = false;

    while scan < data_len {
        let entry_end = data[scan..data_len].iter()
            .position(|&b| b == b';')
            .map(|p| scan + p)
            .unwrap_or(data_len);

        let entry = &data[scan..entry_end];

        let is_target = if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            &entry[..eq] == target_key
        } else { false };

        if is_target {
            if pos > 0 { pos = write_separator(&mut new_data, pos); }
            pos = write_entry(&mut new_data, pos, target_key, new_value);
            found = true;
        } else if !entry.is_empty() {
            if pos > 0 { pos = write_separator(&mut new_data, pos); }
            let elen = entry.len();
            if pos + elen <= new_data.len() {
                new_data[pos..pos + elen].copy_from_slice(entry);
                pos += elen;
            }
        }

        scan = entry_end + 1;
    }

    if !found {
        return Err(ERR_DATA_READ);
    }

    Ok((new_data, pos))
}
