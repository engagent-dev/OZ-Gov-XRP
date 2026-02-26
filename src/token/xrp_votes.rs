//! XRP Votes — mirrors OpenZeppelin ERC20Votes for XRPL native tokens.
//!
//! On Ethereum, voting power comes from ERC20Votes token with delegation
//! and checkpointing. On XRPL, we adapt this to work with:
//!
//! 1. Native XRP balances (read via XRPL hooks host functions)
//! 2. Issued tokens (IOUs) on the XRPL DEX
//! 3. Snapshot-based voting (balance at proposal creation time)
//!
//! ## Delegation
//!
//! Like ERC20Votes, members can delegate their voting power to another
//! account. Self-delegation is implicit (if no delegate set, votes count
//! as self-delegated).
//!
//! Data format:
//!   delegate_<voter_hex>=<delegate_hex>
//!   snapshot_<prop_id>_<account_hex>=<power_at_snapshot>

use crate::foundation::config::*;
use crate::foundation::data::*;
use crate::foundation::parse::*;
use crate::crypto::hex::encode_hex;
use crate::governance::governor::{parse_u64, format_u64};
use crate::governance::votes;

/// Delegate voting power to another account. Mirrors ERC20Votes.delegate().
///
/// If delegate == voter (self-delegation), clears any existing delegation.
pub fn delegate(
    data: &[u8],
    data_len: usize,
    voter: &[u8; ACCOUNT_ID_SIZE],
    delegate_to: &[u8; ACCOUNT_ID_SIZE],
) -> Result<([u8; 4096], usize), i32> {
    let mut voter_hex = [0u8; 40];
    encode_hex(voter, &mut voter_hex);

    let mut delegate_hex = [0u8; 40];
    encode_hex(delegate_to, &mut delegate_hex);

    // Build delegation key: "delegate_<voter_hex>"
    let mut key_buf = [0u8; 50]; // "delegate_" + 40 hex
    let prefix = b"delegate_";
    key_buf[..prefix.len()].copy_from_slice(prefix);
    key_buf[prefix.len()..prefix.len() + 40].copy_from_slice(&voter_hex);
    let key_len = prefix.len() + 40;

    // Check if delegation already exists
    let _existing = find_value(data, &key_buf[..key_len]);

    // Self-delegation: if voter == delegate, remove delegation entry
    let is_self_delegate = voter == delegate_to;

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
            &entry[..eq] == &key_buf[..key_len]
        } else { false };

        if is_target {
            found = true;
            if !is_self_delegate {
                // Update delegation
                if pos > 0 { pos = write_separator(&mut new_data, pos); }
                pos = write_entry(&mut new_data, pos, &key_buf[..key_len], &delegate_hex);
            }
            // If self-delegate, skip (removes delegation)
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

    // New delegation (not found previously)
    if !found && !is_self_delegate {
        if pos > 0 { pos = write_separator(&mut new_data, pos); }
        pos = write_entry(&mut new_data, pos, &key_buf[..key_len], &delegate_hex);
    }

    Ok((new_data, pos))
}

/// Get the delegate for a voter. Returns the delegate's AccountID.
/// If no delegation exists, returns the voter themselves (self-delegation).
pub fn get_delegate(
    data: &[u8],
    voter: &[u8; ACCOUNT_ID_SIZE],
) -> [u8; ACCOUNT_ID_SIZE] {
    let mut voter_hex = [0u8; 40];
    encode_hex(voter, &mut voter_hex);

    let mut key_buf = [0u8; 50];
    let prefix = b"delegate_";
    key_buf[..prefix.len()].copy_from_slice(prefix);
    key_buf[prefix.len()..prefix.len() + 40].copy_from_slice(&voter_hex);
    let key_len = prefix.len() + 40;

    if let Some(delegate_hex) = find_value(data, &key_buf[..key_len]) {
        if delegate_hex.len() == 40 {
            let mut result = [0u8; ACCOUNT_ID_SIZE];
            if crate::crypto::hex::decode_hex(delegate_hex, &mut result) {
                return result;
            }
        }
    }

    // Default: self-delegation
    *voter
}

/// Get effective voting power for an account, including delegated power.
/// Mirrors ERC20Votes.getVotes() which returns delegated voting power.
pub fn get_effective_votes(
    data: &[u8],
    account: &[u8; ACCOUNT_ID_SIZE],
) -> u64 {
    let mut account_hex = [0u8; 40];
    encode_hex(account, &mut account_hex);

    let mut total_power: u64 = 0;

    // Self-power (if self-delegated or no delegation)
    let self_delegate = get_delegate(data, account);
    if self_delegate == *account {
        total_power += votes::get_votes(data, account);
    }

    // Scan all members for those who delegated to this account
    let member_count = votes::get_member_count(data);
    let mut key_buf = [0u8; 16];

    for i in 0..member_count {
        // Build multi-digit member key
        let prefix = b"member_";
        let plen = prefix.len();
        key_buf[..plen].copy_from_slice(prefix);
        let idx_len = crate::governance::governor::format_u8(i, &mut key_buf[plen..]);
        let klen = plen + idx_len;

        if let Some(val) = find_value(data, &key_buf[..klen]) {
            if val.len() >= 40 {
                let member_hex = &val[..40];
                // Skip self (already counted)
                if member_hex == &account_hex[..] {
                    continue;
                }

                // Decode this member's AccountID
                let mut member_id = [0u8; ACCOUNT_ID_SIZE];
                if crate::crypto::hex::decode_hex(member_hex, &mut member_id) {
                    let their_delegate = get_delegate(data, &member_id);
                    if their_delegate == *account {
                        total_power += votes::get_votes(data, &member_id);
                    }
                }
            }
        }
    }

    total_power
}

/// Take a snapshot of voting power at proposal creation time.
/// Stored as: snapshot_<prop_id>_<account_hex>=<power>
pub fn snapshot_voting_power(
    data: &[u8],
    data_len: usize,
    proposal_id: u32,
    account: &[u8; ACCOUNT_ID_SIZE],
) -> Result<([u8; 4096], usize), i32> {
    let power = get_effective_votes(data, account);

    let mut account_hex = [0u8; 40];
    encode_hex(account, &mut account_hex);

    // Build key: "snap_<prop_id>_<hex>"
    let mut key_buf = [0u8; 64];
    let prefix = b"snap_";
    let mut kpos = prefix.len();
    key_buf[..kpos].copy_from_slice(prefix);

    let mut id_buf = [0u8; 10];
    let id_len = format_u32(proposal_id, &mut id_buf);
    key_buf[kpos..kpos + id_len].copy_from_slice(&id_buf[..id_len]);
    kpos += id_len;

    key_buf[kpos] = b'_';
    kpos += 1;

    key_buf[kpos..kpos + 40].copy_from_slice(&account_hex);
    kpos += 40;

    // Append snapshot entry
    let mut new_data = [0u8; 4096];
    let mut pos = 0;

    // Copy existing data
    if data_len > 0 {
        new_data[..data_len].copy_from_slice(&data[..data_len]);
        pos = data_len;
    }

    let mut val_buf = [0u8; 20];
    let vlen = format_u64(power, &mut val_buf);

    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    pos = write_entry(&mut new_data, pos, &key_buf[..kpos], &val_buf[..vlen]);

    Ok((new_data, pos))
}

/// Get snapshotted voting power for an account at a specific proposal.
pub fn get_snapshot_votes(
    data: &[u8],
    proposal_id: u32,
    account: &[u8; ACCOUNT_ID_SIZE],
) -> u64 {
    let mut account_hex = [0u8; 40];
    encode_hex(account, &mut account_hex);

    let mut key_buf = [0u8; 64];
    let prefix = b"snap_";
    let mut kpos = prefix.len();
    key_buf[..kpos].copy_from_slice(prefix);

    let mut id_buf = [0u8; 10];
    let id_len = format_u32(proposal_id, &mut id_buf);
    key_buf[kpos..kpos + id_len].copy_from_slice(&id_buf[..id_len]);
    kpos += id_len;

    key_buf[kpos] = b'_';
    kpos += 1;

    key_buf[kpos..kpos + 40].copy_from_slice(&account_hex);
    kpos += 40;

    find_value(data, &key_buf[..kpos])
        .and_then(|v| parse_u64(v))
        .unwrap_or(0)
}
