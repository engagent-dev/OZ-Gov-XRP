//! Governor core logic — mirrors OpenZeppelin's Governor.sol
//!
//! Implements the proposal lifecycle:
//!   propose() → vote → queue() → execute()
//!
//! ## Proposal States (mirrors IGovernor.ProposalState)
//!
//! Pending → Active → Succeeded → Queued → Executed
//!                  ↘ Defeated
//!        ↘ Canceled
//!
//! ## Security Fixes Applied
//!
//! - Cryptographic proposal ID via FNV-1a hash (not weak XOR)
//! - Checked arithmetic on all vote tallies (overflow protection)
//! - Multi-digit index keys (supports 0-99, not just 0-9)

use crate::foundation::config::*;
use crate::foundation::data::*;
use crate::foundation::parse::*;
use crate::crypto::hex::encode_hex;
use crate::crypto::hash::hash_proposal;

/// Create a new proposal. Mirrors Governor.propose().
///
/// Requirements:
///   - Caller must have voting power >= PROPOSAL_THRESHOLD
///   - Proposal count must be < MAX_PROPOSALS
///
/// Proposal ID is a cryptographic hash of (proposer, description, time, nonce),
/// mirroring OZ's `keccak256(abi.encode(targets, values, calldatas, descriptionHash))`.
pub fn propose(
    data: &[u8],
    data_len: usize,
    proposer: &[u8; ACCOUNT_ID_SIZE],
    description_hash: u32,
    current_time: u32,
    proposer_votes: u64,
) -> Result<([u8; 4096], usize, u32), i32> {
    // Check proposal threshold
    if proposer_votes < PROPOSAL_THRESHOLD {
        return Err(ERR_BELOW_THRESHOLD);
    }

    // Count existing proposals
    let prop_count = read_count(data, b"proposal_count");

    if prop_count as usize >= MAX_PROPOSALS {
        return Err(ERR_MAX_PROPOSALS);
    }

    // Generate cryptographic proposal ID bound to all inputs
    let proposal_id = hash_proposal(proposer, description_hash, current_time, prop_count);

    // Build new data with proposal added
    let mut new_data = [0u8; 4096];
    let mut pos = 0;

    // Copy existing entries
    let mut scan = 0;
    while scan < data_len {
        let entry_end = data[scan..data_len].iter()
            .position(|&b| b == b';')
            .map(|p| scan + p)
            .unwrap_or(data_len);

        let entry = &data[scan..entry_end];

        // Skip proposal_count (we'll rewrite it)
        let skip = if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            &entry[..eq] == b"proposal_count"
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

    let idx = prop_count;
    let mut key_buf = [0u8; 48];
    let mut val_buf = [0u8; 64];

    // proposal_count
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let count_len = format_u8(idx + 1, &mut val_buf);
    pos = write_entry(&mut new_data, pos, b"proposal_count", &val_buf[..count_len]);

    // prop_N_id=<id>
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let key_len = build_prop_key(b"prop_", idx, b"_id", &mut key_buf);
    let val_len = format_u32(proposal_id, &mut val_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..key_len], &val_buf[..val_len]);

    // prop_N_proposer=<hex>
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let key_len = build_prop_key(b"prop_", idx, b"_proposer", &mut key_buf);
    let mut hex_buf = [0u8; 40];
    encode_hex(proposer, &mut hex_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..key_len], &hex_buf);

    // prop_N_state=0 (Pending)
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let key_len = build_prop_key(b"prop_", idx, b"_state", &mut key_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..key_len], b"0");

    // prop_N_start=<time + voting_delay>
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let key_len = build_prop_key(b"prop_", idx, b"_start", &mut key_buf);
    let start_time = current_time + VOTING_DELAY;
    let val_len = format_u32(start_time, &mut val_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..key_len], &val_buf[..val_len]);

    // prop_N_end=<start + voting_period>
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let key_len = build_prop_key(b"prop_", idx, b"_end", &mut key_buf);
    let end_time = start_time + VOTING_PERIOD;
    let val_len = format_u32(end_time, &mut val_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..key_len], &val_buf[..val_len]);

    // prop_N_for=0; prop_N_against=0; prop_N_abstain=0
    for suffix in [b"_for" as &[u8], b"_against", b"_abstain"] {
        if pos > 0 { pos = write_separator(&mut new_data, pos); }
        let key_len = build_prop_key(b"prop_", idx, suffix, &mut key_buf);
        pos = write_entry(&mut new_data, pos, &key_buf[..key_len], b"0");
    }

    // prop_N_desc=<hash>
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let key_len = build_prop_key(b"prop_", idx, b"_desc", &mut key_buf);
    let val_len = format_u32(description_hash, &mut val_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..key_len], &val_buf[..val_len]);

    Ok((new_data, pos, proposal_id))
}

/// Get the current state of a proposal. Mirrors Governor.state().
///
/// State transitions based on time:
///   - Before vote_start: Pending (0)
///   - Between vote_start and vote_end: Active (1)
///   - After vote_end, quorum not met or defeated: Defeated (3)
///   - After vote_end, succeeded: Succeeded (4)
///   - Explicitly set states (Canceled, Queued, Executed) override
pub fn get_proposal_state(
    data: &[u8],
    proposal_index: u8,
    current_time: u32,
    total_voting_power: u64,
) -> u8 {
    let mut key_buf = [0u8; 48];

    // Read stored state
    let key_len = build_prop_key(b"prop_", proposal_index, b"_state", &mut key_buf);
    let stored_state = find_value(data, &key_buf[..key_len])
        .and_then(parse_u8_digit)
        .unwrap_or(PROPOSAL_STATE_PENDING);

    // If explicitly canceled, queued, or executed, return as-is
    if stored_state == PROPOSAL_STATE_CANCELED
        || stored_state == PROPOSAL_STATE_QUEUED
        || stored_state == PROPOSAL_STATE_EXECUTED
        || stored_state == PROPOSAL_STATE_EXPIRED
    {
        return stored_state;
    }

    // Read timing
    let key_len = build_prop_key(b"prop_", proposal_index, b"_start", &mut key_buf);
    let vote_start = find_value(data, &key_buf[..key_len])
        .and_then(|v| parse_u32(v))
        .unwrap_or(0);

    let key_len = build_prop_key(b"prop_", proposal_index, b"_end", &mut key_buf);
    let vote_end = find_value(data, &key_buf[..key_len])
        .and_then(|v| parse_u32(v))
        .unwrap_or(0);

    if current_time < vote_start {
        return PROPOSAL_STATE_PENDING;
    }

    if current_time <= vote_end {
        return PROPOSAL_STATE_ACTIVE;
    }

    // Voting ended — check results using checked arithmetic
    let key_len = build_prop_key(b"prop_", proposal_index, b"_for", &mut key_buf);
    let for_votes = find_value(data, &key_buf[..key_len])
        .and_then(|v| parse_u64(v))
        .unwrap_or(0);

    let key_len = build_prop_key(b"prop_", proposal_index, b"_against", &mut key_buf);
    let against_votes = find_value(data, &key_buf[..key_len])
        .and_then(|v| parse_u64(v))
        .unwrap_or(0);

    let key_len = build_prop_key(b"prop_", proposal_index, b"_abstain", &mut key_buf);
    let abstain_votes = find_value(data, &key_buf[..key_len])
        .and_then(|v| parse_u64(v))
        .unwrap_or(0);

    let quorum_required = (total_voting_power / 100).saturating_mul(QUORUM_PERCENTAGE as u64);

    // Quorum: for + abstain must meet threshold (checked)
    let quorum_votes = for_votes.saturating_add(abstain_votes);

    if quorum_votes < quorum_required {
        return PROPOSAL_STATE_DEFEATED;
    }

    if for_votes > against_votes {
        PROPOSAL_STATE_SUCCEEDED
    } else {
        PROPOSAL_STATE_DEFEATED
    }
}

/// Cancel a proposal. Mirrors Governor._cancel().
/// Only the proposer can cancel, and only while Pending.
pub fn cancel_proposal(
    data: &[u8],
    data_len: usize,
    proposal_index: u8,
    caller: &[u8; ACCOUNT_ID_SIZE],
    current_time: u32,
    total_voting_power: u64,
) -> Result<([u8; 4096], usize), i32> {
    let mut key_buf = [0u8; 48];

    // Verify caller is the proposer
    let key_len = build_prop_key(b"prop_", proposal_index, b"_proposer", &mut key_buf);
    let stored_proposer = find_value(data, &key_buf[..key_len])
        .ok_or(ERR_PROPOSAL_NOT_FOUND)?;

    let mut caller_hex = [0u8; 40];
    encode_hex(caller, &mut caller_hex);
    if stored_proposer != &caller_hex[..] {
        return Err(ERR_NOT_PROPOSER);
    }

    // Check proposal is still Pending
    let state = get_proposal_state(data, proposal_index, current_time, total_voting_power);
    if state != PROPOSAL_STATE_PENDING {
        return Err(ERR_PROPOSAL_NOT_ACTIVE);
    }

    // Update state to Canceled
    update_proposal_field(data, data_len, proposal_index, b"_state", b"2")
}

/// Find a proposal index by its ID. Returns the index or error.
pub fn find_proposal_by_id(data: &[u8], proposal_id: u32) -> Result<u8, i32> {
    let prop_count = read_count(data, b"proposal_count");

    let mut key_buf = [0u8; 48];
    let mut id_buf = [0u8; 10];
    let id_len = format_u32(proposal_id, &mut id_buf);

    for i in 0..prop_count {
        let key_len = build_prop_key(b"prop_", i, b"_id", &mut key_buf);
        if let Some(stored_id) = find_value(data, &key_buf[..key_len]) {
            if stored_id == &id_buf[..id_len] {
                return Ok(i);
            }
        }
    }

    Err(ERR_PROPOSAL_NOT_FOUND)
}

// ═══════════════════════════════════════════════════════════════════════
// Reentrancy Guard — Fix #2
// ═══════════════════════════════════════════════════════════════════════

/// Check if the contract is currently executing (reentrancy guard).
/// Returns true if locked.
pub fn is_locked(data: &[u8]) -> bool {
    find_value(data, b"_lock") == Some(b"1")
}

/// Set the reentrancy lock. Returns updated data.
pub fn set_lock(
    data: &[u8],
    data_len: usize,
    locked: bool,
) -> Result<([u8; 4096], usize), i32> {
    let lock_val = if locked { b"1" as &[u8] } else { b"0" };

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
            &entry[..eq] == b"_lock"
        } else { false };

        if is_target {
            if pos > 0 { pos = write_separator(&mut new_data, pos); }
            pos = write_entry(&mut new_data, pos, b"_lock", lock_val);
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
        if pos > 0 { pos = write_separator(&mut new_data, pos); }
        pos = write_entry(&mut new_data, pos, b"_lock", lock_val);
    }

    Ok((new_data, pos))
}

// ═══════════════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════════════

/// Build a composite key like "prop_0_state", "prop_12_for".
/// Supports multi-digit indices (0-99), fixing the single-digit limitation.
pub fn build_prop_key(prefix: &[u8], index: u8, suffix: &[u8], out: &mut [u8]) -> usize {
    let mut pos = prefix.len();
    if pos > out.len() { return 0; }
    out[..pos].copy_from_slice(prefix);

    // Write index as 1-3 digit ASCII
    let idx_len = format_u8(index, &mut out[pos..]);
    pos += idx_len;

    let end = pos + suffix.len();
    if end > out.len() { return 0; }
    out[pos..end].copy_from_slice(suffix);
    end
}

/// Format a u8 as ASCII decimal. Returns bytes written.
pub fn format_u8(value: u8, out: &mut [u8]) -> usize {
    if value >= 100 {
        if out.len() < 3 { return 0; }
        out[0] = b'0' + (value / 100);
        out[1] = b'0' + ((value / 10) % 10);
        out[2] = b'0' + (value % 10);
        3
    } else if value >= 10 {
        if out.len() < 2 { return 0; }
        out[0] = b'0' + (value / 10);
        out[1] = b'0' + (value % 10);
        2
    } else {
        if out.is_empty() { return 0; }
        out[0] = b'0' + value;
        1
    }
}

/// Read a count field (supports multi-digit values 0-99).
pub fn read_count(data: &[u8], key: &[u8]) -> u8 {
    find_value(data, key)
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

/// Update a single field on a proposal in the data store.
pub fn update_proposal_field(
    data: &[u8],
    data_len: usize,
    proposal_index: u8,
    field_suffix: &[u8],
    new_value: &[u8],
) -> Result<([u8; 4096], usize), i32> {
    let mut key_buf = [0u8; 48];
    let key_len = build_prop_key(b"prop_", proposal_index, field_suffix, &mut key_buf);
    let target_key = &key_buf[..key_len];

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
        return Err(ERR_PROPOSAL_NOT_FOUND);
    }

    Ok((new_data, pos))
}

/// Parse a u64 from ASCII decimal bytes.
pub fn parse_u64(data: &[u8]) -> Option<u64> {
    if data.is_empty() { return None; }
    let mut result: u64 = 0;
    for &b in data {
        if b < b'0' || b > b'9' { return None; }
        result = result.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(result)
}

/// Format a u64 as ASCII decimal into a buffer.
pub fn format_u64(mut value: u64, out: &mut [u8]) -> usize {
    if value == 0 {
        if !out.is_empty() { out[0] = b'0'; return 1; }
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
