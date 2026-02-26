//! TimelockController — mirrors OpenZeppelin TimelockController.sol
//!
//! Introduces a delay between a proposal passing and its execution.
//! Operations follow the lifecycle:
//!
//!   Unset → Pending → Ready → Done
//!                   ↘ Canceled
//!                           ↘ Expired (after grace period)
//!
//! ## Security Fixes Applied
//!
//! - Cryptographic operation ID via FNV-1a hash (not weak XOR)
//! - Grace period: operations expire after ready_at + TIMELOCK_GRACE_PERIOD
//! - Multi-digit index support (0-99)
//!
//! ## Data Format
//!
//! Operations stored as:
//!   op_count=2;op_0_id=<hash>;op_0_prop=<prop_id>;op_0_ready=<time>;op_0_state=1;...

use crate::foundation::config::*;
use crate::foundation::data::*;
use crate::foundation::parse::*;
use crate::governance::governor::{build_prop_key, read_count, format_u8};
use crate::crypto::hash::hash_operation;

/// Schedule an operation for future execution. Mirrors TimelockController.schedule().
///
/// Requirements:
///   - Operation must not already exist (state == Unset)
///   - Delay must be >= TIMELOCK_MIN_DELAY
///
/// The operation becomes Ready when current_time >= ready_at,
/// and Expired when current_time > ready_at + TIMELOCK_GRACE_PERIOD.
pub fn schedule(
    data: &[u8],
    data_len: usize,
    proposal_id: u32,
    current_time: u32,
    delay: u32,
) -> Result<([u8; 4096], usize, u32), i32> {
    if delay < TIMELOCK_MIN_DELAY {
        return Err(ERR_TOO_EARLY);
    }

    // Check operation doesn't already exist for this proposal
    if find_operation_by_proposal(data, proposal_id).is_ok() {
        return Err(ERR_OP_ALREADY_QUEUED);
    }

    let op_count = read_count(data, b"op_count");

    // Generate cryptographic operation ID
    let op_id = hash_operation(proposal_id, current_time, op_count);
    let ready_at = current_time + delay;

    // Build updated data
    let mut new_data = [0u8; 4096];
    let mut pos = 0;
    let mut scan = 0;

    while scan < data_len {
        let entry_end = data[scan..data_len].iter()
            .position(|&b| b == b';')
            .map(|p| scan + p)
            .unwrap_or(data_len);

        let entry = &data[scan..entry_end];

        let skip = if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            &entry[..eq] == b"op_count"
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

    let idx = op_count;
    let mut key_buf = [0u8; 48];
    let mut val_buf = [0u8; 20];

    // op_count
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let count_len = format_u8(idx + 1, &mut val_buf);
    pos = write_entry(&mut new_data, pos, b"op_count", &val_buf[..count_len]);

    // op_N_id
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let klen = build_prop_key(b"op_", idx, b"_id", &mut key_buf);
    let vlen = format_u32(op_id, &mut val_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..klen], &val_buf[..vlen]);

    // op_N_prop (linked proposal)
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let klen = build_prop_key(b"op_", idx, b"_prop", &mut key_buf);
    let vlen = format_u32(proposal_id, &mut val_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..klen], &val_buf[..vlen]);

    // op_N_ready
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let klen = build_prop_key(b"op_", idx, b"_ready", &mut key_buf);
    let vlen = format_u32(ready_at, &mut val_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..klen], &val_buf[..vlen]);

    // op_N_state = Pending (1)
    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let klen = build_prop_key(b"op_", idx, b"_state", &mut key_buf);
    pos = write_entry(&mut new_data, pos, &key_buf[..klen], b"1");

    Ok((new_data, pos, op_id))
}

/// Execute a ready operation. Mirrors TimelockController.execute().
///
/// Requirements:
///   - Operation must be in Ready state (timer expired, within grace period)
pub fn execute(
    data: &[u8],
    data_len: usize,
    operation_index: u8,
    current_time: u32,
) -> Result<([u8; 4096], usize), i32> {
    let state = get_operation_state(data, operation_index, current_time);

    if state == OP_STATE_EXPIRED {
        return Err(ERR_OP_EXPIRED);
    }

    if state != OP_STATE_READY {
        return Err(ERR_OP_NOT_READY);
    }

    // Update state to Done (3)
    update_op_field(data, data_len, operation_index, b"_state", b"3")
}

/// Cancel a pending operation. Mirrors TimelockController.cancel().
pub fn cancel(
    data: &[u8],
    data_len: usize,
    operation_index: u8,
    current_time: u32,
) -> Result<([u8; 4096], usize), i32> {
    let state = get_operation_state(data, operation_index, current_time);

    // Can only cancel Pending or Ready operations (not Done or Expired)
    if state != OP_STATE_PENDING && state != OP_STATE_READY {
        return Err(ERR_OP_NOT_READY);
    }

    // Set state to Unset (effectively removes it)
    update_op_field(data, data_len, operation_index, b"_state", b"0")
}

/// Get the current state of an operation.
/// Now includes grace period expiry (Fix #8).
///
/// State transitions:
///   - Stored Done/Unset → return as-is
///   - Stored Pending + time < ready_at → Pending
///   - Stored Pending + ready_at <= time <= ready_at + grace → Ready
///   - Stored Pending + time > ready_at + grace → Expired
pub fn get_operation_state(data: &[u8], operation_index: u8, current_time: u32) -> u8 {
    let mut key_buf = [0u8; 48];

    let klen = build_prop_key(b"op_", operation_index, b"_state", &mut key_buf);
    let stored_state = find_value(data, &key_buf[..klen])
        .and_then(parse_u8_digit)
        .unwrap_or(OP_STATE_UNSET);

    if stored_state != OP_STATE_PENDING {
        return stored_state;
    }

    // Check timing with grace period
    let klen = build_prop_key(b"op_", operation_index, b"_ready", &mut key_buf);
    let ready_at = find_value(data, &key_buf[..klen])
        .and_then(|v| parse_u32(v))
        .unwrap_or(u32::MAX);

    if current_time < ready_at {
        return OP_STATE_PENDING;
    }

    // Check grace period expiry
    let expiry = ready_at.saturating_add(TIMELOCK_GRACE_PERIOD);
    if current_time > expiry {
        return OP_STATE_EXPIRED;
    }

    OP_STATE_READY
}

/// Check if an operation is pending.
pub fn is_operation_pending(data: &[u8], operation_index: u8, current_time: u32) -> bool {
    get_operation_state(data, operation_index, current_time) == OP_STATE_PENDING
}

/// Check if an operation is ready.
pub fn is_operation_ready(data: &[u8], operation_index: u8, current_time: u32) -> bool {
    get_operation_state(data, operation_index, current_time) == OP_STATE_READY
}

/// Check if an operation is done.
pub fn is_operation_done(data: &[u8], operation_index: u8) -> bool {
    let mut key_buf = [0u8; 48];
    let klen = build_prop_key(b"op_", operation_index, b"_state", &mut key_buf);
    let stored = find_value(data, &key_buf[..klen])
        .and_then(parse_u8_digit)
        .unwrap_or(OP_STATE_UNSET);
    stored == OP_STATE_DONE
}

/// Check if an operation has expired (past grace period).
pub fn is_operation_expired(data: &[u8], operation_index: u8, current_time: u32) -> bool {
    get_operation_state(data, operation_index, current_time) == OP_STATE_EXPIRED
}

/// Get the ready timestamp for an operation.
pub fn get_timestamp(data: &[u8], operation_index: u8) -> u32 {
    let mut key_buf = [0u8; 48];
    let klen = build_prop_key(b"op_", operation_index, b"_ready", &mut key_buf);
    find_value(data, &key_buf[..klen])
        .and_then(|v| parse_u32(v))
        .unwrap_or(0)
}

/// Find an operation index by its linked proposal ID.
pub fn find_operation_by_proposal(data: &[u8], proposal_id: u32) -> Result<u8, i32> {
    let op_count = read_count(data, b"op_count");

    let mut key_buf = [0u8; 48];
    let mut id_buf = [0u8; 10];
    let id_len = format_u32(proposal_id, &mut id_buf);

    for i in 0..op_count {
        let klen = build_prop_key(b"op_", i, b"_prop", &mut key_buf);
        if let Some(stored_id) = find_value(data, &key_buf[..klen]) {
            if stored_id == &id_buf[..id_len] {
                return Ok(i);
            }
        }
    }

    Err(ERR_PROPOSAL_NOT_FOUND)
}

// ——— Internal helpers ———

fn update_op_field(
    data: &[u8],
    data_len: usize,
    op_index: u8,
    field_suffix: &[u8],
    new_value: &[u8],
) -> Result<([u8; 4096], usize), i32> {
    let mut key_buf = [0u8; 48];
    let klen = build_prop_key(b"op_", op_index, field_suffix, &mut key_buf);
    let target_key = &key_buf[..klen];

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
