//! Timelock batch operations and dependency tracking.
//!
//! Mirrors OpenZeppelin's TimelockController batch scheduling and
//! predecessor dependency mechanism.
//!
//! ## Predecessors
//!
//! An operation can optionally depend on another operation (predecessor).
//! The predecessor must be in Done state before the dependent operation
//! can be executed.
//!
//! Data format:
//!   op_N_predecessor=<op_id>    (0 means no predecessor)

use crate::foundation::config::*;
use crate::foundation::data::*;
use crate::foundation::parse::*;
use crate::governance::governor::build_prop_key;
use crate::timelock::controller;

/// Schedule an operation with a predecessor dependency.
/// Mirrors TimelockController.schedule() with predecessor parameter.
pub fn schedule_with_predecessor(
    data: &[u8],
    data_len: usize,
    proposal_id: u32,
    predecessor_op_id: u32,
    current_time: u32,
    delay: u32,
) -> Result<([u8; 4096], usize, u32), i32> {
    // Schedule the base operation
    let (mut new_data, mut pos, op_id) =
        controller::schedule(data, data_len, proposal_id, current_time, delay)?;

    // Append predecessor reference
    let op_count = find_value(&new_data[..pos], b"op_count")
        .and_then(parse_u8_digit)
        .unwrap_or(0);

    let op_index = op_count - 1; // just-added operation

    let mut key_buf = [0u8; 32];
    let klen = build_prop_key(b"op_", op_index, b"_predecessor", &mut key_buf);
    let mut val_buf = [0u8; 10];
    let vlen = format_u32(predecessor_op_id, &mut val_buf);

    if pos > 0 { pos = crate::foundation::data::write_separator(&mut new_data, pos); }
    pos = crate::foundation::data::write_entry(&mut new_data, pos, &key_buf[..klen], &val_buf[..vlen]);

    Ok((new_data, pos, op_id))
}

/// Execute an operation, checking predecessor dependencies.
/// Enhanced version of controller::execute() that verifies predecessors.
pub fn execute_with_predecessor_check(
    data: &[u8],
    data_len: usize,
    operation_index: u8,
    current_time: u32,
) -> Result<([u8; 4096], usize), i32> {
    // Check predecessor is done (if any)
    let mut key_buf = [0u8; 32];
    let klen = build_prop_key(b"op_", operation_index, b"_predecessor", &mut key_buf);

    if let Some(pred_val) = find_value(data, &key_buf[..klen]) {
        let pred_id = parse_u32(pred_val).unwrap_or(0);
        if pred_id != 0 {
            // Find predecessor operation and check it's Done
            if !is_predecessor_done(data, pred_id, current_time) {
                return Err(ERR_OP_NOT_READY);
            }
        }
    }

    // Delegate to base execute
    controller::execute(data, data_len, operation_index, current_time)
}

/// Check if a predecessor operation (by op_id) is in Done state.
fn is_predecessor_done(data: &[u8], predecessor_op_id: u32, _current_time: u32) -> bool {
    let op_count = find_value(data, b"op_count")
        .and_then(parse_u8_digit)
        .unwrap_or(0);

    let mut key_buf = [0u8; 32];
    let mut id_buf = [0u8; 10];
    let id_len = format_u32(predecessor_op_id, &mut id_buf);

    for i in 0..op_count {
        let klen = build_prop_key(b"op_", i, b"_id", &mut key_buf);
        if let Some(stored_id) = find_value(data, &key_buf[..klen]) {
            if stored_id == &id_buf[..id_len] {
                return controller::is_operation_done(data, i);
            }
        }
    }
    false
}

/// Get the predecessor operation ID for a given operation.
/// Returns 0 if no predecessor.
pub fn get_predecessor(data: &[u8], operation_index: u8) -> u32 {
    let mut key_buf = [0u8; 32];
    let klen = build_prop_key(b"op_", operation_index, b"_predecessor", &mut key_buf);
    find_value(data, &key_buf[..klen])
        .and_then(|v| parse_u32(v))
        .unwrap_or(0)
}
