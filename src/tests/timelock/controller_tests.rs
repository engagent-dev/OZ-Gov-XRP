use crate::foundation::config::*;
use crate::foundation::data::*;
use crate::foundation::parse::*;
use crate::timelock::controller::*;
use crate::governance::governor::build_prop_key;
use crate::tests::*;

/// Helper: build DAO data with a timelock operation already scheduled.
fn build_dao_with_operation(
    members: &[(&[u8; ACCOUNT_ID_SIZE], u64, u8)],
    proposal_id: u32,
    op_id: u32,
    ready_at: u32,
    op_state: u8,
) -> ([u8; 4096], usize) {
    let (base, base_len) = build_dao_data(members);
    let mut data = [0u8; 4096];
    data[..base_len].copy_from_slice(&base[..base_len]);
    let mut pos = base_len;

    let mut key_buf = [0u8; 32];
    let mut val_buf = [0u8; 20];

    // op_count=1
    pos = write_separator(&mut data, pos);
    pos = write_entry(&mut data, pos, b"op_count", b"1");

    // op_0_id
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"op_", 0, b"_id", &mut key_buf);
    let vlen = format_u32(op_id, &mut val_buf);
    pos = write_entry(&mut data, pos, &key_buf[..klen], &val_buf[..vlen]);

    // op_0_prop
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"op_", 0, b"_prop", &mut key_buf);
    let vlen = format_u32(proposal_id, &mut val_buf);
    pos = write_entry(&mut data, pos, &key_buf[..klen], &val_buf[..vlen]);

    // op_0_ready
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"op_", 0, b"_ready", &mut key_buf);
    let vlen = format_u32(ready_at, &mut val_buf);
    pos = write_entry(&mut data, pos, &key_buf[..klen], &val_buf[..vlen]);

    // op_0_state
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"op_", 0, b"_state", &mut key_buf);
    let state_val = [b'0' + op_state];
    pos = write_entry(&mut data, pos, &key_buf[..klen], &state_val);

    (data, pos)
}

// ═══════════════════════════════════════════════════════════════════════
// schedule() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_schedule_success() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER | ROLE_ADMIN),
    ]);

    let result = schedule(&data[..len], len, 42, 1000, TIMELOCK_MIN_DELAY);
    assert!(result.is_ok());

    let (new_data, new_len, op_id) = result.unwrap();
    assert!(op_id != 0);

    // Verify operation was stored
    let found = find_operation_by_proposal(&new_data[..new_len], 42);
    assert!(found.is_ok());
}

#[test]
fn test_schedule_delay_too_short() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    let result = schedule(&data[..len], len, 42, 1000, TIMELOCK_MIN_DELAY - 1);
    assert_eq!(result, Err(ERR_TOO_EARLY));
}

#[test]
fn test_schedule_duplicate_rejected() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    // First schedule succeeds
    let (data1, len1, _) = schedule(&data[..len], len, 42, 1000, TIMELOCK_MIN_DELAY).unwrap();

    // Second schedule for same proposal fails
    let result = schedule(&data1[..len1], len1, 42, 2000, TIMELOCK_MIN_DELAY);
    assert_eq!(result, Err(ERR_OP_ALREADY_QUEUED));
}

#[test]
fn test_schedule_sets_correct_ready_time() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    let current_time = 1000;
    let (new_data, new_len, _) = schedule(
        &data[..len], len, 42, current_time, TIMELOCK_MIN_DELAY,
    ).unwrap();

    let expected_ready = current_time + TIMELOCK_MIN_DELAY;
    let actual_ready = get_timestamp(&new_data[..new_len], 0);
    assert_eq!(actual_ready, expected_ready);
}

// ═══════════════════════════════════════════════════════════════════════
// Operation state tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_state_pending_before_ready() {
    let ready_at = 200_000;
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, ROLE_ADMIN)],
        42, 99, ready_at, OP_STATE_PENDING,
    );

    let state = get_operation_state(&data[..len], 0, 100_000); // before ready_at
    assert_eq!(state, OP_STATE_PENDING);
    assert!(is_operation_pending(&data[..len], 0, 100_000));
    assert!(!is_operation_ready(&data[..len], 0, 100_000));
}

#[test]
fn test_state_ready_after_timer() {
    let ready_at = 200_000;
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, ROLE_ADMIN)],
        42, 99, ready_at, OP_STATE_PENDING,
    );

    let state = get_operation_state(&data[..len], 0, 200_001); // after ready_at
    assert_eq!(state, OP_STATE_READY);
    assert!(is_operation_ready(&data[..len], 0, 200_001));
}

#[test]
fn test_state_ready_at_exact_time() {
    let ready_at = 200_000;
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, ROLE_ADMIN)],
        42, 99, ready_at, OP_STATE_PENDING,
    );

    let state = get_operation_state(&data[..len], 0, ready_at); // exactly at ready_at
    assert_eq!(state, OP_STATE_READY);
}

#[test]
fn test_state_done() {
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, ROLE_ADMIN)],
        42, 99, 200_000, OP_STATE_DONE,
    );

    assert!(is_operation_done(&data[..len], 0));
    assert_eq!(get_operation_state(&data[..len], 0, 300_000), OP_STATE_DONE);
}

// ═══════════════════════════════════════════════════════════════════════
// execute() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_execute_ready_operation() {
    let ready_at = 200_000;
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, ROLE_ADMIN | ROLE_EXECUTOR)],
        42, 99, ready_at, OP_STATE_PENDING,
    );

    let result = execute(&data[..len], len, 0, 200_001);
    assert!(result.is_ok());

    let (new_data, new_len) = result.unwrap();
    assert!(is_operation_done(&new_data[..new_len], 0));
}

#[test]
fn test_execute_pending_fails() {
    let ready_at = 200_000;
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, ROLE_ADMIN | ROLE_EXECUTOR)],
        42, 99, ready_at, OP_STATE_PENDING,
    );

    // Try to execute before ready
    let result = execute(&data[..len], len, 0, 100_000);
    assert_eq!(result, Err(ERR_OP_NOT_READY));
}

#[test]
fn test_execute_already_done_fails() {
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, ROLE_ADMIN | ROLE_EXECUTOR)],
        42, 99, 200_000, OP_STATE_DONE,
    );

    let result = execute(&data[..len], len, 0, 300_000);
    assert_eq!(result, Err(ERR_OP_NOT_READY));
}

// ═══════════════════════════════════════════════════════════════════════
// cancel() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_cancel_pending_operation() {
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, ROLE_ADMIN)],
        42, 99, 200_000, OP_STATE_PENDING,
    );

    let result = cancel(&data[..len], len, 0, 100_000);
    assert!(result.is_ok());

    let (new_data, new_len) = result.unwrap();
    let state = get_operation_state(&new_data[..new_len], 0, 300_000);
    assert_eq!(state, OP_STATE_UNSET);
}

#[test]
fn test_cancel_done_fails() {
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, ROLE_ADMIN)],
        42, 99, 200_000, OP_STATE_DONE,
    );

    let result = cancel(&data[..len], len, 0, 300_000);
    assert_eq!(result, Err(ERR_OP_NOT_READY));
}

// ═══════════════════════════════════════════════════════════════════════
// find_operation_by_proposal() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_find_operation_found() {
    let (data, len) = build_dao_with_operation(
        &[(&alice(), 200_000_000, 0)],
        42, 99, 200_000, OP_STATE_PENDING,
    );

    assert_eq!(find_operation_by_proposal(&data[..len], 42), Ok(0));
}

#[test]
fn test_find_operation_not_found() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, 0)]);
    assert_eq!(find_operation_by_proposal(&data[..len], 999), Err(ERR_PROPOSAL_NOT_FOUND));
}

// ═══════════════════════════════════════════════════════════════════════
// Full schedule → execute lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_full_timelock_lifecycle() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER | ROLE_ADMIN | ROLE_EXECUTOR),
    ]);

    // Schedule
    let schedule_time = 1000;
    let (d1, l1, _op_id) = schedule(
        &data[..len], len, 42, schedule_time, TIMELOCK_MIN_DELAY,
    ).unwrap();

    let op_idx = find_operation_by_proposal(&d1[..l1], 42).unwrap();
    assert!(is_operation_pending(&d1[..l1], op_idx, schedule_time + 1000));

    // Try execute too early — fails
    let early = schedule_time + TIMELOCK_MIN_DELAY - 1;
    assert!(execute(&d1[..l1], l1, op_idx, early).is_err());

    // Execute after delay — succeeds
    let late = schedule_time + TIMELOCK_MIN_DELAY + 1;
    let (d2, l2) = execute(&d1[..l1], l1, op_idx, late).unwrap();
    assert!(is_operation_done(&d2[..l2], op_idx));
}
