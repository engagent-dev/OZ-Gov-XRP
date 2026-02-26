use crate::foundation::config::*;
use crate::timelock::controller;
use crate::timelock::operations::*;
use crate::tests::*;

// ═══════════════════════════════════════════════════════════════════════
// schedule_with_predecessor() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_schedule_with_predecessor() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER | ROLE_ADMIN),
    ]);

    // Schedule first operation
    let (d1, l1, op1_id) = controller::schedule(
        &data[..len], len, 100, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    // Schedule second with predecessor
    let result = schedule_with_predecessor(
        &d1[..l1], l1, 200, op1_id, 2000, TIMELOCK_MIN_DELAY,
    );
    assert!(result.is_ok());

    let (d2, l2, _op2_id) = result.unwrap();

    // Verify predecessor is recorded
    let pred = get_predecessor(&d2[..l2], 1); // op index 1
    assert_eq!(pred, op1_id);
}

#[test]
fn test_predecessor_zero_means_none() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    // Schedule without predecessor — predecessor field won't exist
    let (d1, l1, _) = controller::schedule(
        &data[..len], len, 100, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    let pred = get_predecessor(&d1[..l1], 0);
    assert_eq!(pred, 0); // no predecessor
}

// ═══════════════════════════════════════════════════════════════════════
// execute_with_predecessor_check() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_execute_blocked_by_predecessor() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_ADMIN | ROLE_EXECUTOR),
    ]);

    // Schedule op1
    let (d1, l1, op1_id) = controller::schedule(
        &data[..len], len, 100, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    // Schedule op2 with op1 as predecessor
    let (d2, l2, _op2_id) = schedule_with_predecessor(
        &d1[..l1], l1, 200, op1_id, 2000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    // Try to execute op2 while op1 is still pending (not done)
    let exec_time = 2000 + TIMELOCK_MIN_DELAY + 1;
    let result = execute_with_predecessor_check(&d2[..l2], l2, 1, exec_time);
    assert_eq!(result, Err(ERR_OP_NOT_READY));
}

#[test]
fn test_execute_after_predecessor_done() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_ADMIN | ROLE_EXECUTOR),
    ]);

    // Schedule op1
    let (d1, l1, op1_id) = controller::schedule(
        &data[..len], len, 100, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    // Schedule op2 with predecessor
    let (d2, l2, _) = schedule_with_predecessor(
        &d1[..l1], l1, 200, op1_id, 2000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    // Execute op1 first
    let exec_time1 = 1000 + TIMELOCK_MIN_DELAY + 1;
    let (d3, l3) = controller::execute(&d2[..l2], l2, 0, exec_time1).unwrap();

    // Now execute op2 — predecessor is done, should succeed
    let exec_time2 = 2000 + TIMELOCK_MIN_DELAY + 1;
    let result = execute_with_predecessor_check(&d3[..l3], l3, 1, exec_time2);
    assert!(result.is_ok());
}

#[test]
fn test_execute_no_predecessor_works() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_ADMIN | ROLE_EXECUTOR),
    ]);

    let (d1, l1, _) = controller::schedule(
        &data[..len], len, 100, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    // No predecessor → execute directly
    let exec_time = 1000 + TIMELOCK_MIN_DELAY + 1;
    let result = execute_with_predecessor_check(&d1[..l1], l1, 0, exec_time);
    assert!(result.is_ok());
}
