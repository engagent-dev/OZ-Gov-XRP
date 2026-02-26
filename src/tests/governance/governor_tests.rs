use crate::foundation::config::*;
use crate::governance::governor::*;
use crate::tests::*;

// ═══════════════════════════════════════════════════════════════════════
// propose() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_propose_success() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER | ROLE_ADMIN),
        (&bob(), 100_000_000, 0),
    ]);

    let result = propose(
        &data[..len], len, &alice(),
        12345, 1000, 200_000_000,
    );
    assert!(result.is_ok());

    let (new_data, new_len, prop_id) = result.unwrap();
    assert!(prop_id != 0);

    // Verify proposal was stored
    let idx = find_proposal_by_id(&new_data[..new_len], prop_id);
    assert!(idx.is_ok());
    assert_eq!(idx.unwrap(), 0);
}

#[test]
fn test_propose_below_threshold() {
    let (data, len) = build_dao_data(&[
        (&alice(), 50_000_000, ROLE_PROPOSER), // 50 XRP < 100 XRP threshold
    ]);

    let result = propose(
        &data[..len], len, &alice(),
        12345, 1000, 50_000_000,
    );
    assert_eq!(result, Err(ERR_BELOW_THRESHOLD));
}

#[test]
fn test_propose_at_exact_threshold() {
    let (data, len) = build_dao_data(&[
        (&alice(), PROPOSAL_THRESHOLD, ROLE_PROPOSER),
    ]);

    let result = propose(
        &data[..len], len, &alice(),
        12345, 1000, PROPOSAL_THRESHOLD,
    );
    assert!(result.is_ok());
}

#[test]
fn test_propose_multiple() {
    let (data, len) = build_dao_data(&[
        (&alice(), 500_000_000, ROLE_PROPOSER | ROLE_ADMIN),
    ]);

    // First proposal
    let (data1, len1, id1) = propose(
        &data[..len], len, &alice(), 111, 1000, 500_000_000,
    ).unwrap();

    // Second proposal
    let (data2, len2, id2) = propose(
        &data1[..len1], len1, &alice(), 222, 2000, 500_000_000,
    ).unwrap();

    assert_ne!(id1, id2);
    assert!(find_proposal_by_id(&data2[..len2], id1).is_ok());
    assert!(find_proposal_by_id(&data2[..len2], id2).is_ok());
}

// ═══════════════════════════════════════════════════════════════════════
// get_proposal_state() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_state_pending_before_vote_start() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER | ROLE_ADMIN),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(),
        1300, // vote_start
        260500, // vote_end
        0, // stored state = Pending
    );

    let state = get_proposal_state(&data[..len], 0, 1000, 300_000_000);
    assert_eq!(state, PROPOSAL_STATE_PENDING);
}

#[test]
fn test_state_active_during_voting() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let state = get_proposal_state(&data[..len], 0, 5000, 300_000_000);
    assert_eq!(state, PROPOSAL_STATE_ACTIVE);
}

#[test]
fn test_state_defeated_no_quorum() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 2000, 0,
    );

    // After voting ends, no votes cast → no quorum → defeated
    let state = get_proposal_state(&data[..len], 0, 3000, 300_000_000);
    assert_eq!(state, PROPOSAL_STATE_DEFEATED);
}

#[test]
fn test_state_canceled_overrides_time() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000,
        PROPOSAL_STATE_CANCELED, // explicitly canceled
    );

    // Even though time says Active, stored Canceled wins
    let state = get_proposal_state(&data[..len], 0, 5000, 200_000_000);
    assert_eq!(state, PROPOSAL_STATE_CANCELED);
}

#[test]
fn test_state_executed_overrides() {
    let members = [(&alice(), 200_000_000u64, ROLE_PROPOSER)];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 2000,
        PROPOSAL_STATE_EXECUTED,
    );

    let state = get_proposal_state(&data[..len], 0, 5000, 200_000_000);
    assert_eq!(state, PROPOSAL_STATE_EXECUTED);
}

// ═══════════════════════════════════════════════════════════════════════
// cancel_proposal() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_cancel_by_proposer() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
    ];
    // vote_start far in future so state is Pending
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 5000, 265000, 0,
    );

    let result = cancel_proposal(&data[..len], len, 0, &alice(), 1000, 200_000_000);
    assert!(result.is_ok());

    let (new_data, new_len) = result.unwrap();
    let state = get_proposal_state(&new_data[..new_len], 0, 1000, 200_000_000);
    assert_eq!(state, PROPOSAL_STATE_CANCELED);
}

#[test]
fn test_cancel_by_non_proposer_fails() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 5000, 265000, 0,
    );

    let result = cancel_proposal(&data[..len], len, 0, &bob(), 1000, 300_000_000);
    assert_eq!(result, Err(ERR_NOT_PROPOSER));
}

#[test]
fn test_cancel_active_proposal_fails() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
    ];
    // vote_start=1000, current_time=2000 → Active
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let result = cancel_proposal(&data[..len], len, 0, &alice(), 2000, 200_000_000);
    assert_eq!(result, Err(ERR_PROPOSAL_NOT_ACTIVE));
}

// ═══════════════════════════════════════════════════════════════════════
// Helper function tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_build_prop_key() {
    let mut buf = [0u8; 32];
    let len = build_prop_key(b"prop_", 0, b"_state", &mut buf);
    assert_eq!(&buf[..len], b"prop_0_state");

    let len = build_prop_key(b"prop_", 3, b"_for", &mut buf);
    assert_eq!(&buf[..len], b"prop_3_for");
}

#[test]
fn test_find_proposal_not_found() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, 0)]);
    assert_eq!(find_proposal_by_id(&data[..len], 999), Err(ERR_PROPOSAL_NOT_FOUND));
}
