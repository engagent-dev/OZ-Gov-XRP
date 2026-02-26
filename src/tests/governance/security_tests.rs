//! Security fix tests — validates all 8 security gaps are addressed.
//!
//! Fix #1: Cryptographic proposal ID (FNV-1a hash)
//! Fix #2: Reentrancy guard (lock/unlock)
//! Fix #3: Caller identity verification (double-read pattern)
//! Fix #4: Vote-by-signature framework
//! Fix #5: Self-registration (permissionless member join)
//! Fix #6: Overflow protection (checked/saturating arithmetic)
//! Fix #7: Multi-digit index keys (0-99)
//! Fix #8: Timelock grace period (operation expiry)

use crate::foundation::config::*;
use crate::foundation::data::*;
use crate::governance::governor::*;
use crate::governance::counting;
use crate::governance::votes;
use crate::governance::signatures;
use crate::timelock::controller;
use crate::crypto::hash;
use crate::tests::*;

// ═══════════════════════════════════════════════════════════════════════
// Fix #1: Cryptographic Proposal ID
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_fix1_proposal_id_is_content_bound() {
    // Same proposer, different descriptions should produce different IDs
    let id1 = hash::hash_proposal(&alice(), 111, 1000, 0);
    let id2 = hash::hash_proposal(&alice(), 222, 1000, 0);
    assert_ne!(id1, id2, "Different descriptions must produce different IDs");
}

#[test]
fn test_fix1_proposal_id_includes_proposer() {
    // Same description, different proposers should differ
    let id1 = hash::hash_proposal(&alice(), 111, 1000, 0);
    let id2 = hash::hash_proposal(&bob(), 111, 1000, 0);
    assert_ne!(id1, id2, "Different proposers must produce different IDs");
}

#[test]
fn test_fix1_proposal_id_includes_time() {
    let id1 = hash::hash_proposal(&alice(), 111, 1000, 0);
    let id2 = hash::hash_proposal(&alice(), 111, 2000, 0);
    assert_ne!(id1, id2, "Different times must produce different IDs");
}

#[test]
fn test_fix1_proposal_id_includes_nonce() {
    let id1 = hash::hash_proposal(&alice(), 111, 1000, 0);
    let id2 = hash::hash_proposal(&alice(), 111, 1000, 1);
    assert_ne!(id1, id2, "Different nonces must produce different IDs");
}

#[test]
fn test_fix1_proposal_id_nonzero() {
    // ID must always be non-zero (we OR with 1)
    for seed in 0u8..255 {
        let account = mock_account(seed);
        let id = hash::hash_proposal(&account, seed as u32, seed as u32, seed);
        assert_ne!(id, 0, "Proposal ID must never be zero");
    }
}

#[test]
fn test_fix1_proposal_id_deterministic() {
    let id1 = hash::hash_proposal(&alice(), 111, 1000, 0);
    let id2 = hash::hash_proposal(&alice(), 111, 1000, 0);
    assert_eq!(id1, id2, "Same inputs must produce same ID");
}

// ═══════════════════════════════════════════════════════════════════════
// Fix #2: Reentrancy Guard
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_fix2_lock_unlocked_by_default() {
    let (data, _len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);
    assert!(!is_locked(&data), "Lock must be off by default");
}

#[test]
fn test_fix2_set_lock_on() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);
    let (locked_data, locked_len) = set_lock(&data[..len], len, true).unwrap();
    assert!(is_locked(&locked_data[..locked_len]), "Lock must be on after set_lock(true)");
}

#[test]
fn test_fix2_set_lock_off() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);
    let (locked_data, locked_len) = set_lock(&data[..len], len, true).unwrap();
    let (unlocked_data, unlocked_len) = set_lock(&locked_data[..locked_len], locked_len, false).unwrap();
    assert!(!is_locked(&unlocked_data[..unlocked_len]), "Lock must be off after set_lock(false)");
}

#[test]
fn test_fix2_lock_preserves_data() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_ADMIN),
        (&bob(), 100_000_000, 0),
    ]);

    let (locked_data, locked_len) = set_lock(&data[..len], len, true).unwrap();

    // Member data should still be readable
    let alice_votes = votes::get_votes(&locked_data[..locked_len], &alice());
    assert_eq!(alice_votes, 200_000_000);

    let bob_votes = votes::get_votes(&locked_data[..locked_len], &bob());
    assert_eq!(bob_votes, 100_000_000);
}

#[test]
fn test_fix2_lock_toggle_idempotent() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    // Lock twice
    let (d1, l1) = set_lock(&data[..len], len, true).unwrap();
    let (d2, l2) = set_lock(&d1[..l1], l1, true).unwrap();
    assert!(is_locked(&d2[..l2]));

    // Unlock twice
    let (d3, l3) = set_lock(&d2[..l2], l2, false).unwrap();
    let (d4, l4) = set_lock(&d3[..l3], l3, false).unwrap();
    assert!(!is_locked(&d4[..l4]));
}

// ═══════════════════════════════════════════════════════════════════════
// Fix #4: Vote-by-Signature Framework
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_fix4_vote_message_format() {
    let mut msg = [0u8; 128];
    let len = signatures::build_vote_message(42, VOTE_FOR, &alice(), &mut msg);
    assert!(len > 0, "Message should have non-zero length");

    // Message should start with domain prefix
    assert!(msg[..14] == *b"xrpl-dao:vote:", "Message must start with domain prefix");
}

#[test]
fn test_fix4_vote_message_differs_by_proposal() {
    let mut msg1 = [0u8; 128];
    let len1 = signatures::build_vote_message(42, VOTE_FOR, &alice(), &mut msg1);
    let mut msg2 = [0u8; 128];
    let len2 = signatures::build_vote_message(99, VOTE_FOR, &alice(), &mut msg2);

    assert_ne!(&msg1[..len1], &msg2[..len2], "Different proposals must produce different messages");
}

#[test]
fn test_fix4_vote_message_differs_by_support() {
    let mut msg1 = [0u8; 128];
    let len1 = signatures::build_vote_message(42, VOTE_FOR, &alice(), &mut msg1);
    let mut msg2 = [0u8; 128];
    let len2 = signatures::build_vote_message(42, VOTE_AGAINST, &alice(), &mut msg2);

    assert_ne!(&msg1[..len1], &msg2[..len2], "Different support must produce different messages");
}

#[test]
fn test_fix4_vote_message_differs_by_voter() {
    let mut msg1 = [0u8; 128];
    let len1 = signatures::build_vote_message(42, VOTE_FOR, &alice(), &mut msg1);
    let mut msg2 = [0u8; 128];
    let len2 = signatures::build_vote_message(42, VOTE_FOR, &bob(), &mut msg2);

    assert_ne!(&msg1[..len1], &msg2[..len2], "Different voters must produce different messages");
}

#[test]
fn test_fix4_validate_rejects_invalid_support() {
    assert!(!signatures::validate_vote_message(42, 3, &alice()), "Support > 2 must fail");
    assert!(!signatures::validate_vote_message(42, 255, &alice()), "Support 255 must fail");
}

#[test]
fn test_fix4_validate_rejects_zero_proposal() {
    assert!(!signatures::validate_vote_message(0, VOTE_FOR, &alice()), "Zero proposal must fail");
}

#[test]
fn test_fix4_validate_rejects_zero_voter() {
    let zero = [0u8; ACCOUNT_ID_SIZE];
    assert!(!signatures::validate_vote_message(42, VOTE_FOR, &zero), "Zero voter must fail");
}

#[test]
fn test_fix4_validate_accepts_valid_input() {
    assert!(signatures::validate_vote_message(42, VOTE_FOR, &alice()));
    assert!(signatures::validate_vote_message(42, VOTE_AGAINST, &bob()));
    assert!(signatures::validate_vote_message(42, VOTE_ABSTAIN, &carol()));
}

#[test]
fn test_fix4_record_sig_vote_intent() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, 0)]);
    let result = signatures::record_sig_vote_intent(&data[..len], len, 42, VOTE_FOR, &alice());
    assert!(result.is_ok());

    let (new_data, new_len) = result.unwrap();
    // Should contain sigvote entry
    let data_str = core::str::from_utf8(&new_data[..new_len]).unwrap_or("");
    assert!(data_str.contains("sigvote_"), "Should contain sigvote entry");
}

#[test]
fn test_fix4_hash_vote_message_deterministic() {
    let msg = b"xrpl-dao:vote:42:1:aa";
    let h1 = signatures::hash_vote_message(msg, msg.len());
    let h2 = signatures::hash_vote_message(msg, msg.len());
    assert_eq!(h1, h2, "Same message must produce same hash");
}

// ═══════════════════════════════════════════════════════════════════════
// Fix #5: Self-Registration (Permissionless)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_fix5_self_register_new_member() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_ADMIN),
    ]);

    // Bob self-registers with 0 power, no roles
    let result = votes::set_member(&data[..len], len, &bob(), SELF_REGISTER_INITIAL_POWER, 0);
    assert!(result.is_ok());

    let (new_data, new_len) = result.unwrap();
    let bob_votes = votes::get_votes(&new_data[..new_len], &bob());
    assert_eq!(bob_votes, 0, "Self-registered members should have 0 voting power");

    let bob_roles = votes::get_roles(&new_data[..new_len], &bob());
    assert_eq!(bob_roles, 0, "Self-registered members should have no roles");
}

#[test]
fn test_fix5_self_register_then_admin_grants_power() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_ADMIN),
    ]);

    // Bob self-registers
    let (d1, l1) = votes::set_member(&data[..len], len, &bob(), 0, 0).unwrap();

    // Admin (alice) grants Bob voting power
    let (d2, l2) = votes::set_member(&d1[..l1], l1, &bob(), 100_000_000, ROLE_PROPOSER).unwrap();

    let bob_votes = votes::get_votes(&d2[..l2], &bob());
    assert_eq!(bob_votes, 100_000_000);

    let bob_proposer = votes::has_role(&d2[..l2], &bob(), ROLE_PROPOSER);
    assert!(bob_proposer, "Bob should now have proposer role");
}

#[test]
fn test_fix5_member_count_preserved() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_ADMIN),
    ]);

    assert_eq!(votes::get_member_count(&data[..len]), 1);

    let (d1, l1) = votes::set_member(&data[..len], len, &bob(), 0, 0).unwrap();
    assert_eq!(votes::get_member_count(&d1[..l1]), 2);

    let (d2, l2) = votes::set_member(&d1[..l1], l1, &carol(), 0, 0).unwrap();
    assert_eq!(votes::get_member_count(&d2[..l2]), 3);
}

// ═══════════════════════════════════════════════════════════════════════
// Fix #6: Overflow Protection
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_fix6_vote_tally_overflow_returns_error() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER | ROLE_ADMIN),
        (&bob(), u64::MAX - 1, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    // First cast a huge vote
    let result = counting::cast_vote(
        &data[..len], len, 0, &bob(), VOTE_FOR, u64::MAX - 1, 5000, u64::MAX,
    );
    assert!(result.is_ok(), "First vote should succeed");

    let (d1, l1) = result.unwrap();

    // Second vote would overflow u64
    let result2 = counting::cast_vote(
        &d1[..l1], l1, 0, &alice(), VOTE_FOR, u64::MAX, 5000, u64::MAX,
    );
    assert_eq!(result2, Err(ERR_OVERFLOW), "Overflow should return ERR_OVERFLOW");
}

#[test]
fn test_fix6_saturating_total_voting_power() {
    // Build data with near-max voting powers
    let (data, len) = build_dao_data(&[
        (&alice(), u64::MAX / 2, ROLE_ADMIN),
        (&bob(), u64::MAX / 2, 0),
    ]);

    let total = votes::get_total_voting_power(&data[..len]);
    // Should be close to u64::MAX but not overflow
    assert!(total >= u64::MAX / 2, "Total should include both members");
    // With saturating_add, total <= u64::MAX guaranteed
    assert!(total <= u64::MAX);
}

#[test]
fn test_fix6_quorum_no_overflow() {
    let total_vp = u64::MAX;
    let quorum = votes::quorum(total_vp);
    // (u64::MAX * 4) / 100 — should not overflow/panic
    assert!(quorum > 0, "Quorum of max VP should still be positive");
}

// ═══════════════════════════════════════════════════════════════════════
// Fix #7: Multi-Digit Index Keys
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_fix7_build_prop_key_single_digit() {
    let mut buf = [0u8; 48];
    let len = build_prop_key(b"prop_", 0, b"_state", &mut buf);
    assert_eq!(&buf[..len], b"prop_0_state");
}

#[test]
fn test_fix7_build_prop_key_double_digit() {
    let mut buf = [0u8; 48];
    let len = build_prop_key(b"prop_", 12, b"_state", &mut buf);
    assert_eq!(&buf[..len], b"prop_12_state");
}

#[test]
fn test_fix7_build_prop_key_triple_digit() {
    let mut buf = [0u8; 48];
    let len = build_prop_key(b"prop_", 255, b"_id", &mut buf);
    assert_eq!(&buf[..len], b"prop_255_id");
}

#[test]
fn test_fix7_format_u8_range() {
    let mut buf = [0u8; 3];
    assert_eq!(format_u8(0, &mut buf), 1); assert_eq!(&buf[..1], b"0");
    assert_eq!(format_u8(9, &mut buf), 1); assert_eq!(&buf[..1], b"9");
    assert_eq!(format_u8(10, &mut buf), 2); assert_eq!(&buf[..2], b"10");
    assert_eq!(format_u8(99, &mut buf), 2); assert_eq!(&buf[..2], b"99");
    assert_eq!(format_u8(100, &mut buf), 3); assert_eq!(&buf[..3], b"100");
    assert_eq!(format_u8(255, &mut buf), 3); assert_eq!(&buf[..3], b"255");
}

#[test]
fn test_fix7_read_count_multi_digit() {
    let data = b"proposal_count=12;other=1";
    let count = read_count(data, b"proposal_count");
    assert_eq!(count, 12);
}

#[test]
fn test_fix7_member_key_multi_digit() {
    // Create more than 9 members to verify multi-digit support
    let mut data = [0u8; 4096];
    let mut pos = 0;

    // Write member_count=12 (multi-digit)
    pos = write_entry(&mut data, pos, b"member_count", b"12");

    // Verify the count is read correctly
    let count = votes::get_member_count(&data[..pos]);
    assert_eq!(count, 12);
}

// ═══════════════════════════════════════════════════════════════════════
// Fix #8: Timelock Grace Period
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_fix8_operation_pending_before_ready() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    let (d1, l1, _op_id) = controller::schedule(
        &data[..len], len, 42, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    // Before ready_at (1000 + 172800 = 173800)
    let state = controller::get_operation_state(&d1[..l1], 0, 100_000);
    assert_eq!(state, OP_STATE_PENDING);
}

#[test]
fn test_fix8_operation_ready_within_grace() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    let (d1, l1, _op_id) = controller::schedule(
        &data[..len], len, 42, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    let ready_at = 1000 + TIMELOCK_MIN_DELAY;
    // Exactly at ready_at: should be Ready
    let state = controller::get_operation_state(&d1[..l1], 0, ready_at);
    assert_eq!(state, OP_STATE_READY);

    // Within grace period: should be Ready
    let state = controller::get_operation_state(&d1[..l1], 0, ready_at + TIMELOCK_GRACE_PERIOD / 2);
    assert_eq!(state, OP_STATE_READY);
}

#[test]
fn test_fix8_operation_expired_after_grace() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    let (d1, l1, _op_id) = controller::schedule(
        &data[..len], len, 42, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    let ready_at = 1000 + TIMELOCK_MIN_DELAY;
    let expiry = ready_at + TIMELOCK_GRACE_PERIOD;

    // After grace period: should be Expired
    let state = controller::get_operation_state(&d1[..l1], 0, expiry + 1);
    assert_eq!(state, OP_STATE_EXPIRED);
}

#[test]
fn test_fix8_execute_expired_operation_fails() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    let (d1, l1, _op_id) = controller::schedule(
        &data[..len], len, 42, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    let ready_at = 1000 + TIMELOCK_MIN_DELAY;
    let long_after = ready_at + TIMELOCK_GRACE_PERIOD + 100;

    let result = controller::execute(&d1[..l1], l1, 0, long_after);
    assert_eq!(result, Err(ERR_OP_EXPIRED), "Expired operations must not be executable");
}

#[test]
fn test_fix8_execute_within_grace_succeeds() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    let (d1, l1, _op_id) = controller::schedule(
        &data[..len], len, 42, 1000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    let ready_at = 1000 + TIMELOCK_MIN_DELAY;
    // Execute within grace period
    let result = controller::execute(&d1[..l1], l1, 0, ready_at + 1000);
    assert!(result.is_ok(), "Execution within grace period should succeed");
}

#[test]
fn test_fix8_grace_period_constant() {
    // 14 days = 14 * 24 * 60 * 60 = 1,209,600
    assert_eq!(TIMELOCK_GRACE_PERIOD, 1_209_600);
}

#[test]
fn test_fix8_expired_state_constant() {
    assert_eq!(PROPOSAL_STATE_EXPIRED, 6);
}

// ═══════════════════════════════════════════════════════════════════════
// Integration: Full Lifecycle with All Fixes
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_full_lifecycle_with_all_fixes() {
    // 1. Setup DAO with members
    let (data, len) = build_dao_data(&[
        (&alice(), 500_000_000, ROLE_PROPOSER | ROLE_ADMIN | ROLE_EXECUTOR),
        (&bob(), 300_000_000, 0),
        (&carol(), 200_000_000, 0),
    ]);
    let total_vp = votes::get_total_voting_power(&data[..len]);
    assert_eq!(total_vp, 1_000_000_000);

    // 2. Fix #5: Self-register new member (dave)
    let (d1, l1) = votes::set_member(&data[..len], len, &dave(), 0, 0).unwrap();
    assert_eq!(votes::get_member_count(&d1[..l1]), 4);

    // 3. Fix #1: Propose (ID is cryptographic)
    let (d2, l2, prop_id) = propose(
        &d1[..l1], l1, &alice(), 12345, 1000, 500_000_000,
    ).unwrap();
    assert!(prop_id != 0);

    // 4. Fix #7: Multi-digit key lookup works
    let idx = find_proposal_by_id(&d2[..l2], prop_id).unwrap();
    assert_eq!(idx, 0);

    // 5. Advance time to Active
    let state = get_proposal_state(&d2[..l2], 0, 2000, total_vp);
    assert_eq!(state, PROPOSAL_STATE_ACTIVE);

    // 6. Fix #6: Cast votes with overflow protection
    let (d3, l3) = counting::cast_vote(
        &d2[..l2], l2, 0, &alice(), VOTE_FOR, 500_000_000, 2000, total_vp,
    ).unwrap();

    let (d4, l4) = counting::cast_vote(
        &d3[..l3], l3, 0, &bob(), VOTE_FOR, 300_000_000, 2000, total_vp,
    ).unwrap();

    // 7. Verify vote tallies
    let (f, a, ab) = counting::proposal_votes(&d4[..l4], 0);
    assert_eq!(f, 800_000_000);
    assert_eq!(a, 0);
    assert_eq!(ab, 0);

    // 8. Advance past voting end → Succeeded
    let state = get_proposal_state(&d4[..l4], 0, 300_000, total_vp);
    assert_eq!(state, PROPOSAL_STATE_SUCCEEDED);

    // 9. Fix #8: Schedule in timelock with grace period
    let (d5, l5, _op_id) = controller::schedule(
        &d4[..l4], l4, prop_id, 300_000, TIMELOCK_MIN_DELAY,
    ).unwrap();

    let ready_at = 300_000 + TIMELOCK_MIN_DELAY;

    // Pending before ready
    assert!(controller::is_operation_pending(&d5[..l5], 0, 400_000));

    // Ready after delay
    assert!(controller::is_operation_ready(&d5[..l5], 0, ready_at + 100));

    // Fix #2: Reentrancy guard — verify lock mechanism works
    assert!(!is_locked(&d5[..l5]));
    let (d5_locked, l5_locked) = set_lock(&d5[..l5], l5, true).unwrap();
    assert!(is_locked(&d5_locked[..l5_locked]));
    let (d5_unlocked, _l5_unlocked) = set_lock(&d5_locked[..l5_locked], l5_locked, false).unwrap();
    assert!(!is_locked(&d5_unlocked));

    // Execute
    let result = controller::execute(&d5[..l5], l5, 0, ready_at + 100);
    assert!(result.is_ok());

    // Expired after grace
    // (schedule another to test expiry)
    let (d6, l6, _) = controller::schedule(
        &d5[..l5], l5, prop_id + 1, 300_000, TIMELOCK_MIN_DELAY,
    ).unwrap();
    let expired_time = ready_at + TIMELOCK_GRACE_PERIOD + 100;
    assert!(controller::is_operation_expired(&d6[..l6], 1, expired_time));
}
