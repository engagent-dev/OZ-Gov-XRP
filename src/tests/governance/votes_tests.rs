use crate::foundation::config::*;
use crate::governance::votes::*;
use crate::tests::*;

// ═══════════════════════════════════════════════════════════════════════
// get_votes() / get_total_voting_power() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_get_votes_registered_member() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER),
        (&bob(), 100_000_000, 0),
    ]);
    assert_eq!(get_votes(&data[..len], &alice()), 200_000_000);
    assert_eq!(get_votes(&data[..len], &bob()), 100_000_000);
}

#[test]
fn test_get_votes_unregistered() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, 0)]);
    assert_eq!(get_votes(&data[..len], &eve()), 0);
}

#[test]
fn test_total_voting_power() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER),
        (&bob(), 100_000_000, 0),
        (&carol(), 150_000_000, 0),
    ]);
    assert_eq!(get_total_voting_power(&data[..len]), 450_000_000);
}

#[test]
fn test_total_voting_power_empty() {
    let data = b"member_count=0";
    assert_eq!(get_total_voting_power(data), 0);
}

// ═══════════════════════════════════════════════════════════════════════
// Quorum calculation tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_quorum_calculation() {
    // 4% of 1,000,000,000 = 40,000,000
    assert_eq!(quorum(1_000_000_000), 40_000_000);
}

#[test]
fn test_quorum_zero_supply() {
    assert_eq!(quorum(0), 0);
}

#[test]
fn test_quorum_small_supply() {
    // 4% of 100 = 4
    assert_eq!(quorum(100), 4);
}

// ═══════════════════════════════════════════════════════════════════════
// Role management tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_has_role() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER | ROLE_ADMIN),
        (&bob(), 100_000_000, ROLE_EXECUTOR),
    ]);

    assert!(has_role(&data[..len], &alice(), ROLE_PROPOSER));
    assert!(has_role(&data[..len], &alice(), ROLE_ADMIN));
    assert!(!has_role(&data[..len], &alice(), ROLE_EXECUTOR));

    assert!(has_role(&data[..len], &bob(), ROLE_EXECUTOR));
    assert!(!has_role(&data[..len], &bob(), ROLE_PROPOSER));
}

#[test]
fn test_has_role_unregistered() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);
    assert!(!has_role(&data[..len], &eve(), ROLE_ADMIN));
}

#[test]
fn test_grant_role() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_ADMIN),
        (&bob(), 100_000_000, 0),
    ]);

    // Grant executor role to bob
    let (new_data, new_len) = grant_role(&data[..len], len, &bob(), ROLE_EXECUTOR).unwrap();
    assert!(has_role(&new_data[..new_len], &bob(), ROLE_EXECUTOR));
}

#[test]
fn test_grant_role_additive() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER),
    ]);

    // Grant admin — should keep proposer
    let (new_data, new_len) = grant_role(&data[..len], len, &alice(), ROLE_ADMIN).unwrap();
    assert!(has_role(&new_data[..new_len], &alice(), ROLE_PROPOSER));
    assert!(has_role(&new_data[..new_len], &alice(), ROLE_ADMIN));
}

#[test]
fn test_revoke_role() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER | ROLE_ADMIN),
    ]);

    let (new_data, new_len) = revoke_role(&data[..len], len, &alice(), ROLE_PROPOSER).unwrap();
    assert!(!has_role(&new_data[..new_len], &alice(), ROLE_PROPOSER));
    assert!(has_role(&new_data[..new_len], &alice(), ROLE_ADMIN)); // kept
}

// ═══════════════════════════════════════════════════════════════════════
// set_member() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_set_member_new() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, ROLE_ADMIN)]);

    let (new_data, new_len) = set_member(
        &data[..len], len, &bob(), 100_000_000, ROLE_EXECUTOR,
    ).unwrap();

    assert_eq!(get_votes(&new_data[..new_len], &bob()), 100_000_000);
    assert!(has_role(&new_data[..new_len], &bob(), ROLE_EXECUTOR));
    assert_eq!(get_member_count(&new_data[..new_len]), 2);
}

#[test]
fn test_set_member_update_existing() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_ADMIN),
        (&bob(), 100_000_000, 0),
    ]);

    // Update bob's voting power
    let (new_data, new_len) = set_member(
        &data[..len], len, &bob(), 500_000_000, ROLE_EXECUTOR,
    ).unwrap();

    assert_eq!(get_votes(&new_data[..new_len], &bob()), 500_000_000);
    assert!(has_role(&new_data[..new_len], &bob(), ROLE_EXECUTOR));
    assert_eq!(get_member_count(&new_data[..new_len]), 2); // count unchanged
}

#[test]
fn test_member_count() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, 0),
        (&bob(), 100_000_000, 0),
        (&carol(), 150_000_000, 0),
    ]);
    assert_eq!(get_member_count(&data[..len]), 3);
}
