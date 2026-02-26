use crate::foundation::config::*;
use crate::governance::counting::*;
use crate::governance::governor;
use crate::tests::*;

// ═══════════════════════════════════════════════════════════════════════
// cast_vote() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_cast_vote_for() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    // Active proposal (current_time between start and end)
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let result = cast_vote(
        &data[..len], len, 0, &bob(), VOTE_FOR, 100_000_000, 2000, 300_000_000,
    );
    assert!(result.is_ok());

    let (new_data, new_len) = result.unwrap();
    let (for_v, against_v, abstain_v) = proposal_votes(&new_data[..new_len], 0);
    assert_eq!(for_v, 100_000_000);
    assert_eq!(against_v, 0);
    assert_eq!(abstain_v, 0);
}

#[test]
fn test_cast_vote_against() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let result = cast_vote(
        &data[..len], len, 0, &bob(), VOTE_AGAINST, 100_000_000, 2000, 300_000_000,
    );
    assert!(result.is_ok());

    let (new_data, new_len) = result.unwrap();
    let (for_v, against_v, _) = proposal_votes(&new_data[..new_len], 0);
    assert_eq!(for_v, 0);
    assert_eq!(against_v, 100_000_000);
}

#[test]
fn test_cast_vote_abstain() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let result = cast_vote(
        &data[..len], len, 0, &bob(), VOTE_ABSTAIN, 100_000_000, 2000, 300_000_000,
    );
    assert!(result.is_ok());

    let (new_data, new_len) = result.unwrap();
    let (_, _, abstain_v) = proposal_votes(&new_data[..new_len], 0);
    assert_eq!(abstain_v, 100_000_000);
}

#[test]
fn test_cast_vote_invalid_support() {
    let members = [(&alice(), 200_000_000u64, ROLE_PROPOSER)];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let result = cast_vote(&data[..len], len, 0, &alice(), 3, 200_000_000, 2000, 200_000_000);
    assert_eq!(result, Err(ERR_INVALID_VOTE));
}

#[test]
fn test_cast_vote_not_active() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    // vote_start=5000, current=1000 → Pending, not Active
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 5000, 265000, 0,
    );

    let result = cast_vote(
        &data[..len], len, 0, &bob(), VOTE_FOR, 100_000_000, 1000, 300_000_000,
    );
    assert_eq!(result, Err(ERR_PROPOSAL_NOT_ACTIVE));
}

#[test]
fn test_double_vote_rejected() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    // First vote succeeds
    let (data1, len1) = cast_vote(
        &data[..len], len, 0, &bob(), VOTE_FOR, 100_000_000, 2000, 300_000_000,
    ).unwrap();

    // Second vote fails
    let result = cast_vote(
        &data1[..len1], len1, 0, &bob(), VOTE_AGAINST, 100_000_000, 2500, 300_000_000,
    );
    assert_eq!(result, Err(ERR_ALREADY_VOTED));
}

#[test]
fn test_multiple_voters() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
        (&carol(), 150_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let (data1, len1) = cast_vote(
        &data[..len], len, 0, &alice(), VOTE_FOR, 200_000_000, 2000, 450_000_000,
    ).unwrap();

    let (data2, len2) = cast_vote(
        &data1[..len1], len1, 0, &bob(), VOTE_AGAINST, 100_000_000, 2100, 450_000_000,
    ).unwrap();

    let (data3, len3) = cast_vote(
        &data2[..len2], len2, 0, &carol(), VOTE_FOR, 150_000_000, 2200, 450_000_000,
    ).unwrap();

    let (for_v, against_v, abstain_v) = proposal_votes(&data3[..len3], 0);
    assert_eq!(for_v, 350_000_000); // alice + carol
    assert_eq!(against_v, 100_000_000); // bob
    assert_eq!(abstain_v, 0);
}

// ═══════════════════════════════════════════════════════════════════════
// has_voted() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_has_voted_false_initially() {
    let members = [(&alice(), 200_000_000u64, ROLE_PROPOSER)];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    assert!(!has_voted(&data[..len], 0, &bob()));
}

#[test]
fn test_has_voted_true_after_vote() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let (new_data, new_len) = cast_vote(
        &data[..len], len, 0, &bob(), VOTE_FOR, 100_000_000, 2000, 300_000_000,
    ).unwrap();

    assert!(has_voted(&new_data[..new_len], 0, &bob()));
    assert!(!has_voted(&new_data[..new_len], 0, &carol()));
}

// ═══════════════════════════════════════════════════════════════════════
// quorum and vote success tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_quorum_not_reached() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );
    // No votes cast, quorum needs 4% of 300M = 12M
    assert!(!quorum_reached(&data[..len], 0, 300_000_000));
}

#[test]
fn test_quorum_reached_with_for_votes() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    // Cast enough votes to meet quorum (12M needed from 300M total)
    let (voted, vlen) = cast_vote(
        &data[..len], len, 0, &bob(), VOTE_FOR, 100_000_000, 2000, 300_000_000,
    ).unwrap();

    assert!(quorum_reached(&voted[..vlen], 0, 300_000_000));
}

#[test]
fn test_quorum_reached_with_abstain() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    // Abstain votes count toward quorum
    let (voted, vlen) = cast_vote(
        &data[..len], len, 0, &bob(), VOTE_ABSTAIN, 100_000_000, 2000, 300_000_000,
    ).unwrap();

    assert!(quorum_reached(&voted[..vlen], 0, 300_000_000));
}

#[test]
fn test_vote_succeeded() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let (voted, vlen) = cast_vote(
        &data[..len], len, 0, &alice(), VOTE_FOR, 200_000_000, 2000, 300_000_000,
    ).unwrap();

    assert!(vote_succeeded(&voted[..vlen], 0));
}

#[test]
fn test_vote_defeated() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 300_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let (v1, l1) = cast_vote(
        &data[..len], len, 0, &alice(), VOTE_FOR, 200_000_000, 2000, 500_000_000,
    ).unwrap();

    let (v2, l2) = cast_vote(
        &v1[..l1], l1, 0, &bob(), VOTE_AGAINST, 300_000_000, 2100, 500_000_000,
    ).unwrap();

    assert!(!vote_succeeded(&v2[..l2], 0));
}

// ═══════════════════════════════════════════════════════════════════════
// get_vote() tests
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_get_vote_details() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
    ];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    let (voted, vlen) = cast_vote(
        &data[..len], len, 0, &bob(), VOTE_FOR, 100_000_000, 2000, 300_000_000,
    ).unwrap();

    let vote = get_vote(&voted[..vlen], 0, &bob());
    assert!(vote.is_some());
    let (support, weight) = vote.unwrap();
    assert_eq!(support, VOTE_FOR);
    assert_eq!(weight, 100_000_000);
}

#[test]
fn test_get_vote_not_found() {
    let members = [(&alice(), 200_000_000u64, ROLE_PROPOSER)];
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 260000, 0,
    );

    assert!(get_vote(&data[..len], 0, &bob()).is_none());
}

// ═══════════════════════════════════════════════════════════════════════
// Full lifecycle: propose → vote → state check
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_proposal_succeeds_after_voting() {
    let members = [
        (&alice(), 200_000_000u64, ROLE_PROPOSER),
        (&bob(), 100_000_000u64, 0u8),
        (&carol(), 150_000_000u64, 0u8),
    ];
    let total_vp = 450_000_000u64;
    let (data, len) = build_dao_with_proposal(
        &members, 42, &alice(), 1000, 2000, 0,
    );

    // Alice votes FOR (200M), Bob votes AGAINST (100M)
    let (d1, l1) = cast_vote(
        &data[..len], len, 0, &alice(), VOTE_FOR, 200_000_000, 1500, total_vp,
    ).unwrap();

    let (d2, l2) = cast_vote(
        &d1[..l1], l1, 0, &bob(), VOTE_AGAINST, 100_000_000, 1600, total_vp,
    ).unwrap();

    // Carol votes FOR (150M)
    let (d3, l3) = cast_vote(
        &d2[..l2], l2, 0, &carol(), VOTE_FOR, 150_000_000, 1700, total_vp,
    ).unwrap();

    // After voting ends (time > 2000)
    let state = governor::get_proposal_state(&d3[..l3], 0, 3000, total_vp);
    assert_eq!(state, PROPOSAL_STATE_SUCCEEDED);
}
