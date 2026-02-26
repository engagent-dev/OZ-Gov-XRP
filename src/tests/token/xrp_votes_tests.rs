use crate::foundation::config::*;
use crate::token::xrp_votes::*;
use crate::tests::*;

// ═══════════════════════════════════════════════════════════════════════
// Delegation tests — mirrors ERC20Votes.delegate()
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_delegate_to_another() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER),
        (&bob(), 100_000_000, 0),
    ]);

    let (new_data, new_len) = delegate(&data[..len], len, &alice(), &bob()).unwrap();
    let d = get_delegate(&new_data[..new_len], &alice());
    assert_eq!(d, bob());
}

#[test]
fn test_self_delegation_clears() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER),
        (&bob(), 100_000_000, 0),
    ]);

    // First delegate to bob
    let (d1, l1) = delegate(&data[..len], len, &alice(), &bob()).unwrap();
    assert_eq!(get_delegate(&d1[..l1], &alice()), bob());

    // Self-delegate to remove
    let (d2, l2) = delegate(&d1[..l1], l1, &alice(), &alice()).unwrap();
    assert_eq!(get_delegate(&d2[..l2], &alice()), alice()); // back to self
}

#[test]
fn test_default_self_delegation() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, 0)]);
    // No explicit delegation → self-delegate
    assert_eq!(get_delegate(&data[..len], &alice()), alice());
}

// ═══════════════════════════════════════════════════════════════════════
// Effective votes tests — mirrors ERC20Votes.getVotes()
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_effective_votes_self_delegated() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER),
        (&bob(), 100_000_000, 0),
    ]);

    // No delegation → self-delegated → own power
    assert_eq!(get_effective_votes(&data[..len], &alice()), 200_000_000);
    assert_eq!(get_effective_votes(&data[..len], &bob()), 100_000_000);
}

#[test]
fn test_effective_votes_with_delegation() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER),
        (&bob(), 100_000_000, 0),
    ]);

    // Alice delegates to Bob
    let (d1, l1) = delegate(&data[..len], len, &alice(), &bob()).unwrap();

    // Bob now has his own power + alice's delegated power
    let bob_votes = get_effective_votes(&d1[..l1], &bob());
    assert_eq!(bob_votes, 300_000_000); // 100M own + 200M from alice

    // Alice has 0 effective power (delegated away)
    let alice_votes = get_effective_votes(&d1[..l1], &alice());
    assert_eq!(alice_votes, 0);
}

#[test]
fn test_effective_votes_unregistered() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, 0)]);
    assert_eq!(get_effective_votes(&data[..len], &eve()), 0);
}

#[test]
fn test_effective_votes_multiple_delegations() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, 0),
        (&bob(), 100_000_000, 0),
        (&carol(), 150_000_000, 0),
    ]);

    // Alice and Carol both delegate to Bob
    let (d1, l1) = delegate(&data[..len], len, &alice(), &bob()).unwrap();
    let (d2, l2) = delegate(&d1[..l1], l1, &carol(), &bob()).unwrap();

    let bob_votes = get_effective_votes(&d2[..l2], &bob());
    // bob's own (100M) + alice's (200M) + carol's (150M)
    assert_eq!(bob_votes, 450_000_000);
}

// ═══════════════════════════════════════════════════════════════════════
// Snapshot tests — mirrors ERC20Votes checkpointing
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn test_snapshot_voting_power() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, ROLE_PROPOSER),
        (&bob(), 100_000_000, 0),
    ]);

    let prop_id = 42;
    let (d1, l1) = snapshot_voting_power(&data[..len], len, prop_id, &alice()).unwrap();

    let snapped = get_snapshot_votes(&d1[..l1], prop_id, &alice());
    assert_eq!(snapped, 200_000_000);
}

#[test]
fn test_snapshot_not_found() {
    let (data, len) = build_dao_data(&[(&alice(), 200_000_000, 0)]);
    // No snapshot taken → returns 0
    assert_eq!(get_snapshot_votes(&data[..len], 999, &alice()), 0);
}

#[test]
fn test_snapshot_different_proposals() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, 0),
    ]);

    let (d1, l1) = snapshot_voting_power(&data[..len], len, 1, &alice()).unwrap();
    let (d2, l2) = snapshot_voting_power(&d1[..l1], l1, 2, &alice()).unwrap();

    // Both snapshots preserved
    assert_eq!(get_snapshot_votes(&d2[..l2], 1, &alice()), 200_000_000);
    assert_eq!(get_snapshot_votes(&d2[..l2], 2, &alice()), 200_000_000);
}

#[test]
fn test_snapshot_with_delegation() {
    let (data, len) = build_dao_data(&[
        (&alice(), 200_000_000, 0),
        (&bob(), 100_000_000, 0),
    ]);

    // Alice delegates to Bob
    let (d1, l1) = delegate(&data[..len], len, &alice(), &bob()).unwrap();

    // Snapshot Bob's effective power (should include delegation)
    let (d2, l2) = snapshot_voting_power(&d1[..l1], l1, 42, &bob()).unwrap();
    let snapped = get_snapshot_votes(&d2[..l2], 42, &bob());
    assert_eq!(snapped, 300_000_000); // own + delegated
}
