//! Core types for the XRPL Token DAO.
//!
//! These mirror OpenZeppelin's Governor and TimelockController structs,
//! adapted for XRPL's on-chain data format.

use crate::foundation::config::*;

/// A governance proposal. Mirrors Governor's ProposalCore struct.
///
/// Stored in the escrow's contract data as key=value pairs:
///   prop_0_id=<hash>;prop_0_proposer=<hex>;prop_0_start=<time>;...
#[derive(Clone, Copy)]
pub struct Proposal {
    /// Unique proposal ID (first 8 bytes of description hash)
    pub id: u32,
    /// AccountID of the proposer
    pub proposer: [u8; ACCOUNT_ID_SIZE],
    /// Ledger close time when voting starts (after voting delay)
    pub vote_start: u32,
    /// Ledger close time when voting ends
    pub vote_end: u32,
    /// Current state of the proposal
    pub state: u8,
    /// Votes for
    pub for_votes: u64,
    /// Votes against
    pub against_votes: u64,
    /// Abstain votes
    pub abstain_votes: u64,
    /// Timelock execution timestamp (0 if not queued)
    pub eta: u32,
    /// Description hash (first 4 bytes for compact storage)
    pub description_hash: u32,
}

impl Proposal {
    pub fn new() -> Self {
        Proposal {
            id: 0,
            proposer: [0u8; ACCOUNT_ID_SIZE],
            vote_start: 0,
            vote_end: 0,
            state: PROPOSAL_STATE_PENDING,
            for_votes: 0,
            against_votes: 0,
            abstain_votes: 0,
            eta: 0,
            description_hash: 0,
        }
    }

    /// Total votes cast (for + against + abstain)
    pub fn total_votes(&self) -> u64 {
        self.for_votes + self.against_votes + self.abstain_votes
    }

    /// Check if the vote succeeded (more for than against)
    /// Mirrors Governor._voteSucceeded()
    pub fn vote_succeeded(&self) -> bool {
        self.for_votes > self.against_votes
    }
}

/// A DAO member with voting power. Mirrors ERC20Votes balances.
#[derive(Clone, Copy)]
pub struct Member {
    /// AccountID of the member
    pub account: [u8; ACCOUNT_ID_SIZE],
    /// Voting power in drops (XRP balance snapshot)
    pub voting_power: u64,
    /// Role bitmask (ROLE_PROPOSER | ROLE_EXECUTOR | ROLE_ADMIN)
    pub roles: u8,
}

impl Member {
    pub fn new() -> Self {
        Member {
            account: [0u8; ACCOUNT_ID_SIZE],
            voting_power: 0,
            roles: 0,
        }
    }

    pub fn has_role(&self, role: u8) -> bool {
        self.roles & role != 0
    }
}

/// A timelock operation. Mirrors TimelockController's operation.
#[derive(Clone, Copy)]
pub struct TimelockOp {
    /// Operation ID (hash of content)
    pub id: u32,
    /// Linked proposal ID
    pub proposal_id: u32,
    /// Timestamp when operation becomes executable
    pub ready_at: u32,
    /// Current state
    pub state: u8,
}

impl TimelockOp {
    pub fn new() -> Self {
        TimelockOp {
            id: 0,
            proposal_id: 0,
            ready_at: 0,
            state: OP_STATE_UNSET,
        }
    }
}

/// Vote record for a specific member on a specific proposal.
#[derive(Clone, Copy)]
pub struct VoteRecord {
    /// Voter AccountID
    pub voter: [u8; ACCOUNT_ID_SIZE],
    /// Proposal ID
    pub proposal_id: u32,
    /// Vote type (VOTE_FOR, VOTE_AGAINST, VOTE_ABSTAIN)
    pub support: u8,
    /// Weight of the vote (voting power at snapshot)
    pub weight: u64,
}
