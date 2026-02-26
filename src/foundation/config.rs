//! Constants and error codes for the XRPL Token DAO.
//!
//! Mirrors OpenZeppelin Governor + TimelockController configuration.
//!
//! ## Architecture Mapping
//!
//! | OpenZeppelin          | XRPL DAO                  |
//! |-----------------------|---------------------------|
//! | Governor              | governance module          |
//! | TimelockController    | timelock module            |
//! | ERC20Votes            | token module (XRP-native)  |
//! | ProposalState enum    | PROPOSAL_STATE_* constants |

/// Size of an XRPL AccountID in bytes (RIPEMD160 hash)
pub const ACCOUNT_ID_SIZE: usize = 20;

/// Maximum number of DAO members / token holders tracked
pub const MAX_MEMBERS: usize = 20;

/// Maximum proposals that can exist simultaneously
pub const MAX_PROPOSALS: usize = 10;

/// Maximum operations in a single timelock batch
pub const MAX_BATCH_OPS: usize = 5;

// ═══════════════════════════════════════════════════════════════════════
// GOVERNANCE SETTINGS (mirrors GovernorSettings.sol)
// ═══════════════════════════════════════════════════════════════════════

/// Delay in ledger close times (seconds) after proposal creation before
/// voting starts. Mirrors `votingDelay()` in Governor.
/// Default: ~5 minutes (300 seconds / ~4sec per ledger ≈ 75 ledgers)
pub const VOTING_DELAY: u32 = 300;

/// Duration in seconds that voting remains open.
/// Mirrors `votingPeriod()` in Governor.
/// Default: ~3 days (259200 seconds)
pub const VOTING_PERIOD: u32 = 259200;

/// Minimum token balance required to create a proposal.
/// Mirrors `proposalThreshold()` in Governor.
/// Expressed in drops (1 XRP = 1,000,000 drops).
pub const PROPOSAL_THRESHOLD: u64 = 100_000_000; // 100 XRP

/// Quorum: percentage of total voting power required (0-100).
/// Mirrors `GovernorVotesQuorumFraction`.
pub const QUORUM_PERCENTAGE: u8 = 4; // 4% like OZ default

// ═══════════════════════════════════════════════════════════════════════
// TIMELOCK SETTINGS (mirrors TimelockController.sol)
// ═══════════════════════════════════════════════════════════════════════

/// Minimum delay in seconds before a queued proposal can be executed.
/// Mirrors `getMinDelay()` in TimelockController.
/// Default: 2 days
pub const TIMELOCK_MIN_DELAY: u32 = 172800;

/// Grace period after timelock expires during which execution is allowed.
/// After ready_at + TIMELOCK_GRACE_PERIOD, the operation expires.
/// Mirrors OZ GovernorTimelockControl expiry behavior.
/// Default: 14 days
pub const TIMELOCK_GRACE_PERIOD: u32 = 1_209_600;

/// Initial voting power for self-registered members (0 = no auto-power).
/// Members can self-register but start with 0 voting power.
/// Admin must grant voting power explicitly.
pub const SELF_REGISTER_INITIAL_POWER: u64 = 0;

// ═══════════════════════════════════════════════════════════════════════
// PROPOSAL STATES (mirrors IGovernor.ProposalState enum)
// ═══════════════════════════════════════════════════════════════════════

/// Proposal does not exist
pub const PROPOSAL_STATE_PENDING: u8 = 0;
/// Voting has not started yet (within voting delay)
pub const PROPOSAL_STATE_ACTIVE: u8 = 1;
/// Proposal was canceled by proposer
pub const PROPOSAL_STATE_CANCELED: u8 = 2;
/// Voting ended, did not reach quorum or majority
pub const PROPOSAL_STATE_DEFEATED: u8 = 3;
/// Voting ended, quorum and majority reached
pub const PROPOSAL_STATE_SUCCEEDED: u8 = 4;
/// Proposal queued in timelock
pub const PROPOSAL_STATE_QUEUED: u8 = 5;
/// Timelock expired without execution
pub const PROPOSAL_STATE_EXPIRED: u8 = 6;
/// Proposal executed successfully
pub const PROPOSAL_STATE_EXECUTED: u8 = 7;

// ═══════════════════════════════════════════════════════════════════════
// VOTE TYPES (mirrors GovernorCountingSimple.sol)
// ═══════════════════════════════════════════════════════════════════════

/// Vote against the proposal
pub const VOTE_AGAINST: u8 = 0;
/// Vote for the proposal
pub const VOTE_FOR: u8 = 1;
/// Abstain from voting (counts toward quorum but not for/against)
pub const VOTE_ABSTAIN: u8 = 2;

// ═══════════════════════════════════════════════════════════════════════
// ROLES (mirrors TimelockController roles)
// ═══════════════════════════════════════════════════════════════════════

/// Role for accounts that can propose operations
pub const ROLE_PROPOSER: u8 = 1;
/// Role for accounts that can execute operations
pub const ROLE_EXECUTOR: u8 = 2;
/// Role for the admin (can grant/revoke roles)
pub const ROLE_ADMIN: u8 = 4;

// ═══════════════════════════════════════════════════════════════════════
// TIMELOCK OPERATION STATES
// ═══════════════════════════════════════════════════════════════════════

/// Operation not scheduled
pub const OP_STATE_UNSET: u8 = 0;
/// Operation scheduled, timer not expired
pub const OP_STATE_PENDING: u8 = 1;
/// Operation scheduled, timer expired, ready to execute
pub const OP_STATE_READY: u8 = 2;
/// Operation has been executed
pub const OP_STATE_DONE: u8 = 3;
/// Operation has expired (past grace period)
pub const OP_STATE_EXPIRED: u8 = 4;

// ═══════════════════════════════════════════════════════════════════════
// RETURN CODES
// ═══════════════════════════════════════════════════════════════════════

pub const SUCCESS: i32 = 1;
pub const ERR_WRONG_ACCOUNT: i32 = -1;
pub const ERR_TOO_EARLY: i32 = -2;
pub const ERR_NOT_APPROVED: i32 = -3;
pub const ERR_DATA_READ: i32 = -4;
pub const ERR_HOST_CALL: i32 = -5;
pub const ERR_BAD_CONFIG: i32 = -6;
pub const ERR_ALREADY_VOTED: i32 = -7;
pub const ERR_PROPOSAL_NOT_ACTIVE: i32 = -8;
pub const ERR_BELOW_THRESHOLD: i32 = -9;
pub const ERR_MAX_PROPOSALS: i32 = -10;
pub const ERR_NOT_PROPOSER: i32 = -11;
pub const ERR_NOT_EXECUTOR: i32 = -12;
pub const ERR_OP_NOT_READY: i32 = -13;
pub const ERR_OP_ALREADY_QUEUED: i32 = -14;
pub const ERR_PROPOSAL_NOT_FOUND: i32 = -15;
pub const ERR_INVALID_VOTE: i32 = -16;
pub const ERR_QUORUM_NOT_MET: i32 = -17;
pub const ERR_NOT_ADMIN: i32 = -18;
pub const ERR_OVERFLOW: i32 = -19;
pub const ERR_REENTRANT: i32 = -20;
pub const ERR_OP_EXPIRED: i32 = -21;
pub const ERR_CALLER_VERIFICATION: i32 = -22;
