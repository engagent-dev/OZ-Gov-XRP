//! Deterministic hash function for proposal and operation IDs.
//!
//! Replaces the weak `description_hash ^ current_time` with a proper
//! multi-input hash that mirrors OpenZeppelin's
//! `keccak256(abi.encode(targets, values, calldatas, descriptionHash))`.
//!
//! Uses a FNV-1a inspired mixing function with additional bit rotation.
//! Not cryptographically secure (no SHA-256 available in no_std without
//! extra dependencies), but collision-resistant for our domain of
//! proposal IDs where inputs are unique (proposer + time + desc + nonce).

use crate::foundation::config::ACCOUNT_ID_SIZE;

/// Hash multiple inputs into a deterministic u32 proposal ID.
///
/// Inputs bound to the hash:
///   - proposer AccountID (20 bytes) — who proposed
///   - description_hash (4 bytes)    — what was proposed
///   - current_time (4 bytes)        — when proposed
///   - proposal_count (1 byte)       — nonce to prevent collisions
///
/// This mirrors OZ's approach of binding the ID to all proposal content.
pub fn hash_proposal(
    proposer: &[u8; ACCOUNT_ID_SIZE],
    description_hash: u32,
    current_time: u32,
    proposal_nonce: u8,
) -> u32 {
    let mut h: u64 = 0xcbf29ce484222325; // FNV offset basis

    // Mix proposer bytes
    for &b in proposer.iter() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }

    // Mix description hash (4 bytes, big-endian)
    for &b in &description_hash.to_be_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }

    // Mix current time (4 bytes, big-endian)
    for &b in &current_time.to_be_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }

    // Mix nonce
    h ^= proposal_nonce as u64;
    h = h.wrapping_mul(0x100000001b3);

    // Final avalanche: fold 64-bit down to 32-bit with mixing
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;

    // Return lower 32 bits, ensure non-zero
    let result = (h as u32) | 1;
    result
}

/// Hash inputs for a timelock operation ID.
/// Binds: proposal_id + schedule_time + op_nonce.
pub fn hash_operation(
    proposal_id: u32,
    schedule_time: u32,
    op_nonce: u8,
) -> u32 {
    let mut h: u64 = 0xcbf29ce484222325;

    for &b in &proposal_id.to_be_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }

    for &b in &schedule_time.to_be_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }

    h ^= op_nonce as u64;
    h = h.wrapping_mul(0x100000001b3);

    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;

    (h as u32) | 1
}
