//! Test suite for the XRPL Token DAO.
//!
//! Organized to mirror the source structure:
//!   tests/foundation/  — data, parse tests
//!   tests/crypto/      — hex tests
//!   tests/governance/  — governor, counting, votes tests
//!   tests/timelock/    — controller, operations tests
//!   tests/token/       — xrp_votes tests

pub mod foundation;
pub mod crypto;
pub mod governance;
pub mod timelock;
pub mod token;

use crate::foundation::config::*;
use crate::foundation::data::*;
use crate::crypto::hex::encode_hex;
use crate::governance::governor::{format_u64, build_prop_key};

// ═══════════════════════════════════════════════════════════════════════
// Shared Test Helpers
// ═══════════════════════════════════════════════════════════════════════

/// Create a mock AccountID from a simple seed byte.
pub fn mock_account(seed: u8) -> [u8; ACCOUNT_ID_SIZE] {
    let mut account = [0u8; ACCOUNT_ID_SIZE];
    account[0] = seed;
    account[19] = seed;
    account
}

/// Create an Alice account (proposer/admin)
pub fn alice() -> [u8; ACCOUNT_ID_SIZE] { mock_account(0xAA) }

/// Create a Bob account (voter)
pub fn bob() -> [u8; ACCOUNT_ID_SIZE] { mock_account(0xBB) }

/// Create a Carol account (voter)
pub fn carol() -> [u8; ACCOUNT_ID_SIZE] { mock_account(0xCC) }

/// Create a Dave account (executor)
pub fn dave() -> [u8; ACCOUNT_ID_SIZE] { mock_account(0xDD) }

/// Create an Eve account (unregistered)
pub fn eve() -> [u8; ACCOUNT_ID_SIZE] { mock_account(0xEE) }

/// Build initial DAO data with members.
/// Returns (data_buffer, data_length).
pub fn build_dao_data(
    members: &[(&[u8; ACCOUNT_ID_SIZE], u64, u8)],
) -> ([u8; 4096], usize) {
    let mut data = [0u8; 4096];
    let mut pos = 0;

    // member_count (multi-digit safe)
    let mut count_buf = [0u8; 3];
    let count_len = crate::governance::governor::format_u8(members.len() as u8, &mut count_buf);
    pos = write_entry(&mut data, pos, b"member_count", &count_buf[..count_len]);

    for (i, (account, power, roles)) in members.iter().enumerate() {
        pos = write_separator(&mut data, pos);

        // member_N=<hex>:<power>:<roles> (multi-digit index safe)
        let mut key = [0u8; 16];
        let prefix = b"member_";
        let plen = prefix.len();
        key[..plen].copy_from_slice(prefix);
        let idx_len = crate::governance::governor::format_u8(i as u8, &mut key[plen..]);
        let klen = plen + idx_len;

        let mut val = [0u8; 64];
        let mut vpos = 0;
        let mut hex_buf = [0u8; 40];
        encode_hex(*account, &mut hex_buf);
        val[vpos..vpos + 40].copy_from_slice(&hex_buf);
        vpos += 40;
        val[vpos] = b':';
        vpos += 1;
        let plen = format_u64(*power, &mut val[vpos..]);
        vpos += plen;
        val[vpos] = b':';
        vpos += 1;
        val[vpos] = b'0' + roles;
        vpos += 1;

        pos = write_entry(&mut data, pos, &key[..klen], &val[..vpos]);
    }

    (data, pos)
}

/// Build DAO data with a proposal already created.
pub fn build_dao_with_proposal(
    members: &[(&[u8; ACCOUNT_ID_SIZE], u64, u8)],
    proposal_id: u32,
    proposer: &[u8; ACCOUNT_ID_SIZE],
    vote_start: u32,
    vote_end: u32,
    state: u8,
) -> ([u8; 4096], usize) {
    let (base_data, base_len) = build_dao_data(members);

    let mut data = [0u8; 4096];
    data[..base_len].copy_from_slice(&base_data[..base_len]);
    let mut pos = base_len;

    // proposal_count=1
    pos = write_separator(&mut data, pos);
    pos = write_entry(&mut data, pos, b"proposal_count", b"1");

    let mut key_buf = [0u8; 32];
    let mut val_buf = [0u8; 20];

    // prop_0_id
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"prop_", 0, b"_id", &mut key_buf);
    let vlen = crate::foundation::parse::format_u32(proposal_id, &mut val_buf);
    pos = write_entry(&mut data, pos, &key_buf[..klen], &val_buf[..vlen]);

    // prop_0_proposer
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"prop_", 0, b"_proposer", &mut key_buf);
    let mut hex_buf = [0u8; 40];
    encode_hex(proposer, &mut hex_buf);
    pos = write_entry(&mut data, pos, &key_buf[..klen], &hex_buf);

    // prop_0_state
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"prop_", 0, b"_state", &mut key_buf);
    let state_val = [b'0' + state];
    pos = write_entry(&mut data, pos, &key_buf[..klen], &state_val);

    // prop_0_start
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"prop_", 0, b"_start", &mut key_buf);
    let vlen = crate::foundation::parse::format_u32(vote_start, &mut val_buf);
    pos = write_entry(&mut data, pos, &key_buf[..klen], &val_buf[..vlen]);

    // prop_0_end
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"prop_", 0, b"_end", &mut key_buf);
    let vlen = crate::foundation::parse::format_u32(vote_end, &mut val_buf);
    pos = write_entry(&mut data, pos, &key_buf[..klen], &val_buf[..vlen]);

    // prop_0_for=0, prop_0_against=0, prop_0_abstain=0
    for suffix in [b"_for" as &[u8], b"_against", b"_abstain"] {
        pos = write_separator(&mut data, pos);
        let klen = build_prop_key(b"prop_", 0, suffix, &mut key_buf);
        pos = write_entry(&mut data, pos, &key_buf[..klen], b"0");
    }

    // prop_0_desc
    pos = write_separator(&mut data, pos);
    let klen = build_prop_key(b"prop_", 0, b"_desc", &mut key_buf);
    let vlen = crate::foundation::parse::format_u32(12345, &mut val_buf);
    pos = write_entry(&mut data, pos, &key_buf[..klen], &val_buf[..vlen]);

    (data, pos)
}
