//! GovernorCountingSimple — mirrors OpenZeppelin GovernorCountingSimple.sol
//!
//! Simple voting mechanism with 3 voting options: Against, For, Abstain.
//!
//! ## COUNTING_MODE
//! `support=bravo&quorum=for,abstain`
//!
//! ## Vote Types
//! - 0 = Against
//! - 1 = For
//! - 2 = Abstain
//!
//! Quorum is reached when `for + abstain >= quorum_required`.
//! Vote succeeds when `for > against`.

use crate::foundation::config::*;
use crate::foundation::data::*;
use crate::crypto::hex::encode_hex;
use crate::governance::governor::{build_prop_key, parse_u64, format_u64};

/// Cast a vote on a proposal. Mirrors GovernorCountingSimple._countVote().
///
/// Requirements:
///   - Proposal must be Active
///   - Voter must not have already voted
///   - Support must be 0, 1, or 2
///
/// Records the vote and updates tallies in the data store.
pub fn cast_vote(
    data: &[u8],
    data_len: usize,
    proposal_index: u8,
    voter: &[u8; ACCOUNT_ID_SIZE],
    support: u8,
    weight: u64,
    current_time: u32,
    total_voting_power: u64,
) -> Result<([u8; 4096], usize), i32> {
    // Validate vote type
    if support > VOTE_ABSTAIN {
        return Err(ERR_INVALID_VOTE);
    }

    // Check proposal is Active
    let state = crate::governance::governor::get_proposal_state(
        data, proposal_index, current_time, total_voting_power,
    );
    if state != PROPOSAL_STATE_ACTIVE {
        return Err(ERR_PROPOSAL_NOT_ACTIVE);
    }

    // Check voter hasn't already voted (search for vote_N_M entries)
    if has_voted(data, proposal_index, voter) {
        return Err(ERR_ALREADY_VOTED);
    }

    // Determine which tally to increment
    let tally_suffix: &[u8] = match support {
        VOTE_AGAINST => b"_against",
        VOTE_FOR => b"_for",
        VOTE_ABSTAIN => b"_abstain",
        _ => return Err(ERR_INVALID_VOTE),
    };

    // Read current tally
    let mut key_buf = [0u8; 32];
    let key_len = build_prop_key(b"prop_", proposal_index, tally_suffix, &mut key_buf);
    let current_tally = find_value(data, &key_buf[..key_len])
        .and_then(|v| parse_u64(v))
        .unwrap_or(0);

    let new_tally = current_tally.checked_add(weight).ok_or(ERR_OVERFLOW)?;
    let mut tally_buf = [0u8; 20];
    let tally_len = format_u64(new_tally, &mut tally_buf);

    // Update the tally in data
    let mut new_data = [0u8; 4096];
    let mut pos = 0;
    let mut scan = 0;

    let key_len = build_prop_key(b"prop_", proposal_index, tally_suffix, &mut key_buf);
    let target_key = &key_buf[..key_len];

    while scan < data_len {
        let entry_end = data[scan..data_len].iter()
            .position(|&b| b == b';')
            .map(|p| scan + p)
            .unwrap_or(data_len);

        let entry = &data[scan..entry_end];

        let is_target = if let Some(eq) = entry.iter().position(|&b| b == b'=') {
            &entry[..eq] == target_key
        } else { false };

        if is_target {
            if pos > 0 { pos = write_separator(&mut new_data, pos); }
            pos = write_entry(&mut new_data, pos, target_key, &tally_buf[..tally_len]);
        } else if !entry.is_empty() {
            if pos > 0 { pos = write_separator(&mut new_data, pos); }
            let elen = entry.len();
            if pos + elen <= new_data.len() {
                new_data[pos..pos + elen].copy_from_slice(entry);
                pos += elen;
            }
        }

        scan = entry_end + 1;
    }

    // Append vote record: vote_P_V=<voter_hex>:<support>:<weight>
    // Count existing votes for this proposal
    let vote_count = count_votes_for_proposal(data, proposal_index);

    if pos > 0 { pos = write_separator(&mut new_data, pos); }
    let mut vote_key = [0u8; 32];
    let vk_len = build_vote_key(proposal_index, vote_count, &mut vote_key);

    // Build vote value: <voter_hex>:<support>:<weight>
    let mut vote_val = [0u8; 64];
    let mut vpos = 0;
    let mut hex_buf = [0u8; 40];
    encode_hex(voter, &mut hex_buf);
    vote_val[vpos..vpos + 40].copy_from_slice(&hex_buf);
    vpos += 40;
    vote_val[vpos] = b':';
    vpos += 1;
    vote_val[vpos] = b'0' + support;
    vpos += 1;
    vote_val[vpos] = b':';
    vpos += 1;
    let wlen = format_u64(weight, &mut vote_val[vpos..]);
    vpos += wlen;

    pos = write_entry(&mut new_data, pos, &vote_key[..vk_len], &vote_val[..vpos]);

    Ok((new_data, pos))
}

/// Check if an account has already voted on a proposal.
/// Mirrors GovernorCountingSimple.hasVoted().
pub fn has_voted(
    data: &[u8],
    proposal_index: u8,
    voter: &[u8; ACCOUNT_ID_SIZE],
) -> bool {
    let mut hex_buf = [0u8; 40];
    encode_hex(voter, &mut hex_buf);

    // Search all vote_P_N entries for this proposal
    let count = count_votes_for_proposal(data, proposal_index);
    let mut key_buf = [0u8; 32];

    for i in 0..count {
        let klen = build_vote_key(proposal_index, i, &mut key_buf);
        if let Some(val) = find_value(data, &key_buf[..klen]) {
            // Value format: <voter_hex>:<support>:<weight>
            // First 40 chars are the voter hex
            if val.len() >= 40 && &val[..40] == &hex_buf[..] {
                return true;
            }
        }
    }
    false
}

/// Get vote details for a specific voter on a proposal.
/// Returns (support, weight) or None.
pub fn get_vote(
    data: &[u8],
    proposal_index: u8,
    voter: &[u8; ACCOUNT_ID_SIZE],
) -> Option<(u8, u64)> {
    let mut hex_buf = [0u8; 40];
    encode_hex(voter, &mut hex_buf);

    let count = count_votes_for_proposal(data, proposal_index);
    let mut key_buf = [0u8; 32];

    for i in 0..count {
        let klen = build_vote_key(proposal_index, i, &mut key_buf);
        if let Some(val) = find_value(data, &key_buf[..klen]) {
            if val.len() >= 40 && &val[..40] == &hex_buf[..] {
                return parse_vote_record(val);
            }
        }
    }
    None
}

/// Get proposal vote tallies: (for_votes, against_votes, abstain_votes).
/// Mirrors GovernorCountingSimple.proposalVotes().
pub fn proposal_votes(
    data: &[u8],
    proposal_index: u8,
) -> (u64, u64, u64) {
    let mut key_buf = [0u8; 32];

    let key_len = build_prop_key(b"prop_", proposal_index, b"_for", &mut key_buf);
    let for_v = find_value(data, &key_buf[..key_len])
        .and_then(|v| parse_u64(v))
        .unwrap_or(0);

    let key_len = build_prop_key(b"prop_", proposal_index, b"_against", &mut key_buf);
    let against_v = find_value(data, &key_buf[..key_len])
        .and_then(|v| parse_u64(v))
        .unwrap_or(0);

    let key_len = build_prop_key(b"prop_", proposal_index, b"_abstain", &mut key_buf);
    let abstain_v = find_value(data, &key_buf[..key_len])
        .and_then(|v| parse_u64(v))
        .unwrap_or(0);

    (for_v, against_v, abstain_v)
}

/// Check if quorum was reached.
/// Mirrors Governor._quorumReached().
pub fn quorum_reached(
    data: &[u8],
    proposal_index: u8,
    total_voting_power: u64,
) -> bool {
    let (for_v, _against_v, abstain_v) = proposal_votes(data, proposal_index);
    let quorum_required = (total_voting_power / 100).saturating_mul(QUORUM_PERCENTAGE as u64);
    (for_v.saturating_add(abstain_v)) >= quorum_required
}

/// Check if the vote succeeded (for > against).
/// Mirrors Governor._voteSucceeded().
pub fn vote_succeeded(data: &[u8], proposal_index: u8) -> bool {
    let (for_v, against_v, _) = proposal_votes(data, proposal_index);
    for_v > against_v
}

// ——— Internal helpers ———

/// Build a vote record key: "vote_P_N" — multi-digit safe (Fix #7).
fn build_vote_key(proposal_index: u8, vote_index: u8, out: &mut [u8]) -> usize {
    let prefix = b"vote_";
    let mut pos = prefix.len();
    out[..pos].copy_from_slice(prefix);
    let pi_len = crate::governance::governor::format_u8(proposal_index, &mut out[pos..]);
    pos += pi_len;
    out[pos] = b'_';
    pos += 1;
    let vi_len = crate::governance::governor::format_u8(vote_index, &mut out[pos..]);
    pos += vi_len;
    pos
}

/// Count existing vote records for a proposal by scanning keys.
fn count_votes_for_proposal(data: &[u8], proposal_index: u8) -> u8 {
    let mut count: u8 = 0;
    let mut key_buf = [0u8; 32];

    loop {
        let klen = build_vote_key(proposal_index, count, &mut key_buf);
        if find_value(data, &key_buf[..klen]).is_some() {
            count += 1;
            if count >= MAX_MEMBERS as u8 { break; }
        } else {
            break;
        }
    }
    count
}

/// Parse vote record "hex:support:weight" → (support, weight)
fn parse_vote_record(val: &[u8]) -> Option<(u8, u64)> {
    // Skip 40-char hex, then ':'
    if val.len() < 42 { return None; }
    if val[40] != b':' { return None; }
    let support = val[41].checked_sub(b'0')?;
    if support > 2 { return None; }
    if val.len() < 43 || val[42] != b':' { return None; }
    let weight = parse_u64(&val[43..])?;
    Some((support, weight))
}
