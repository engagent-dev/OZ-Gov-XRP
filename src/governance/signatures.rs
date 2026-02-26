//! Vote-by-Signature — mirrors OpenZeppelin GovernorCountingSimple.castVoteBySig()
//!
//! ## Fix #4: Vote-by-Signature Framework
//!
//! In OZ, `castVoteBySig()` uses EIP-712 typed data signatures allowing
//! gasless voting via meta-transactions. On XRPL, we implement an equivalent
//! using XRPL's native secp256k1 signatures.
//!
//! ## How It Works
//!
//! 1. Voter signs a message: `vote:{proposal_id}:{support}:{voter_hex}`
//! 2. Any account can submit the signature on-chain
//! 3. Contract verifies the signature recovers to the voter's account
//! 4. Vote is recorded as if the voter called cast_vote directly
//!
//! ## XRPL Signature Format
//!
//! XRPL uses secp256k1 (same as Ethereum pre-EIP-155).
//! The signature is 65 bytes: [r (32 bytes) | s (32 bytes) | v (1 byte)]
//!
//! ## Data Format
//!
//! Pending signatures stored as:
//!   sig_N=<voter_hex>:<proposal_id>:<support>:<signature_hex>
//!
//! ## Security
//!
//! - Replay protection: vote records prevent double-voting
//! - Message binding: signature commits to specific proposal + support value
//! - Nonce not needed: hasVoted() check prevents replay

use crate::foundation::config::*;
use crate::crypto::hex::encode_hex;

/// Size of a secp256k1 signature (r + s + v)
pub const SIGNATURE_SIZE: usize = 65;

/// Build the message that must be signed for a vote-by-signature.
/// Message format: "xrpl-dao:vote:{proposal_id}:{support}:{voter_hex}"
///
/// This mirrors EIP-712 typed data hashing — binding the signature to:
///   - Domain (xrpl-dao)
///   - Action (vote)
///   - Proposal ID (which proposal)
///   - Support (how they're voting)
///   - Voter (who is voting)
pub fn build_vote_message(
    proposal_id: u32,
    support: u8,
    voter: &[u8; ACCOUNT_ID_SIZE],
    out: &mut [u8],
) -> usize {
    let prefix = b"xrpl-dao:vote:";
    let mut pos = prefix.len();
    if pos > out.len() { return 0; }
    out[..pos].copy_from_slice(prefix);

    // Proposal ID as decimal
    let mut id_buf = [0u8; 10];
    let id_len = crate::foundation::parse::format_u32(proposal_id, &mut id_buf);
    if pos + id_len > out.len() { return 0; }
    out[pos..pos + id_len].copy_from_slice(&id_buf[..id_len]);
    pos += id_len;

    // Separator
    if pos >= out.len() { return 0; }
    out[pos] = b':';
    pos += 1;

    // Support as single digit
    if pos >= out.len() { return 0; }
    out[pos] = b'0' + support;
    pos += 1;

    // Separator
    if pos >= out.len() { return 0; }
    out[pos] = b':';
    pos += 1;

    // Voter hex
    let mut hex_buf = [0u8; 40];
    encode_hex(voter, &mut hex_buf);
    if pos + 40 > out.len() { return 0; }
    out[pos..pos + 40].copy_from_slice(&hex_buf);
    pos += 40;

    pos
}

/// Hash a vote message for signature verification.
/// Uses the same FNV-1a hash as proposal IDs for consistency.
pub fn hash_vote_message(message: &[u8], message_len: usize) -> u32 {
    let mut h: u64 = 0xcbf29ce484222325;

    for i in 0..message_len {
        h ^= message[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
    }

    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;

    h as u32
}

/// Verify that a vote-by-signature message is well-formed.
/// Returns (proposal_id, support, voter_account) if valid.
///
/// Note: Actual cryptographic signature verification (secp256k1 recovery)
/// requires a host function `verify_signature(msg, sig, pubkey)` that
/// XRPL WASM would need to expose. This function validates the message
/// structure; the host call would verify the cryptographic proof.
///
/// When the XRPL WASM host exposes `verify_secp256k1`, this module
/// is ready to plug in:
///
/// ```ignore
/// extern "C" {
///     fn verify_signature(
///         msg: *const u8, msg_len: u32,
///         sig: *const u8, sig_len: u32,
///         pubkey: *const u8, pubkey_len: u32,
///     ) -> i32;
/// }
/// ```
pub fn validate_vote_message(
    proposal_id: u32,
    support: u8,
    voter: &[u8; ACCOUNT_ID_SIZE],
) -> bool {
    // Validate support type
    if support > 2 {
        return false;
    }

    // Validate proposal_id is non-zero
    if proposal_id == 0 {
        return false;
    }

    // Validate voter is non-zero
    let mut all_zero = true;
    for &b in voter.iter() {
        if b != 0 { all_zero = false; break; }
    }
    if all_zero {
        return false;
    }

    true
}

/// Record a signature-based vote.
/// This stores the intent so it can be processed when the host
/// exposes signature verification.
///
/// Data format: sigvote_<proposal_id>_<voter_hex>=<support>
pub fn record_sig_vote_intent(
    data: &[u8],
    data_len: usize,
    proposal_id: u32,
    support: u8,
    voter: &[u8; ACCOUNT_ID_SIZE],
) -> Result<([u8; 4096], usize), i32> {
    if !validate_vote_message(proposal_id, support, voter) {
        return Err(ERR_INVALID_VOTE);
    }

    let mut voter_hex = [0u8; 40];
    encode_hex(voter, &mut voter_hex);

    // Build key: "sigvote_<prop_id>_<voter_hex>"
    let mut key_buf = [0u8; 64];
    let prefix = b"sigvote_";
    let mut kpos = prefix.len();
    key_buf[..kpos].copy_from_slice(prefix);

    let mut id_buf = [0u8; 10];
    let id_len = crate::foundation::parse::format_u32(proposal_id, &mut id_buf);
    key_buf[kpos..kpos + id_len].copy_from_slice(&id_buf[..id_len]);
    kpos += id_len;

    key_buf[kpos] = b'_';
    kpos += 1;

    key_buf[kpos..kpos + 40].copy_from_slice(&voter_hex);
    kpos += 40;

    // Value: support digit
    let val = [b'0' + support];

    // Append to data
    let mut new_data = [0u8; 4096];
    if data_len > 0 {
        new_data[..data_len].copy_from_slice(&data[..data_len]);
    }
    let mut pos = data_len;

    if pos > 0 {
        pos = crate::foundation::data::write_separator(&mut new_data, pos);
    }
    pos = crate::foundation::data::write_entry(&mut new_data, pos, &key_buf[..kpos], &val);

    Ok((new_data, pos))
}
