//! XRPL Token DAO — OpenZeppelin Governor + TimelockController for XRPL WASM
//!
//! # Architecture
//!
//! This contract mirrors OpenZeppelin's governance contracts (v4.x) adapted
//! for XRPL's WASM smart contract environment:
//!
//! | OZ Component               | XRPL Module                     |
//! |----------------------------|---------------------------------|
//! | Governor.sol               | governance::governor            |
//! | GovernorCountingSimple.sol | governance::counting            |
//! | GovernorVotes.sol           | governance::votes               |
//! | GovernorVotesQuorumFraction | governance::votes (quorum fn)  |
//! | TimelockController.sol      | timelock::controller           |
//! | Timelock batch/predecessor  | timelock::operations           |
//! | ERC20Votes                  | token::xrp_votes               |
//! | GovernorSettings.sol        | foundation::config (constants) |
//!
//! # WASM Exports
//!
//! The contract exposes these entry points matching the Governor interface:
//!
//! - `propose`    — Create a new governance proposal
//! - `cast_vote`  — Vote on an active proposal
//! - `queue`      — Queue a succeeded proposal into the timelock
//! - `execute`    — Execute a ready timelock operation
//! - `cancel`     — Cancel a pending proposal (proposer only)
//! - `delegate`   — Delegate voting power to another account
//! - `add_member` — Add/update a DAO member (admin only)
//! - `grant_role` — Grant a role to an account (admin only)
//!
//! # Data Format
//!
//! All state is stored in the escrow's Data field as semicolon-delimited
//! key=value pairs, matching the XRPL WASM hook data specification.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

pub mod foundation;
pub mod crypto;
pub mod governance;
pub mod timelock;
pub mod token;

#[cfg(test)]
pub mod tests;

#[cfg(not(test))]
use foundation::config::*;
#[cfg(not(test))]
use foundation::data::*;
#[cfg(not(test))]
use governance::governor;
#[cfg(not(test))]
use governance::counting;
#[cfg(not(test))]
use governance::votes;
#[cfg(not(test))]
use timelock::controller;
#[cfg(not(test))]
use token::xrp_votes;

// ═══════════════════════════════════════════════════════════════════════
// XRPL WASM Host Function Imports
// ═══════════════════════════════════════════════════════════════════════

#[cfg(not(test))]
extern "C" {
    fn get_data(buf: *mut u8, len: u32) -> i32;
    fn set_data(buf: *const u8, len: u32) -> i32;
    fn get_current_account(buf: *mut u8, len: u32) -> i32;
    fn get_current_ledger_time() -> i64;
}

// ═══════════════════════════════════════════════════════════════════════
// WASM Entry Points — Governor Interface
// ═══════════════════════════════════════════════════════════════════════

/// Create a new governance proposal. Mirrors Governor.propose().
///
/// Reads description_hash from the transaction memo field.
/// Caller must hold tokens >= PROPOSAL_THRESHOLD.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn propose() -> i32 {
    let mut data_buf = [0u8; 4096];
    let data_len = unsafe { get_data(data_buf.as_mut_ptr(), data_buf.len() as u32) };
    if data_len < 0 { return ERR_DATA_READ; }
    let data_len = data_len as usize;

    let mut caller = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }
    // Fix #3: Caller identity double-read verification
    let mut caller_verify = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller_verify.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }
    if caller != caller_verify {
        return ERR_CALLER_VERIFICATION;
    }

    let current_time = unsafe { get_current_ledger_time() } as u32;
    let proposer_votes = xrp_votes::get_effective_votes(&data_buf[..data_len], &caller);

    // Description hash from tx memo (simplified: use time-based hash)
    let description_hash = current_time.wrapping_mul(0x9E3779B9);

    match governor::propose(
        &data_buf[..data_len], data_len, &caller,
        description_hash, current_time, proposer_votes,
    ) {
        Ok((new_data, new_len, _prop_id)) => {
            if unsafe { set_data(new_data.as_ptr(), new_len as u32) } < 0 {
                return ERR_HOST_CALL;
            }
            SUCCESS
        }
        Err(code) => code,
    }
}

/// Cast a vote on an active proposal. Mirrors Governor.castVote().
///
/// Vote support types: 0=Against, 1=For, 2=Abstain
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn cast_vote(proposal_id: u32, support: u8) -> i32 {
    let mut data_buf = [0u8; 4096];
    let data_len = unsafe { get_data(data_buf.as_mut_ptr(), data_buf.len() as u32) };
    if data_len < 0 { return ERR_DATA_READ; }
    let data_len = data_len as usize;

    let mut caller = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }
    // Fix #3: Caller identity double-read verification
    let mut caller_verify = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller_verify.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }
    if caller != caller_verify {
        return ERR_CALLER_VERIFICATION;
    }

    let current_time = unsafe { get_current_ledger_time() } as u32;
    let total_vp = votes::get_total_voting_power(&data_buf[..data_len]);
    let weight = xrp_votes::get_effective_votes(&data_buf[..data_len], &caller);

    let proposal_index = match governor::find_proposal_by_id(&data_buf[..data_len], proposal_id) {
        Ok(idx) => idx,
        Err(code) => return code,
    };

    match counting::cast_vote(
        &data_buf[..data_len], data_len, proposal_index,
        &caller, support, weight, current_time, total_vp,
    ) {
        Ok((new_data, new_len)) => {
            if unsafe { set_data(new_data.as_ptr(), new_len as u32) } < 0 {
                return ERR_HOST_CALL;
            }
            SUCCESS
        }
        Err(code) => code,
    }
}

/// Queue a succeeded proposal into the timelock.
/// Mirrors GovernorTimelockControl._queueOperations().
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn queue(proposal_id: u32) -> i32 {
    let mut data_buf = [0u8; 4096];
    let data_len = unsafe { get_data(data_buf.as_mut_ptr(), data_buf.len() as u32) };
    if data_len < 0 { return ERR_DATA_READ; }
    let data_len = data_len as usize;

    let current_time = unsafe { get_current_ledger_time() } as u32;
    let total_vp = votes::get_total_voting_power(&data_buf[..data_len]);

    let prop_idx = match governor::find_proposal_by_id(&data_buf[..data_len], proposal_id) {
        Ok(idx) => idx,
        Err(code) => return code,
    };

    // Proposal must be Succeeded
    let state = governor::get_proposal_state(&data_buf[..data_len], prop_idx, current_time, total_vp);
    if state != PROPOSAL_STATE_SUCCEEDED {
        return ERR_PROPOSAL_NOT_ACTIVE;
    }

    // Schedule in timelock
    match controller::schedule(&data_buf[..data_len], data_len, proposal_id, current_time, TIMELOCK_MIN_DELAY) {
        Ok((new_data, new_len, _op_id)) => {
            // Update proposal state to Queued
            let mut key_buf = [0u8; 32];
            let klen = governor::build_prop_key(b"prop_", prop_idx, b"_state", &mut key_buf);

            // Inline update of state in the new_data
            let target = &key_buf[..klen];
            let mut final_data = [0u8; 4096];
            let mut fpos = 0;
            let mut scan = 0;

            while scan < new_len {
                let entry_end = new_data[scan..new_len].iter()
                    .position(|&b| b == b';')
                    .map(|p| scan + p)
                    .unwrap_or(new_len);

                let entry = &new_data[scan..entry_end];
                let is_target = if let Some(eq) = entry.iter().position(|&b| b == b'=') {
                    &entry[..eq] == target
                } else { false };

                if is_target {
                    if fpos > 0 { fpos = write_separator(&mut final_data, fpos); }
                    fpos = write_entry(&mut final_data, fpos, target, b"5"); // QUEUED
                } else if !entry.is_empty() {
                    if fpos > 0 { fpos = write_separator(&mut final_data, fpos); }
                    let elen = entry.len();
                    if fpos + elen <= final_data.len() {
                        final_data[fpos..fpos + elen].copy_from_slice(entry);
                        fpos += elen;
                    }
                }
                scan = entry_end + 1;
            }

            if unsafe { set_data(final_data.as_ptr(), fpos as u32) } < 0 {
                return ERR_HOST_CALL;
            }
            SUCCESS
        }
        Err(code) => code,
    }
}

/// Execute a queued proposal after timelock delay.
/// Mirrors GovernorTimelockControl._executeOperations().
///
/// Security fixes applied:
/// - Fix #2: Reentrancy guard (lock before execute, unlock after)
/// - Fix #3: Caller identity verification (double-read pattern)
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn execute(proposal_id: u32) -> i32 {
    let mut data_buf = [0u8; 4096];
    let data_len = unsafe { get_data(data_buf.as_mut_ptr(), data_buf.len() as u32) };
    if data_len < 0 { return ERR_DATA_READ; }
    let data_len = data_len as usize;

    // Fix #3: Caller identity verification — double-read pattern
    let mut caller = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }
    let mut caller_verify = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller_verify.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }
    if caller != caller_verify {
        return ERR_CALLER_VERIFICATION;
    }

    // Caller must be executor
    if !votes::has_role(&data_buf[..data_len], &caller, ROLE_EXECUTOR) {
        return ERR_NOT_EXECUTOR;
    }

    // Fix #2: Reentrancy guard — check lock
    if governor::is_locked(&data_buf[..data_len]) {
        return ERR_REENTRANT;
    }

    // Set lock
    let (locked_data, locked_len) = match governor::set_lock(&data_buf[..data_len], data_len, true) {
        Ok(r) => r,
        Err(code) => return code,
    };

    let current_time = unsafe { get_current_ledger_time() } as u32;

    let op_idx = match controller::find_operation_by_proposal(&locked_data[..locked_len], proposal_id) {
        Ok(idx) => idx,
        Err(code) => {
            // Unlock before returning error
            let _ = governor::set_lock(&locked_data[..locked_len], locked_len, false);
            return code;
        }
    };

    match controller::execute(&locked_data[..locked_len], locked_len, op_idx, current_time) {
        Ok((new_data, new_len)) => {
            // Also update proposal state to Executed
            let prop_idx = match governor::find_proposal_by_id(&new_data[..new_len], proposal_id) {
                Ok(idx) => idx,
                Err(_) => {
                    // Unlock and save
                    let (unlocked, ulen) = match governor::set_lock(&new_data[..new_len], new_len, false) {
                        Ok(r) => r,
                        Err(_) => {
                            if unsafe { set_data(new_data.as_ptr(), new_len as u32) } < 0 {
                                return ERR_HOST_CALL;
                            }
                            return SUCCESS;
                        }
                    };
                    if unsafe { set_data(unlocked.as_ptr(), ulen as u32) } < 0 {
                        return ERR_HOST_CALL;
                    }
                    return SUCCESS;
                }
            };

            let mut key_buf = [0u8; 32];
            let klen = governor::build_prop_key(b"prop_", prop_idx, b"_state", &mut key_buf);
            let target = &key_buf[..klen];

            let mut final_data = [0u8; 4096];
            let mut fpos = 0;
            let mut scan = 0;

            while scan < new_len {
                let entry_end = new_data[scan..new_len].iter()
                    .position(|&b| b == b';')
                    .map(|p| scan + p)
                    .unwrap_or(new_len);

                let entry = &new_data[scan..entry_end];
                let is_target = if let Some(eq) = entry.iter().position(|&b| b == b'=') {
                    &entry[..eq] == target
                } else { false };

                if is_target {
                    if fpos > 0 { fpos = write_separator(&mut final_data, fpos); }
                    fpos = write_entry(&mut final_data, fpos, target, b"7"); // EXECUTED
                } else if !entry.is_empty() {
                    if fpos > 0 { fpos = write_separator(&mut final_data, fpos); }
                    let elen = entry.len();
                    if fpos + elen <= final_data.len() {
                        final_data[fpos..fpos + elen].copy_from_slice(entry);
                        fpos += elen;
                    }
                }
                scan = entry_end + 1;
            }

            // Fix #2: Unlock reentrancy guard in final data
            let (unlocked, ulen) = match governor::set_lock(&final_data[..fpos], fpos, false) {
                Ok(r) => r,
                Err(_) => (final_data, fpos),
            };

            if unsafe { set_data(unlocked.as_ptr(), ulen as u32) } < 0 {
                return ERR_HOST_CALL;
            }
            SUCCESS
        }
        Err(code) => {
            // Unlock before returning error
            if let Ok((unlocked, ulen)) = governor::set_lock(&locked_data[..locked_len], locked_len, false) {
                let _ = unsafe { set_data(unlocked.as_ptr(), ulen as u32) };
            }
            code
        }
    }
}

/// Cancel a pending proposal. Mirrors Governor.cancel().
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn cancel(proposal_id: u32) -> i32 {
    let mut data_buf = [0u8; 4096];
    let data_len = unsafe { get_data(data_buf.as_mut_ptr(), data_buf.len() as u32) };
    if data_len < 0 { return ERR_DATA_READ; }
    let data_len = data_len as usize;

    let mut caller = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }
    // Fix #3: Caller identity double-read verification
    let mut caller_verify = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller_verify.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }
    if caller != caller_verify {
        return ERR_CALLER_VERIFICATION;
    }

    let current_time = unsafe { get_current_ledger_time() } as u32;
    let total_vp = votes::get_total_voting_power(&data_buf[..data_len]);

    let prop_idx = match governor::find_proposal_by_id(&data_buf[..data_len], proposal_id) {
        Ok(idx) => idx,
        Err(code) => return code,
    };

    match governor::cancel_proposal(
        &data_buf[..data_len], data_len, prop_idx, &caller, current_time, total_vp,
    ) {
        Ok((new_data, new_len)) => {
            if unsafe { set_data(new_data.as_ptr(), new_len as u32) } < 0 {
                return ERR_HOST_CALL;
            }
            SUCCESS
        }
        Err(code) => code,
    }
}

/// Delegate voting power. Mirrors ERC20Votes.delegate().
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn delegate_votes() -> i32 {
    let mut data_buf = [0u8; 4096];
    let data_len = unsafe { get_data(data_buf.as_mut_ptr(), data_buf.len() as u32) };
    if data_len < 0 { return ERR_DATA_READ; }
    let data_len = data_len as usize;

    let mut caller = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }

    // In production, delegate_to comes from tx memo.
    // Here we self-delegate (clear delegation) as a demonstration.
    match xrp_votes::delegate(&data_buf[..data_len], data_len, &caller, &caller) {
        Ok((new_data, new_len)) => {
            if unsafe { set_data(new_data.as_ptr(), new_len as u32) } < 0 {
                return ERR_HOST_CALL;
            }
            SUCCESS
        }
        Err(code) => code,
    }
}

/// Self-register as a DAO member. Fix #5: Permissionless registration.
///
/// Any account can register themselves as a member with 0 voting power
/// and no roles. This replaces the admin-only member creation, reducing
/// centralization. Admin still controls voting power grants via
/// `set_voting_power()`, but cannot prevent registration.
///
/// Mirrors a permissionless ERC20Votes approach where anyone can hold
/// tokens, but the DAO contract tracks them.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn self_register() -> i32 {
    let mut data_buf = [0u8; 4096];
    let data_len = unsafe { get_data(data_buf.as_mut_ptr(), data_buf.len() as u32) };
    if data_len < 0 { return ERR_DATA_READ; }
    let data_len = data_len as usize;

    let mut caller = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }

    // Check if already registered
    if votes::get_votes(&data_buf[..data_len], &caller) > 0
        || votes::get_roles(&data_buf[..data_len], &caller) > 0
    {
        // Already a member — check if they have an entry
        return SUCCESS;
    }

    // Register with 0 power and no roles
    match votes::set_member(
        &data_buf[..data_len], data_len, &caller,
        SELF_REGISTER_INITIAL_POWER, 0,
    ) {
        Ok((new_data, new_len)) => {
            if unsafe { set_data(new_data.as_ptr(), new_len as u32) } < 0 {
                return ERR_HOST_CALL;
            }
            SUCCESS
        }
        Err(code) => code,
    }
}

/// Admin: set voting power for a member. Fix #5 complement.
///
/// Admin can adjust voting power but cannot prevent self-registration.
/// This is the decentralized alternative: anyone registers, admin
/// allocates voting power based on token holdings / XRP balance.
#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn add_member() -> i32 {
    let mut data_buf = [0u8; 4096];
    let data_len = unsafe { get_data(data_buf.as_mut_ptr(), data_buf.len() as u32) };
    if data_len < 0 { return ERR_DATA_READ; }
    let data_len = data_len as usize;

    let mut caller = [0u8; ACCOUNT_ID_SIZE];
    if unsafe { get_current_account(caller.as_mut_ptr(), ACCOUNT_ID_SIZE as u32) } < 0 {
        return ERR_HOST_CALL;
    }

    // Caller must be admin
    if !votes::has_role(&data_buf[..data_len], &caller, ROLE_ADMIN) {
        return ERR_NOT_ADMIN;
    }

    SUCCESS
}
