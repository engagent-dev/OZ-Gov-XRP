# OZ-Gov-XRP

**OpenZeppelin Governor + TimelockController ported to XRPL WASM**

A full governance system mirroring OpenZeppelin v4.x contracts, adapted for XRPL's WebAssembly smart contract environment. No-std, zero-heap, pure Rust — compiles to a single `.wasm` binary deployable on XRPL.

## Architecture Mapping

| OpenZeppelin (Solidity)           | XRPL DAO (Rust WASM)            |
|-----------------------------------|----------------------------------|
| `Governor.sol`                    | `governance::governor`           |
| `GovernorCountingSimple.sol`      | `governance::counting`           |
| `GovernorVotes.sol`               | `governance::votes`              |
| `GovernorVotesQuorumFraction.sol` | `governance::votes::quorum()`    |
| `GovernorSettings.sol`            | `foundation::config`             |
| `GovernorTimelockControl.sol`     | `timelock::controller`           |
| Timelock predecessors / batches   | `timelock::operations`           |
| `ERC20Votes`                      | `token::xrp_votes`              |
| `AccessControl`                   | `governance::votes` (roles)      |
| `castVoteBySig` / EIP-712        | `governance::signatures`         |

## WASM Exports

Verified via [Octopus](https://github.com/FuzzingLabs/octopus) static analysis:

| Export           | Signature       | OZ Equivalent                          |
|------------------|-----------------|----------------------------------------|
| `propose`        | `() → i32`      | `Governor.propose()`                   |
| `cast_vote`      | `(i32, i32) → i32` | `Governor.castVote()`              |
| `queue`          | `(i32) → i32`   | `GovernorTimelockControl.queue()`      |
| `execute`        | `(i32) → i32`   | `GovernorTimelockControl.execute()`    |
| `cancel`         | `(i32) → i32`   | `Governor.cancel()`                    |
| `delegate_votes` | `() → i32`      | `ERC20Votes.delegate()`               |
| `self_register`  | `() → i32`      | Permissionless member registration     |
| `add_member`     | `() → i32`      | Admin voting power management          |

### Host Imports

| Import                     | Signature              | Purpose                    |
|----------------------------|------------------------|----------------------------|
| `env::get_data`            | `(i32, i32) → i32`    | Read escrow data field     |
| `env::set_data`            | `(i32, i32) → i32`    | Write escrow data field    |
| `env::get_current_account` | `(i32, i32) → i32`    | Get caller AccountID       |
| `env::get_current_ledger_time` | `() → i64`        | Current ledger close time  |

## Proposal Lifecycle

```
Pending (0) → Active (1) → Succeeded (4) → Queued (5) → Executed (7)
           ↘ Canceled (2)  ↘ Defeated (3)
                                          ↘ Expired (6)
```

## Configuration

| Parameter            | Value      | OZ Equivalent                  |
|----------------------|------------|--------------------------------|
| `VOTING_DELAY`       | 300s       | `votingDelay()` (~5 min)       |
| `VOTING_PERIOD`      | 259,200s   | `votingPeriod()` (~3 days)     |
| `PROPOSAL_THRESHOLD` | 100 XRP    | `proposalThreshold()`          |
| `QUORUM_PERCENTAGE`  | 4%         | `GovernorVotesQuorumFraction`  |
| `TIMELOCK_MIN_DELAY` | 172,800s   | `getMinDelay()` (~2 days)      |
| `TIMELOCK_GRACE_PERIOD` | 1,209,600s | Expiry window (~14 days)    |

## Security

8 security gaps vs. OpenZeppelin Solidity identified and fixed:

| # | Gap | Fix |
|---|-----|-----|
| 1 | Weak proposal ID (XOR) | FNV-1a hash binding proposer + description + time + nonce |
| 2 | No reentrancy guard | `_lock` key in data store, wired into `execute()` |
| 3 | Trusted caller identity | Double-read verification on all entry points |
| 4 | No vote-by-signature | Signature framework with domain-prefixed messages |
| 5 | Admin-only member registry | Permissionless `self_register()` + admin power grants |
| 6 | No overflow protection | `checked_add()` / `saturating_add()` on all arithmetic |
| 7 | Single-digit index limit | `format_u8()` supporting indices 0-255 |
| 8 | No timelock grace period | 14-day expiry window, `ERR_OP_EXPIRED` rejection |

Full details in [docs/SECURITY_CHANGELOG.md](docs/SECURITY_CHANGELOG.md).

## Project Structure

```
src/
├── lib.rs                        # 8 WASM entry points
├── foundation/
│   ├── allocator.rs              # Bump allocator + panic handler
│   ├── config.rs                 # All constants, states, error codes
│   ├── data.rs                   # Semicolon-delimited KV store
│   ├── parse.rs                  # ASCII number parsing
│   └── types.rs                  # Proposal, Member, TimelockOp, VoteRecord
├── crypto/
│   ├── hash.rs                   # FNV-1a proposal/operation ID hashing
│   └── hex.rs                    # Hex encode/decode
├── governance/
│   ├── governor.rs               # Proposal lifecycle, reentrancy guard
│   ├── counting.rs               # For/Against/Abstain tallying
│   ├── votes.rs                  # Member registry, roles, quorum
│   └── signatures.rs             # Vote-by-signature framework
├── timelock/
│   ├── controller.rs             # Schedule/execute/cancel with grace period
│   └── operations.rs             # Predecessor dependencies, batch ops
└── token/
    └── xrp_votes.rs              # Delegation, snapshots, effective votes
```

## Build

```bash
# Tests (138 passing)
cargo test

# WASM binary
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
# → target/wasm32-unknown-unknown/release/xrpl_token_dao.wasm
```

## Static Analysis (Octopus)

```bash
pip install octopus
python -c "
from octopus.arch.wasm.analyzer import WasmModuleAnalyzer
with open('target/wasm32-unknown-unknown/release/xrpl_token_dao.wasm', 'rb') as f:
    analyzer = WasmModuleAnalyzer(f.read())
for p in analyzer.func_prototypes: print(p)
"
```

**Results:** 93 functions total — 8 exported entry points, 4 host imports, 81 internal functions. No unauthorized exports detected.

## Data Format

All state stored in XRPL escrow `Data` field as semicolon-delimited `key=value` pairs:

```
member_count=3;member_0=aa00...00aa:500000000:7;member_1=bb00...00bb:300000000:0;
proposal_count=1;prop_0_id=2847361;prop_0_state=1;prop_0_for=800000000;...
op_count=1;op_0_id=9182736;op_0_ready=473800;op_0_state=1;...
delegate_aa00...00aa=bb00...00bb;snap_2847361_aa00...00aa=500000000
```

## Docs

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — Full module mapping, API reference
- [SECURITY_CHANGELOG.md](docs/SECURITY_CHANGELOG.md) — All 8 security fixes documented

## License

MIT