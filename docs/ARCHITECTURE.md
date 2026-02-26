# XRPL Token DAO — OpenZeppelin Governor for XRPL WASM

A complete on-chain governance system for XRPL smart contracts, mirroring
OpenZeppelin's Governor + TimelockController (v4.x) architecture.

## Architecture Mapping

| OpenZeppelin (Solidity)         | XRPL DAO (Rust WASM)           | Description                            |
|---------------------------------|--------------------------------|----------------------------------------|
| `Governor.sol`                  | `governance::governor`         | Proposal lifecycle, state machine      |
| `GovernorCountingSimple.sol`    | `governance::counting`         | For/Against/Abstain vote tallying      |
| `GovernorVotes.sol`             | `governance::votes`            | Voting power from member registry      |
| `GovernorVotesQuorumFraction`   | `governance::votes::quorum()`  | Quorum as % of total voting power      |
| `GovernorSettings.sol`          | `foundation::config`           | Configurable governance constants      |
| `TimelockController.sol`        | `timelock::controller`         | Delayed execution with roles           |
| Timelock predecessors/batches   | `timelock::operations`         | Operation dependencies                 |
| `ERC20Votes`                    | `token::xrp_votes`            | Delegation, snapshots, effective power |
| `AccessControl`                 | `governance::votes` (roles)    | Role-based access (admin/proposer/executor) |

## Module Structure

```
src/
├── lib.rs                          # WASM entry points (8 exports)
├── foundation/
│   ├── allocator.rs                # WASM bump allocator
│   ├── config.rs                   # Constants, error codes, state enums
│   ├── data.rs                     # Key=value data store operations
│   ├── parse.rs                    # ASCII number parsing/formatting
│   └── types.rs                    # Proposal, Member, TimelockOp structs
├── crypto/
│   └── hex.rs                      # Hex encode/decode (AccountID handling)
├── governance/
│   ├── governor.rs                 # Core proposal lifecycle
│   ├── counting.rs                 # Vote tallying (For/Against/Abstain)
│   └── votes.rs                    # Member registry, roles, voting power
├── timelock/
│   ├── controller.rs               # Schedule/execute/cancel with delay
│   └── operations.rs               # Predecessor dependencies
├── token/
│   └── xrp_votes.rs               # Delegation, snapshots, effective votes
└── tests/
    ├── mod.rs                      # Shared test helpers
    ├── foundation/{data,parse}_tests.rs
    ├── crypto/hex_tests.rs
    ├── governance/{governor,counting,votes}_tests.rs
    ├── timelock/{controller,operations}_tests.rs
    └── token/xrp_votes_tests.rs
```

## WASM Exports

| Export          | OZ Equivalent           | Description                                  |
|-----------------|-------------------------|----------------------------------------------|
| `propose()`     | `Governor.propose()`    | Create a governance proposal                 |
| `cast_vote()`   | `Governor.castVote()`   | Vote For/Against/Abstain on active proposal  |
| `queue()`       | `Governor.queue()`      | Queue succeeded proposal into timelock       |
| `execute()`     | `Governor.execute()`    | Execute ready timelock operation             |
| `cancel()`      | `Governor.cancel()`     | Cancel pending proposal (proposer only)      |
| `delegate_votes()` | `ERC20Votes.delegate()` | Delegate voting power                     |
| `add_member()`  | (admin function)        | Add/update DAO member (admin only)           |
| `grant_role()`  | `AccessControl.grantRole()` | Grant role to account (admin only)       |

## Proposal Lifecycle

```
                    ┌───────────┐
        propose()   │  Pending  │   cancel() (proposer only)
        ──────────► │  (0)      │ ──────────────────────────► Canceled (2)
                    └─────┬─────┘
                          │ vote_start reached
                    ┌─────▼─────┐
                    │  Active   │   cast_vote()
                    │  (1)      │ ◄──────────────
                    └─────┬─────┘
                          │ vote_end reached
                    ┌─────▼─────────────┐
                    │  quorum met?      │──No──► Defeated (3)
                    │  for > against?   │
                    └─────┬─────────────┘
                          │ Yes
                    ┌─────▼─────┐
        queue()     │ Succeeded │
        ──────────► │  (4)      │
                    └─────┬─────┘
                          │
                    ┌─────▼─────┐
                    │  Queued   │   (timelock delay)
                    │  (5)      │
                    └─────┬─────┘
                          │ delay expires
                    ┌─────▼─────┐
        execute()   │  Ready    │
        ──────────► │           │
                    └─────┬─────┘
                          │
                    ┌─────▼─────┐
                    │ Executed  │
                    │  (7)      │
                    └───────────┘
```

## Timelock Operation Lifecycle

Mirrors `TimelockController.sol`:

```
    schedule()          timer expires         execute()
Unset ──────► Pending ──────────────► Ready ──────────► Done
                │                                         
                └──── cancel() ──────► Unset              
```

Operations can have **predecessors** — a dependency that must be in `Done` state
before the dependent operation can execute. This enables ordered multi-step governance.

## Data Format

All state is stored in the XRPL escrow's Data field as semicolon-delimited
key=value pairs. No heap allocation — everything operates on fixed-size stack buffers.

### Member Registry

```
member_count=3;member_0=aa00...aa:200000000:5;member_1=bb00...bb:100000000:2;member_2=cc00...cc:150000000:0
```

Format: `member_N=<account_hex_40>:<voting_power>:<role_bitmask>`

Role bitmask: `PROPOSER=1 | EXECUTOR=2 | ADMIN=4`

### Proposals

```
proposal_count=1;prop_0_id=12345;prop_0_proposer=aa00...aa;prop_0_state=1;prop_0_start=1300;prop_0_end=260500;prop_0_for=200000000;prop_0_against=100000000;prop_0_abstain=0;prop_0_desc=67890
```

### Vote Records

```
vote_0_0=aa00...aa:1:200000000;vote_0_1=bb00...bb:0:100000000
```

Format: `vote_<prop_idx>_<vote_idx>=<voter_hex>:<support>:<weight>`

### Timelock Operations

```
op_count=1;op_0_id=99999;op_0_prop=12345;op_0_ready=174800;op_0_state=1;op_0_predecessor=0
```

### Delegation

```
delegate_aa00...aa=bb00...bb
```

### Voting Snapshots

```
snap_42_aa00...aa=200000000
```

## Configuration Constants

| Constant              | Value     | OZ Equivalent                   | Description                    |
|-----------------------|-----------|---------------------------------|--------------------------------|
| `VOTING_DELAY`        | 300s      | `votingDelay()`                 | Delay before voting starts     |
| `VOTING_PERIOD`       | 259,200s  | `votingPeriod()`                | Voting window (~3 days)        |
| `PROPOSAL_THRESHOLD`  | 100 XRP   | `proposalThreshold()`           | Min balance to propose         |
| `QUORUM_PERCENTAGE`   | 4%        | `GovernorVotesQuorumFraction`   | Required quorum                |
| `TIMELOCK_MIN_DELAY`  | 172,800s  | `getMinDelay()`                 | Timelock delay (~2 days)       |
| `MAX_MEMBERS`         | 20        | —                               | Max tracked members            |
| `MAX_PROPOSALS`       | 10        | —                               | Max concurrent proposals       |

## Vote Types

Mirrors `GovernorCountingSimple.sol`:

| Value | Name    | Effect                                    |
|-------|---------|-------------------------------------------|
| 0     | Against | Counts against the proposal               |
| 1     | For     | Counts for the proposal                   |
| 2     | Abstain | Counts toward quorum but not for/against  |

**Quorum formula:** `(for_votes + abstain_votes) >= (total_supply × 4%)`

**Success formula:** `for_votes > against_votes`

## Error Codes

| Code | Name                   | Description                          |
|------|------------------------|--------------------------------------|
| 1    | `SUCCESS`              | Operation completed successfully     |
| -1   | `ERR_WRONG_ACCOUNT`    | Caller is not the expected account   |
| -2   | `ERR_TOO_EARLY`        | Timelock delay not met               |
| -4   | `ERR_DATA_READ`        | Failed to read contract data         |
| -5   | `ERR_HOST_CALL`        | WASM host function call failed       |
| -6   | `ERR_BAD_CONFIG`       | Invalid configuration (max members)  |
| -7   | `ERR_ALREADY_VOTED`    | Account already voted on proposal    |
| -8   | `ERR_PROPOSAL_NOT_ACTIVE` | Proposal not in expected state    |
| -9   | `ERR_BELOW_THRESHOLD`  | Voting power below proposal threshold|
| -10  | `ERR_MAX_PROPOSALS`    | Maximum concurrent proposals reached |
| -11  | `ERR_NOT_PROPOSER`     | Caller is not the proposal's proposer|
| -12  | `ERR_NOT_EXECUTOR`     | Caller lacks executor role           |
| -13  | `ERR_OP_NOT_READY`     | Timelock operation not ready         |
| -14  | `ERR_OP_ALREADY_QUEUED`| Operation already scheduled          |
| -15  | `ERR_PROPOSAL_NOT_FOUND`| No proposal with given ID          |
| -16  | `ERR_INVALID_VOTE`     | Support value not 0, 1, or 2        |
| -18  | `ERR_NOT_ADMIN`        | Caller lacks admin role              |

## Build & Test

```bash
cd xrpl-dao

# Run tests
cargo test -- --nocapture

# Build WASM binary
cargo build --target wasm32-unknown-unknown --release

# Output: target/wasm32-unknown-unknown/release/xrpl_token_dao.wasm
```

## Key Design Decisions

### No Heap Allocation (`#![no_std]`)
All operations use fixed-size stack buffers (`[u8; 4096]`). This is required by
the XRPL WASM sandbox which doesn't provide a heap allocator.

### Semicolon-Delimited Data Store
Rather than Solidity's storage slots, state is stored as ASCII key=value pairs
in the escrow's Data field. This mirrors the XRPL hook data specification and
allows inspection via standard XRPL tools.

### XRP-Native Voting Power
Instead of ERC20 token balances, voting power comes from an admin-managed
member registry. This maps to XRPL's account-based model where token issuance
follows trust lines, not contract-internal balances.

### Role-Based Access via Bitmask
OpenZeppelin uses `bytes32` role identifiers with `AccessControl`. We use a
single `u8` bitmask per member: `PROPOSER=1`, `EXECUTOR=2`, `ADMIN=4`. This
is more compact for the constrained WASM environment.

## Delegation Model

Mirrors `ERC20Votes.delegate()`:

- **Self-delegation** (default): Voting power applies to the member themselves
- **Delegate to another**: Voting power transfers to the delegate for governance
- **Redelegation**: Delegating to yourself removes any existing delegation

Effective voting power = own power (if self-delegated) + all power delegated from others.
