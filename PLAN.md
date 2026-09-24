# MonadBFT → Go port for cosmos-evm — Plan

## 1. What we're actually porting

`github.com/category-labs/monad-bft` is the **entire Monad node** in Rust
(~70 crates, ~150k+ LOC), not just a consensus library. The protocol-critical
subset is ~42k LOC; the rest is Monad-specific infra we replace with the
cosmos-evm stack.

### Port (protocol core)

| Rust crate | LOC | Contents | Go package |
|---|---|---|---|
| `monad-types` | 1.3k | Round, Epoch, SeqNum, NodeId, Hash, RouterTarget | `types` |
| `monad-crypto` + `monad-secp` + `monad-bls` + `monad-multi-sig` | 7.4k | secp256k1 protocol sigs, BLS12-381 cert sigs, signing domains | `crypto` |
| `monad-consensus-types` | 3k | ConsensusBlockHeader/Body, Tip, Vote, QC, TC, NEC, Checkpoint, ValidatorSetData | `cstypes` |
| `monad-validator` | 1.4k | stake-weighted ValidatorSet, ValidatorMapping, EpochManager, LeaderElection (weighted RR) | `validator` |
| `monad-consensus` | 8.4k | messages (Proposal/Vote/Timeout/RoundRecovery/NoEndorsement/AdvanceRound), Pacemaker, VoteState, NoEndorsementState, Safety, validation/signing pipeline | `consensus` |
| `monad-consensus-state` | 6.8k | `ConsensusState` — the main state machine; emits `ConsensusCommand` | `consensus/state` |
| `monad-blocktree` | 2.6k | pending block tree, coherency tracking, commit logic | `blocktree` |
| `monad-blocksync` | 3.5k | block sync requester/responder | `blocksync` |
| `monad-state` | 3.3k | `MonadState` top-level dispatch, ConsensusMode (Live/Sync), BlockBuffer, Forkpoint | `state` |
| `monad-executor-glue` | 3k | `MonadEvent`/`Command` enums (the event→command contract) | `glue` |
| `monad-wal` | 1.1k | write-ahead event log (crash safety) | `wal` |
| `monad-chain-config` | 0.7k | chain params/revisions (vote pacing, limits) | `chaincfg` |
| `monad-mock-swarm`/`twins`/`randomized-tests` | 10k | deterministic swarm sim + byzantine twins — port the *approach* | `testutil/sim` |

### Replace (cosmos-evm side)

| Rust crate | Replaced by |
|---|---|
| `monad-eth-txpool*` (~10k) | cosmos-evm `mempool.ExtMempool` + `PrepareProposal` |
| `monad-execution*`, `triedb*` | SDK `FinalizeBlock`/`Commit` (app executes) |
| `monad-eth-block-policy` | `ProcessProposal` + thin coherency policy |
| `monad-eth-ledger`, `monad-ledger` | SDK block store + our consensus block store |
| `monad-rpc` | cosmos-evm JSON-RPC (existing) + small consensus-status RPC |
| `monad-raptorcast`/`monad-raptor`/`monad-dataplane`/`monad-leanudp` (~37k) | **Ported** — RaptorCast is in scope day 1 (Track B) |
| `monad-peer-discovery`, `monad-wireauth` (~17k) | **Ported** — authenticated transport + peer discovery (Track B) |
| `monad-statesync-executor` | SDK snapshot sync via ABCI |
| `monad-node`, `monad-updaters` | new daemon wiring (`cmd/monadbftd`) |
| archive/debugger/testground/mcp/fuzz infra | out of scope (port fuzz harness later) |

## 2. Target architecture

```
cmd/monadbftd            daemon: event loop (MonadEvent -> MonadState.update -> Command dispatch)
  types/                 Round/Epoch/SeqNum/NodeId/Hash + all consensus structs (RLP tags)
  crypto/                secp256k1 (go-ethereum), BLS12-381 (supranational/blst), domains
  validator/             ValidatorSet, ValidatorMapping, EpochManager, LeaderElection
  consensus/             messages, Pacemaker, VoteState, NoEndorsementState, Safety, validation
  consensus/state/       ConsensusState + ConsensusStateWrapper (handlers -> []ConsensusCommand)
  blocktree/             BlockTree (coherency tracking, prune/commit)
  blocksync/             BlockSync state machine
  state/                 MonadState: event dispatch, Live/Sync modes, forkpoint, cert cache
  glue/                  MonadEvent / Command / LedgerCommand / RouterCommand / TxPoolCommand
  wal/                   append-only event log (RLP), replay on boot
  store/                 consensus block store (headers+bodies+QC) — pebble; forkpoint file
  net/
    raptor/              RFC 6330 RaptorQ codec (GF(256), LDPC+LT, systematic index)
    raptorcast/          chunk assignment, broadcast router, group maps, rebroadcast
    raptorcast/secondary full-node publisher/client path
    dataplane/           UDP (mmsg batching, prio, ban) + TCP point-to-point
    wireauth/            Noise-based session auth, handshake, replay filter, cookies
    peerdisc/            peer discovery + signed name records
  abci/                  adapter: commands <-> cosmos-sdk ABCI calls
  rpc/                   minimal consensus RPC (status, block, validators) + tx broadcast
testutil/sim/            deterministic swarm harness (virtual clock, in-memory transport)
```

The core stays **pure & synchronous**: `update(event) -> []Command`, exactly like
Rust. All I/O lives in executors. This is what makes the port testable and lets
us replay the Rust test scenarios 1:1.

## 3. Seam mapping: Monad ↔ cosmos-evm (ABCI 2.0 / SDK v0.54 / CometBFT v0.39 types)

| Monad command | cosmos-evm realization |
|---|---|
| `ConsensusCommand::CreateProposal` / `TxPoolCommand::CreateProposal` | call app `PrepareProposal` (mempool reaps txs); wrap result in `ProposalMessage`; self-deliver via consensus event → `RouterCommand::Publish` |
| `BlockValidator.validate` + `BlockPolicy.check_coherency` | `ProcessProposal` (app validates txs) + structural checks (seqnum, timestamp, author=leader, delayed results) |
| `CommitBlocks(Finalized)` | `FinalizeBlock` + `Commit`; populate `decided_last_commit` from parent-QC signer bitmap (keeps x/slashing liveness working); collect `validator_updates` |
| `CommitBlocks(Proposed/Verified)` | phase 2: speculative `FinalizeBlock` on branched state → "pending" RPC |
| `ValidatorEvent::UpdateValidators` | built from `FinalizeBlockResponse.validator_updates` at epoch-boundary commit, joined with consensus-key registry (see §4) |
| `MempoolEvent::ForwardedTxs` | `CheckTx` → insert into `ExtMempool` |
| `RequestSync` (blocksync) | fetch blocks from peers' consensus store |
| `RequestStateSync` | SDK snapshot restore (`OfferSnapshot`/`ApplySnapshotChunk`) then catch up via blocksync |
| `TimestampUpdate` | local clock adjust |
| `LedgerCommand::LedgerCommit` | write to consensus block store (headers/bodies/QC, forkpoint) |
| `ConfigFileCommand` (forkpoint, valset data) | `forkpoint.rlp` + `validators.toml` equivalents |

## 4. Key design decisions (to confirm)

### 4.1 Execution model — **DECIDED: sync now, defer later**
Monad decouples ordering from execution: a proposal embeds
`delayed_execution_results` (finalized headers from `seq_num - execution_delay`)
and `check_coherency` verifies them against `ExecutionStateRead`.
- **v1 (build first): synchronous at commit.** `execution_delay=0` semantics:
  `delayed_execution_results` always empty, policy doesn't consult execution
  state; `FinalizeBlock`+`Commit` run when the 2-chain commit fires. Consensus
  machine ported unmodified; simplest correct ABCI integration.
- **v2 (Phase 6): deferred/speculative execution.** Run `FinalizeBlock`
  speculatively when a block becomes coherent/QC'd, embed resulting
  AppHash/EVM-block-hash into proposals `delay` blocks later. Preserves Monad's
  pipelined execution + speculative finality UX. Needs per-branch finalize
  state tracking in the adapter (SDK executes on a cached branch — feasible,
  bigger lift).

### 4.2 Validator keys — **DECIDED: registry module**
Monad validators carry **two** keys: secp256k1 (NodeId, message integrity) and
BLS12-381 (vote/timeout aggregation). Cosmos validators have ed25519 comet keys.
Plan: small `x/consensuskeys` module mapping `valoper -> {secp256k1 pubkey,
BLS pubkey}` with self-signed proof-of-possession; set at genesis and updatable
via tx. The ABCI adapter joins `ValidatorUpdates` (power) with the registry to
build `ValidatorSetDataWithEpoch`. Genesis tooling emits the initial set.

### 4.3 Epochs vs per-block valsets
Monad locks a valset per epoch (`epoch_length` blocks, start scheduled
`epoch_start_delay` rounds ahead). Cosmos valsets can change every block.
Plan: pick `epoch_length` (e.g. 100 blocks); at each boundary-block commit,
snapshot the post-update valset as next epoch's locked set and emit
`ValidatorEvent::UpdateValidators` + `AddEpochValidatorSet`.

### 4.4 Serialization & crypto — **DECIDED: byte-identical**
Keep **RLP + blake3 + secp256k1 + BLS12-381 + signing-domain prefixes
byte-identical** to Rust (`alloy_rlp` derive ordering, `\xNNmonad/<domain>/1\n`
prefixes, `ProtocolMessage` tagged-list encoding, `SignerMap` reversed-bit
encoding, `#[rlp(trailing)]` optionals, PhantomData zero-width fields).
Signed digests depend on encoding — parity lets us reuse Rust test vectors
and run cross-implementation conformance tests.

Note: consensus hashing is **blake3**, not keccak — `monad-types::Hasher` =
blake3; `Vote`/`TimeoutInfo`/header digests are blake3 over RLP.
Ethereum keccak only appears inside EVM execution payloads (geth side).

Go deps: own `rlp` package (alloy-canonical strictness: non-canonical
single-byte/leading-zero/long-form rejection differs from geth's rlp),
`go-ethereum/crypto/secp256k1` (libsecp256k1 cgo — identical to Rust),
`supranational/blst` bindings, `zeebo/blake3`.
Wire-compat with Monad mainnet is NOT a goal (different chain), but byte-parity
is cheap and hugely useful for testing.

### 4.5 Transport — **DECIDED: RaptorCast from day 1 (Track B)**
Port the full Monad networking stack; see Track B in §5. Interim dev/testing
uses a loopback/TCP transport behind the same `RouterCommand` interface —
exactly how `monad-mock-swarm` tests the Rust code — so Track A (consensus) is
never blocked by Track B (network).

### 4.6 Crash safety
Port `monad-wal` semantics faithfully: every `MonadEvent` appended to WAL
before dispatch; on boot replay over last forkpoint. Persist `Safety`
(highest_vote/propose/no_endorse, high_certificate, maybe_high_tip) — this is
the double-sign protection. Forkpoint file format identical to Rust
(`root`, `high_certificate`, `validator_sets: [LockedEpoch]`).

### 4.7 Things to know/limits
- `maybe_statesync` **panics** in Rust (restart → statesync path); in Go we
  surface a typed error → supervisor restarts into sync mode.
- CometBFT replacement breaks: CometBFT RPC (provide compat subset), IBC
  Tendermint light clients (needs custom QC-based light client — out of scope
  for v1; IBC can come back via a wasm/custom client later), `x/evidence`
  Tendermint evidence types (map equivocation → misbehavior in `FinalizeBlock`
  in phase 2).
- Vote extensions: unused (Monad votes carry no app data).
- Metrics: port `Metrics` to Prometheus (Rust impl already is).

## 5. Phased plan — two parallel tracks

The `RouterCommand`/`RouterTarget` boundary means consensus (Track A) never
depends on the transport (Track B): all Track-A testing runs on
loopback/in-memory transports — exactly how `monad-mock-swarm` exercises the
Rust code — and RaptorCast drops in as an executor when ready.

### Track A — consensus + app integration

**A0 — Foundations** ✅ *in progress / largely done*
Repo skeleton (`go.mod`), types, RLP encode/decode, crypto
(secp256k1 + BLS via blst + domains). Conformance vectors extracted from Rust
unit tests — matching byte-for-byte:
`rlp/` (alloy-exact encode/decode incl. strictness), `types/` (Round, Epoch,
SeqNum, Stake, Hash, BlockId, NodeId — compressed-pubkey ordering),
`crypto/` (domains, secp256k1 sign/recover, BLS min-pk sign/verify/aggregate),
`sigcol/` (SignerMap, BlsSignatureCollection), `validator/` (ValidatorSet,
ValidatorMapping, EpochManager, ChaCha20Rng-seeded weighted election),
`exec/` (protocol seam + Mock impl), `cstypes/` (Vote, QC, TimeoutInfo,
Timeout, TC, NEC, FPC, ConsensusTip, RoundCertificate, ConsensusBlockHeader/
Body), `messages/` (Vote/Timeout/Proposal/AdvanceRound/RoundRecovery/NE msgs,
ProtocolMessage tags, ConsensusMessage envelope, Verified/Unverified).
Verified against Rust fixture vectors: all encode byte-identical, sigs verify,
leader election matches rounds 0–7.

**A1 — Consensus core (pure)**
`validator` → `consensus-types` → `blocktree` → `vote_state` →
`no_endorsement_state` → `pacemaker` → `safety` → `validation/signing` →
`consensus-state` handlers (proposal, vote, timeout, round_recovery,
no_endorsement, advance_round, blocksync, vote timer, ledger update).
Port Rust unit tests (vote_state, pacemaker phases, qc, proposal suite ≈4k
LOC of tests are a strong spec).

**A2 — MonadState + simulation harness**
`monad-state` dispatch (Live/Sync modes, block buffer, forkpoint mgmt,
certificate cache), command translation, mock executors, deterministic
mock-swarm (virtual time + in-memory net + fault-injection transformers).
Tests: happy path, leader timeout→TC, NEC reproposal, round recovery,
blocksync, epoch transition, state-sync trigger.

**A3 — Persistence**
Consensus block store (pebble), WAL, forkpoint writer; crash-recovery tests
(kill -9 mid-round, replay; no double-sign).

**A4 — ABCI bridge + evmd** ✅ *milestone reached*
Nested `bridge/` module (core stays dep-free; evmd via local `replace`).
ABCI-backed swarm executors: `Ledger` (FinalizeBlock+Commit per finalized
block, `DecidedLastCommit` from parent-QC signer bitmap → VoteInfo in valset
order), `TxPool` (ReapTxs + PrepareProposal for block building; CheckTx +
InsertTx for submission), `ValSet` (ValidatorUpdates → EvUpdateValidators at
epoch boundaries), `StateRead` (committed-height app-hash index for
delayed-execution results). Genesis tooling in `evmdapp.go` (deterministic
valset keys, slashing signing infos, bonded-pool top-up for N validators).
Key adaptation: PrepareProposal runs at app height (committed tip + 1), not
consensus seq — CometBFT's mempool assumes sequential heights; MonadBFT
pipelines ~2 seqs ahead. ProcessProposal is not in the hot path (Rust's
check_coherency doesn't re-execute; pipelined proposals outrun the finalized
tip anyway) — `MockBlockPolicy` does the structural checks.
Verified: `TestBridgeOneNode` + `TestBridgeFourNodes` — 4 in-process evmd
apps reach height 12 with byte-identical app hashes (`-tags=test`).
Remaining: `x/consensuskeys` registry module on the cosmos-evm side (binds
app cons keys ↔ MonadBFT node/cert keys for on-chain valset exchange).

**A5 — Loopback/TCP interop transport (test-only)**
Minimal transport satisfying `RouterCommand` so Track-A E2E runs before Track B
lands. Deliberately thin — superseded by Track B.

### Track B — RaptorCast networking stack (day-1 scope)

Bottom-up dependency order; each layer independently testable. Port the Rust
network tests too (`raptorcast_instance`, `wireauth_raptorcast`,
`epoch_boundary`, `dataplane/tests`, `leanudp/tests`).

**B1 — `net/raptor`: RaptorQ codec (port of `monad-raptor`, ~4.7k LOC)**
GF(256) tables, LDPC/Half/LT sub-codes, systematic index, decoder w/
inactivation. Dense but mechanical math port; verify symbol-level vs Rust
encoder outputs.

**B2 — `net/dataplane` + `net/wireauth` (~16k LOC Rust)**
UDP dataplane (batched send/recv — Go: `golang.org/x/net` packet batching or
per-packet), priority queues, rate limit, ban list; TCP point-to-point
fallback. WireAuth: Noise-based handshake, session mgmt, replay filter, DoS
cookies — wire-identical for compat tests.

**B3 — `net/peerdisc` (~6.7k LOC)**
Signed name records, ping/pong liveness, peer table, bootstrap.

**B4 — `net/raptorcast` primary (~18k LOC)**
Chunk assignment (`packet/assigner` — stake-weighted symbol distribution),
packet layout + parser, per-epoch validator-group routing, rebroadcast windows
(`round_info`), message expiry, sig-verification rate limiting.

**B5 — `net/raptorcast` secondary (~4.5k LOC)**
Full-node publisher/client: validators rebroadcast to full-node groups;
confirm-group peers (`SecondaryRaptorcastPeersUpdate` event).

**B6 — Integration**
RaptorCast executor into `monadbftd` behind `RouterCommand`; validators on
raptorcast/UDP, full nodes on secondary RC, TCP for statesync/large responses.

### Track C — hardening & ecosystem (after A4 + B6)

**C1** Byzantine/twins tests, fuzzing, metrics/dashboards, crash matrix.
**C2** CometBFT-RPC-compat shim, equivocation→`x/evidence`, snapshot
statesync tuning.
**C3** Deferred/speculative execution (§4.1 v2), vote-pacing tuning,
IBC-via-custom-light-client exploration.

## 6. Sizing estimate (rough)

- Track A consensus core: ~20–25k LOC Go (incl. ported tests)
- Track A integration (abci, store, wal, daemon, rpc): ~10–14k LOC
- Track B networking: ~25–35k LOC Go (raptor ~5k, dataplane+wireauth ~10k,
  peerdisc ~4k, raptorcast ~14k incl. secondary)
- Test harness (sim + twins + fixtures): ~3–5k LOC
- **Total: ~60–75k LOC Go** — networking is now roughly equal to consensus.

## 7. Testing strategy

1. **Vector conformance**: RLP bytes & signature digests vs Rust fixtures.
2. **Ported unit tests**: vote_state, pacemaker, safety, blocktree,
   consensus-state test suite (mockswarm-driven in Rust — we rebuild in Go).
3. **Deterministic swarm sim**: seeded, virtual clock; assert ledger prefix
   consistency & liveness; fault injection (drops, delays, dup, equivocation).
4. **Twin tests**: byzantine replicas of honest state machines (port of
   monad-twins) for tail-forking/equivocation scenarios.
5. **E2E**: evmd localnet; crash/restart; statesync; epoch rotation.

## 8. Open questions

- ~~Target repo/module path~~ **DECIDED**: standalone module
  `github.com/abhijitkrm/monadbft-go`; cosmos-evm will be forked and consume it
  as a dependency.
- Is interop with Monad mainnet/devnet needed, or standalone cosmos-evm chain?
  (assumed: standalone — wire parity kept anyway for testability)
- Validator set size target & max block size → tunes raptorcast params
  (group size, redundancy factor, mtu).
- Do we need IBC on day 1? (drives the light-client question — CometBFT
  light clients won't verify MonadBFT QCs)
- `epoch_length` / `epoch_start_delay` / `delta` / `vote_pace` values for the
  target chain (Rust defaults live in `monad-chain-config`).
