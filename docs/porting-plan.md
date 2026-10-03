# MonadBFT-for-Cosmos-EVM — Production Porting & Integration Plan

Scope: finish the `monadbft-go` port to production grade and integrate it into
`cosmos/evm` as a CometBFT replacement, for block-time/finality performance and
validator-scale networking.

Repos:
- `github.com/abhijitkrm/monadbft-go` — consensus core + `bridge/` (this repo)
- `github.com/abhijitkrm/monad-evm` — maintained `cosmos/evm` fork (SDK
  v0.54.3, CometBFT v0.39.3, geth via `cosmos/go-ethereum v1.17.2-cosmos-0`):
  adds the pluggable engine seam (`engine/`), `evmd --engine` flag, and
  `evmd start` monadbft integration on branch `monadbft-engine-seam`

Verified state (2026-09-28): core `go test ./...` all green; `bridge` tests
(`-tags=test`) green — 4 in-process evmd nodes reach height 12 with identical
app hashes and a real signed `MsgEthereumTx` inclusion.

---

## 0. Executive summary

The hard part is done: the consensus *protocol* is faithfully ported —
byte-exact RLP/secp256k1/BLS12-381/blake3 against Rust fixtures, full pacemaker
/ safety / vote / NE / blocktree / MonadState state machine, WAL + Pebble
blockstore + forkpoint, deterministic swarm simulator, and a working ABCI 2.0
bridge that drives real `evmd` apps.

What does **not** exist is everything that makes it a *node*:

| Missing | Consequence |
|---|---|
| No transport (not even TCP) | multi-process validators impossible |
| No daemon/event loop | nothing runs wall-clock; `swarm` is a discrete-event test driver |
| WAL never replayed | crash recovery unproven |
| Statesync = `NopStateSync` + `maybeStatesync` **panics** | a lagging node crashes by design (mirrors Rust, but no supervisor exists) |
| No `x/consensuskeys` | cons↔secp256k1↔BLS binding is genesis-injected only |
| No RPC surface | nothing can query blocks/status; Ethereum JSON-RPC has no data source |
| No evidence emission | equivocation tracked but never reported → slashing silently off |
| No metrics exporter / ops tooling | counters only, no Prometheus |

On the cosmos-evm side, CometBFT is embedded at seven layers: node runtime
(`server/start.go`), Ethereum JSON-RPC backend (`rpc/backend` →
`cmtrpcclient.SignClient`), event bus/websockets (`rpc/stream`), EVM tx indexer
(`server/indexer_*` — reads CometBFT DB schema directly), mempool notification
wiring, `evmd block` CLI (raw CometBFT blockstore reader), and IBC's Tendermint
light client. The SDK application itself (`BaseApp`, module manager, `x/vm`)
is engine-neutral — it only sees `servertypes.ABCI` calls.

**Architecture decision that frames everything:** keep the app untouched and
replace the *engine around it* — the same pattern CometBFT already uses
(in-process, ABCI 2.0). The bridge proves the mapping is sound; the remaining
work is large but mostly engineering surface area, not protocol risk.

---

## 1. Design decisions to lock first (Phase 0)

These are cheap now and expensive to change later.

### D1 — Node topology: in-process engine (recommended)

`evmd` binary embeds the MonadBFT engine directly — same shape as today, where
CometBFT runs in-process via `node.NewNode` + `proxy.NewLocalClientCreator`
(`server/start.go`).

- **Option A (recommended): in-process.** `evmd start` launches the MonadBFT
  event loop instead of `node.NewNode`. Single binary, no IPC, matches Cosmos
  operational norms, preserves mempool/PrepareProposal call semantics.
- **Option B: sidecar** — `monadbftd` as a separate process over ABCI sockets.
  CometBFT technically supports this (`--with-cometbft=false`), but adds
  serialization on every consensus step, complicates the heightsync coupling,
  and Cosmos tooling assumes one binary. Only worth it if you want app-engine
  fault isolation.
- **Option C: generic engine interface in the SDK** — upstream-grade
  abstraction (`cosmos-sdk` defining an engine seam). Correct long-term but a
  multi-repo political project; don't block on it.

### D2 — Block/tx hash identity

- Cosmos tx hash today = `tmhash(txbytes)` — keep it explicitly as the
  canonical tx hash (it is pure hashing, not engine-bound). Indexer, RPC,
  `msg_server` events all rely on it.
- **Block hash**: `x/vm/keeper/state_transition.go` `GetHashFn` falls back to
  reconstructing a CometBFT header and hashing it → the EVM `BLOCKHASH` opcode
  and `eth_getBlockByHash` are CometBFT-header-hash-bound.
  - *New chain*: adopt the MonadBFT header hash (blake3/RLP) — cleaner.
  - *Migrating a live chain*: either keep emitting CometBFT-shaped headers for
    hashing continuity, or accept a hash-scheme change at the upgrade height
    (EIP-2935 `BLOCKHASH` history still works if you keep serving old hashes
    for old heights — a dual-scheme reader keyed on upgrade height).
  - Recommend a chain-config flag: `header_hash_scheme = comet|monad`.

### D3 — IBC strategy → **DECIDED: defer (not v1)**

`evmd` registers `ibctm.NewLightClientModule` — counterparty chains verify
Tendermint headers over ed25519 `CommitSig`s. MonadBFT produces BLS-aggregate
QCs over different sign-bytes.

Decision: **IBC-out (remote chains verifying us) is deferred.** Document the
break explicitly:

- `ibctm` client module stays registered: **our chain can still verify
  CometBFT counterparties** (we are a valid IBC *client* of comet chains).
- What breaks is the inverse: remote chains cannot create a Tendermint client
  tracking our headers — no Tendermint commits exist. Any relayer flow needing
  a counterparty client on our chain is dead until a MonadBFT light client
  (icsXX) exists or a Tendermint-compat façade is added.
- Future options (parked): (A) façade — carry optional comet-key signatures in
  finalized-block commitments to synthesize `ibctm.Header`+`Commit`;
  (B) proper ibc-go light client verifying BLS QCs — audit + counterparty
  deployment lead time.

### D4 — Execution model → **DECIDED: deferred execution is core scope**

PLAN.md had v1 sync / v2 deferred. Per project decision, **speculative
deferred execution is in v1 scope** — it is the throughput feature. See
WS-4b for the design; the consensus types already carry the plumbing
(`DelayedExecutionResults`, `ExecutionInputs` in `cstypes/block.go`);
`EvmFinalizedHeader{SeqNum, AppHash}` is the right result commitment.
The `execution_delay=0` sync mode remains as a config fallback and the
default while deferred mode is being proven.

### D5 — Mempool architecture

The app-side `ExtMempool` (geth txpool + cosmos rechecker + reaplist) stays the
admission/selection engine — `PrepareProposal` reaps from it, as the bridge
already does. MonadBFT does *not* get its own txpool (unlike upstream Monad,
which has `monad-eth-txpool`); tx propagation is a transport concern (WS-2).
Avoid running two mempools — the `reaplist` bounds invariants assume one.

### D6 — Validator-set semantics

Epoch-locked valsets (already decided): `ValidatorUpdates` apply to app state
immediately but to *consensus* at the next epoch boundary. Two consequences to
handle deliberately:
- **Jailing lag**: a slashed validator keeps consensus voting power until the
  next epoch. Mitigate with short-ish `epoch_length` (it's a chain param —
  e.g. 100 blocks in the migration doc vs 50000 in tests) and document that
  downtime-slashing and evidence still apply retroactively.
- **`ReadValsetAtBlock` bug** (`bridge/stateread.go`, `swarm/inmemory.go`):
  returns the *current* valset, not the historical one → wrong QC signer
  interpretation across epoch churn. Must be fixed before real validator
  updates exist.

### D7 — Hash/serialization parity

Keep blake3+RLP byte-parity with Rust (already done; `conformance_test.go` +
`testdata/vectors.txt`). Wire-compat with Monad mainnet is explicitly not a
goal; parity is for fixture reuse and cross-impl testing.

---

## 2. Workstreams

### WS-1 — Daemonization (monadbft-go)

Turn `MonadState` into a runnable node. `cmd/` does not exist today.

Deliverables:
1. **Event loop**: wall-clock `TimerCommand` execution (`time.Timer`), command
   dispatch to real executors in the documented order (timer → timestamp →
   ledger → txpool → configfile → valset → loopback → statesync → router;
   see `swarm/executor.go:271-375` for the reference splitter), signal
   handling, graceful shutdown.
2. **Config**: node keys (secp256k1 node key + BLS cert key — the "privval"
   equivalent), `forkpoint.rlp`/`validators.rlp` paths, peer list, chain
   config (`chaincfg.StaticConfig`), telemetry config.
3. **Boot sequence**: load forkpoint → reconstruct `MonadState` → **replay
   WAL** (`wal.Reader` + `glue.IsWalLogged` already define the replay set) →
   reconcile committed-vs-executed height with app `Info` → enter Live or
   Sync mode. This is the top correctness item: `store/`+`wal/` are finished
   components but *unwired*; `swarm/restart_test.go` reconstructs state
   in-process without WAL replay.
4. **Double-sign protection**: `Safety` (highest_vote/propose/no_endorse) is
   covered by WAL/forkpoint persistence — verify the restart matrix (§4).
5. **PrivValidator key lifecycle**: file-based to start; remote signer (KMS)
   as a follow-up.
6. **Observability**: Prometheus exporter over `metrics.Metrics` (currently
   bare `uint64`s, not goroutine-safe — needs an atomic wrapper or channel),
   structured logging (`cosmossdk.io/log`), pprof, health endpoint.
7. **Panic hygiene**: convert recoverable-condition panics to errors —
   `consensusstate/state.go:710` (statesync trigger), `bridge/ledger.go`
   (ABCI errors, missing ancestors), `bridge/txpool.go`. Keep genuine
   invariant panics.

### WS-2 — Transport

Two-stage plan; the `RouterCommand`/`RouterTarget` seam keeps consensus
agnostic.

**Stage 1 — A5 TCP (do this first):** thin, real, boring.
- TCP listener/dialer; length-prefixed RLP framing (wire format is already
  byte-exact); secp256k1 `NodeId` handshake (sign a nonce; map to known peer);
  inbound dispatch through existing `validation/`; reconnect/backoff;
  backpressure; static peer set from config.
- Serve `BlockSync` req/resp and point-to-point paths — block sync is the
  first real networking consumer.
- Acceptance: multi-process 4-validator devnet on localhost, then LAN.
- Est. ~2–3k LOC. This unblocks *all* multi-process Track-A work — do not
  skip it to wait for RaptorCast.

**Stage 2 — Track B RaptorCast (v1 scope per project decision):** ~25–35k LOC.
- B1 `net/raptor` — RFC-6330 RaptorQ (GF(256), LDPC+LT, inactivation decode).
  Mechanical math port, symbol-level verifiable vs Rust. **Highest-risk single
  component**: start here, validate encoder/decoder output symbol-for-symbol
  against Rust `monad-raptor` unit vectors before building on it.
- B2 `net/dataplane` (UDP batching, priority queues, ban list; Go: `x/net`
  packet batching or per-packet) + `net/wireauth` (Noise handshake, sessions,
  replay filter, DoS cookies — wire-identical for compat tests).
- B3 `net/peerdisc` — signed name records, ping/pong, bootstrap.
- B4 `net/raptorcast` primary — stake-weighted chunk assignment, per-epoch
  validator-group routing, rebroadcast windows, message expiry, sig-verification
  rate limiting.
- B5 secondary — full-node publisher/client path (needed if RPC/archive full
  nodes are in scope; can slip to v1.1 if not).
- B6 — drop in as the `RouterCommand` executor; **TCP remains as the
  point-to-point fallback** (blocksync responses, statesync, large payloads)
  matching upstream's hybrid design — so A5 is not throwaway work.

**Transport options (decided: b):**
- ~~(a) TCP only~~ — rejected: loses Monad's fanout scaling, and scalability
  is a stated goal.
- (b) **TCP now + RaptorCast for v1** — TCP is the dev substrate + permanent
  fallback path; RaptorCast lands before v1 ships.
- (c) libp2p gossipsub intermediate — rejected: third protocol to maintain,
  worse tail latency than RaptorCast; only resurrect if Track B slips badly.
- (d) QUIC — rejected: RaptorCast semantics assume datagrams; re-platforming
  diverges from Rust behavior.

**Tx propagation** (CometBFT mempool gossip disappears): upstream Monad
forwards txs to *upcoming leaders* — `consensusstate` already computes future
leaders; `TxPoolCommand`/`MempoolEvent::ForwardedTxs` plumbing exists.
Implement leader-forwarding over whatever transport is live; keep
`CheckTx`+`InsertTx` admission. Options: (a) leader-forward (recommended),
(b) naive flood to all peers, (c) RPC-submission-only (proposer-local
mempool — unacceptable for liveness under distributed submission).

### WS-3 — Engine↔app seam (cosmos-evm refactor)

The app keeps speaking `servertypes.ABCI`/`abci.*` protobuf — those types are
SDK-fixed. What changes is the **caller** and the **query/read paths**.

**Phase 1 refactor (zero behavior change, on CometBFT):**
introduce engine-neutral interfaces in `server/` (or a new `engine/` pkg),
backed by current CometBFT code; repoint `rpc/backend`, `rpc/stream`,
`server/indexer_*`, `client/block` to the interfaces only.

```go
type ConsensusClient interface {          // replaces cmtrpcclient.SignClient
    Status(ctx) (*NodeStatus, error)                 // SyncInfo, ValidatorInfo
    Block(ctx, h *int64) (*CommittedBlock, error)
    BlockByHash / Header / HeaderByHash
    BlockResults(ctx, h *int64) (*BlockResults, error) // TxsResults + FinalizeBlockEvents
    ConsensusParams(ctx, h int64) (*ConsensusParams, error)
    NetInfo / UnconfirmedTxs / BroadcastTxSync|Async
    Subscribe(ctx, subscriber, query) (Subscription, error) // EventsClient
}

type EventSource interface {              // replaces cmttypes.EventBus
    Publish(header, results, txs); Subscribe(query)
}

type BlockStore interface {               // replaces comet blockstore+state reads
    LoadBlock(h) / LoadBlockResults(h) / LoadCommitCert(h)
    Base() / Height() / Prune(...)
}
```

Neutral models: `CommittedBlock{Header{Height,ChainID,Time,ParentHash,
AppHash,TxRoot,Proposer,ValidatorsHash,NextValidatorsHash},Txs,CommitCert}`,
`BlockResults{TxsResults []abci.ExecTxResult, FinalizeEvents,
ValidatorUpdates}` — keep `abci.ExecTxResult` (it's SDK-defined anyway).

**Semantics the new engine must preserve** (collected from `rpc/backend`):
- Two-read pattern: every eth block response needs block + results.
- `fee_market` begin-block event must survive in results (base-fee fallback).
- "committed height" (app) vs "consensus tip" divergence during catch-up —
  `eth_blockNumber` reads app height.
- `pending` = mempool contents (`UnconfirmedTxs` equivalent).
- Coinbase = proposer cons-addr → `ValidatorAccount` query; headers must carry
  proposer identity.
- `code==11 && "no block gas left"` → zero-gas receipt rule — preserve
  tx-result code/log verbatim.
- `EthHeaderFromComet` is already ersatz (empty receiptRoot/bloom, zero
  gasLimit/gasUsed) — fix deliberately in the neutral `MakeHeader` with golden
  tests, or carry forward explicitly.

**Event bus:** needs CometBFT-compatible `pubsub` query semantics
(`tm.event='NewBlock'` + attribute filters) for `rpc/stream` + indexer +
mempool `NotifyNewBlock`. Implement a minimal in-process pub/sub matching
`EventsClient` semantics (buffered chan, `Out()` never closes, `Canceled()`
semantics, header→results ordering guarantee). Options: (a) implement the
query subset actually used by `rpc/stream/rpc.go` (recommended — enumerate the
exact queries first), (b) port comet's query engine wholesale.

**Indexer:** `EVMTxIndexer.IndexBlock(*cmttypes.Block, …)` → neutral
`IndexBlock(*CommittedBlock, []abci.ExecTxResult)`. `server/indexer_cmd.go`
and `client/block/store.go` read CometBFT DBs directly → provide a reindex
path over the MonadBFT blockstore plus (for migrated chains) a compatibility
reader over old comet DBs.

**Mempool notification:** keep calling `NotifyNewBlock` per commit (the
`SetPrepareCheckStater` fallback already proves this works without an event
bus); in the daemon wire it to the commit event explicitly.

**Config/CLI:** keep `app.toml`; add `monadbft.toml` (or a config.toml
section) for engine params, transport, keys. Alias existing flags
(`--with-cometbft`, ports) during transition. Re-anchor `ValidateCrossConfig`
(`server/config/config.go`) to MonadBFT mempool semantics.

### WS-4 — `x/consensuskeys` module (cosmos-evm side)

New SDK module: `valoper → {secp256k1 pubkey, BLS pubkey}` with
proof-of-possession (each key signs the valoper address; BLS PoP per
standard). Genesis import/export; `MsgSetConsensusKeys` tx; gRPC query.
- `bridge.ValSet` joins `ValidatorUpdates` (power from staking) with the
  registry at epoch-boundary commits → `ValidatorSetData`.
- Replaces genesis-injected binding (`bridge/app.go` errors with
  "x/consensuskeys registry not implemented" today).
- Alternative considered: off-chain signed registry file — rejected; epoch
  valset snapshotting needs a deterministic on-chain source (already decided
  in PLAN.md §4.2).

### WS-4b — Deferred / speculative execution (core scope)

The headline throughput feature: ordering pipelines ahead of execution —
a proposal at seq N embeds `delayed_execution_results` (execution results of
blocks at seq `N − delay`), so `FinalizeBlock` runs on QC'd-but-unfinalized
blocks and consensus never waits on the EVM.

**Protocol shape (already in the ported core):**
- `ConsensusBlockHeader.DelayedExecutionResults` + `ExecutionInputs`
  (`cstypes/block.go`) — wire-complete.
- `blocktree.BlockPolicy.check_coherency` verifies embedded results against
  `ExecutionStateRead` — today only `MockBlockPolicy`/`PassthruBlockPolicy`
  exist; needs a real policy.
- `bridge.EvmFinalizedHeader{SeqNum, AppHash}` is the result commitment —
  correct shape already.

**What must be built:**

1. **Speculative execution store** — the hard part. When block N becomes
   coherent (QC'd), run `FinalizeBlock` on a *branch* of app state; keep
   `{block_id → (branch, AppHash, results)}`. Seq N+1's speculative execution
   branches off N's spec-state, not the committed tip. On 2-chain commit of
   N: make N's branch canonical (`Commit` semantics). On orphan: drop the
   branch — never Commit.
   - *Feasibility spike (P2) — DONE, mechanism proven.* SDK v0.54 already
     executes every `FinalizeBlock` on a `cms.CacheMultiStore()` branch
     (`baseapp/state/manager.go` `SetState`) and ships
     `baseapp/oe.OptimisticExecution` (goroutine `FinalizeBlock` +
     abort/wait + `AbortIfNeeded`/`WaitResult`/`Reset`), so the per-block
     branch primitive exists. `bridge/specexec_test.go` proves the missing
     generalization on the same rootmulti+IAVL stack evmd mounts:
       - *nested* `CacheMultiStore` branches are hash-transparent (spec chain
         ≡ flat branch at same committed version);
       - IAVL node hashes embed the store version ⇒ each block's writes must
         stage at its own committed depth — batching two heights into one
         `Commit` yields a different root;
       - the working commit protocol is: on finalize(h) `Write()` **every**
         held spec branch tip→root (already-committed ancestors re-flush —
         same-value re-sets are hash-neutral), then one `cms.Commit()` per
         height — reproduces the linear per-height app hash exactly;
       - abandoning a spec branch is free (no `Write` ⇒ no leak).
     Remaining work is the BaseApp seam: `internalFinalizeBlock` is private
     and BaseApp holds a single `execModeFinalize` slot — Phase 5 needs a
     hook that hands us the branch per block (or an SDK-side patch; see
     Phase 5 notes). Height bookkeeping stays sequential (finalization order
     = seq order = app height), guaranteed by the 2-chain commit.
2. **Result index** — `StateRead` must serve results at `seq − delay` for
   coherency checks: committed results from the ledger, in-flight results
   from the spec store. `bridge/stateread.go` currently only serves
   committed app hashes — extend it.
3. **Block policy** — replace `MockBlockPolicy` with `EvmBlockPolicy`:
   verify embedded delayed results against `StateRead`, seqnum/timestamp/
   author structural checks (some already in `MockBlockPolicy` — generalize).
4. **Ledger commit path** — `bridge.Ledger` currently calls
   `FinalizeBlock`+`Commit` synchronously at finalization. With delay>0:
   finalization of N commits the *pre-computed* spec branch (Commit only —
   results already exist); `CommitProposed`/`CommitVoted` triggers spec-exec.
   *Observed constraint (evmd-over-node runtime):* SDK apps are not
   thread-safe, and the node loop executes executors serially — a ~50ms
   `FinalizeBlock` starves inbound serving and livelocks blocksync when
   `7*delta` is too tight. The rework must move app work onto an
   executor-owned goroutine shared by Ledger+TxPool (single app writer),
   emitting results back through the pull queues.
5. **Mempool implications** — `PrepareProposal` still validates against the
   committed tip (unchanged rule), but the effective validation lag grows by
   `delay` blocks. `ReapNewValidTxs` disjointness already prevents
   double-selection across in-flight proposals. Residual risk: txs whose
   validity changed in the spec window (nonce consumed by a QC'd but
   unfinalized block) — produce `TxExceedBlockGasLimit`-style failures at
   finalization; acceptable upstream-parity behavior, document it.
6. **RPC exposure (optional UX win)** — speculative results can feed a
   "pending"/`safe`-vs-`finalized` distinction in eth JSON-RPC (Monad exposes
   speculative state). v1: keep `eth_blockNumber` at committed tip; expose
   spec height via a `monad_`-namespaced or `eth_syncing`-style endpoint.
7. **`execution_delay` as chain param** in `chaincfg` + genesis; `delay ≥ 1`
   requires the embedded results' base seq to already be finalized
   (upstream enforces `delay ≥ 2`-class constraints — mirror Rust's
   `ChainConfig` validation).

### WS-5 — Statesync & catch-up

**Status: landed (v1, replay-sync).** `bridge/statesync.go` implements the
upstream `StateSyncCommand`/`StateSyncEvent` state machine; the payload is
canonical committed *blocks* (RLP) served under a dedicated prefix instead
of upstream's flat-DB upserts — the Cosmos-EVM store is module-scoped IAVL,
so replay is the deterministic equivalent. `DoneSync` is gated on the
replayed app hash matching the requested finalized header; the in-process
mode switch is `StartExecution` + `SpecApp.ResetToHeight` (no crash-restart).
`TestBridgeStatesyncRejoin` drives a wiped-validator mid-run rejoin e2e.
The SDK snapshot-chunk surface (`ListSnapshots`/`OfferSnapshot`/
`ApplySnapshotChunk`) remains a possible fast-path upgrade for large state.

**Engine-scope statesync recovery (upstream-faithful panic→restart arc) —
landed.** `maybe_statesync`'s panic is upstream's "restart client and
statesync" instruction, so the Go port now implements the whole arc rather
than an in-process transition: `consensusstate.NeedStatesync` is a typed
panic carrying the target root+QC → `node` persists a checkpoint-shaped
`statesync-target.rlp` plus the certified block → the loop exits with
`ErrNeedStatesync` → `monadEngine.supervise` rebuilds persistence,
transport, and *per-boot* executors (fresh `StateSync` — its
`startedExecution` session flag is not reusable) → `node.Open` consumes the
target: the forkpoint re-roots at the target, epoch validator coverage is
synthesized from the genesis set for wiped nodes, and the buffer boots into
`MonadState` Sync mode → ancestry blocksync fills the root window →
`RequestSync` streams the app → `DoneSync` → live near tip. A stale target
(forkpoint already advanced past it) is cleared at boot instead of applied.
`node.Open` now converts Build/replay panics into errors so the supervisor
can retry rather than crash-loop the process.

**Preserved-safety wipe.** `safety.rlp` is a port addition over upstream
(durable vote/no-endorse/propose watermarks); an ops wipe keeps it so the
node cannot equivocate on restart. A node that restarts with watermarks
ahead of its forkpoint high certificate must NOT go live below the
watermark — `safety.timeout(round < highest_vote)` would panic — so
`maybeStartConsensus` now holds the Done→live transition until
`hc.Round()+1 >= restored highest_vote`, and the Sync-mode proposal path
re-anchors `highCertificate` on observed certified parents (same-root
re-root) so the hold self-resolves as certs arrive. `TestEngineStatesyncRejoin`
covers both arcs: `keep_safety` (wipe minus safety.rlp → held Sync-mode
recovery) and `wipe_safety` (full wipe → live-at-genesis → panic →
persisted target → supervised restart → Sync-mode rejoin), asserting
`trigger_state_sync` fired and the node regains peers + height.

**Shutdown/panic hardening along the way:** `store.BlockStore` ops are
guarded against use-after-close (`ErrClosed` instead of pebble panic — the
engine's canonical-commit worker can outlive the node loop that owns
`persist.Close`), and the bridge drops tail `fin/` writes that lose that
race (the index self-heals from `AllBlocks` on the next attach). On the
cosmos-evm side, the test-only global EVM config setters
(`setTestingEVMCoinInfo`, EIP-table extensions in `Configure`) now accept
identical re-application — required for multi-app devnets where each
in-process app's `InitGenesis` re-sets shared globals while peers run.

Original plan text (superseded by the replay executor above):
- Implement `StateSyncCommand`/`StateSyncEvent` executor over SDK snapshots
  (`ListSnapshots`/`OfferSnapshot`/`ApplySnapshotChunk`/`LoadSnapshotChunk`);
  `swarm/statesync.go` shows the protocol shape (request → snapshot →
  `DoneSync` → blocksync tail).
- Replace the `maybeStatesync` panic: the Go port already has `MonadStateSync`
  machinery — wire an **in-process mode switch** (preferred over replicating
  Rust's crash+restart; keep crash-restart as a documented fallback for
  operators).
- BlockSync over real transport for small lags (header→payload pipeline is
  ported; needs transport + `LedgerFetch*` over committed blocks).

### WS-6 — Evidence, slashing, governance semantics

- Emit equivocation evidence: `consensus/vote_state.go:80` and
  `consensusstate/state.go:336` TODO sites → new `MonadEvent`/command →
  adapter synthesizes `abci.Misbehavior` (DuplicateVote evidence) into
  `FinalizeBlock`. Needs an equivocation-proof type digestible by x/evidence
  (or a custom evidence type registered with the module).
- `decided_last_commit`: already correct (parent-QC bitmap → `VoteInfo` in
  canonical order). Verify fidelity once `ReadValsetAtBlock` is fixed
  (D6) — slashing liveness depends on it.
- Vote extensions: MonadBFT doesn't use them — ensure SDK passthrough stays a
  consistent no-op (any validator returning non-empty VE would break
  assumptions).
- NextValidatorsHash chain: maintain header `ValidatorsHash`/`NextValidatorsHash`
  continuity per the locked-epoch schedule (app valset hash vs consensus
  epoch-set hash — define which one lands in the header; recommend app hash,
  with epoch set discoverable via `x/consensuskeys`).

### WS-7 — RPC surface

Two layers:

1. **Ethereum JSON-RPC** — existing `rpc/` stack must work unchanged end-user-
  facing: `eth_blockNumber/getBlock*/getTransaction*/getLogs/call/estimateGas/
  sendRawTransaction/feeHistory/syncing`, `net_*`, `txpool_*`, `debug_trace*`,
  websockets `newHeads`/`logs`. Source everything via `ConsensusClient` +
  indexer. `newPendingTransactions` is ante-handler driven already — engine-
  agnostic.
2. **CometBFT-RPC compat shim** — needed so SDK `clientCtx`, gRPC gateway,
  `tx` CLI, wallets, explorers keep working: `/status /health /net_info
  /block /block_by_hash /block_results /validators /consensus_params
  /broadcast_tx_* /abci_query /tx_search /block_search` + WS `/subscribe`.
   - Option (a) full comet-shaped HTTP/WS API over MonadBFT store
     (recommended for ecosystem compat).
   - Option (b) only what eth-rpc needs — much smaller but breaks Cosmos
     tooling; acceptable only for EVM-only deployments.

### WS-8 — Ops & migration tooling

- `monadbft` genesis tooling: emit genesis with valset → consensus-keys
  binding, `forkpoint` for genesis, peer records.
- Testnet material: port `evmd/cmd/evmd/cmd/testnet.go` equivalents (comet
  `GenesisDoc` → new format), `local_node.sh`, docker-compose ports.
- Data migration for live chains (if D-decision says migrate):
  (a) converter from comet blockstore/state → monadbft store at halt height;
  (b) dual-reader compat layer (recommended — old heights served from old DB,
  new heights from new store; preserves historical eth RPC without
  re-execution);
  (c) state-export genesis restart (loses history, simplest).
- Snapshots, pruning, backup/restore stories.

---

## 3. Phasing

Per project decisions: RaptorCast and deferred execution are **v1 scope**;
IBC-out deferred; migration tooling optional (dual-reader default).

```
Phase 0  Decisions (D1–D7) + golden-test oracle
Phase 1  cosmos-evm: engine-neutral refactor behind CometBFT (zero Δ)
         — LANDED: engine.Engine seam + backend registry, CometBFT adapter
         default, MonadBFT backend via bridge init()-registration,
         `evmd start --engine=monadbft` (engine/ + evmd wiring).
Phase 2  monadbft-go: daemon + A5 TCP + WAL-replay recovery → multi-process devnet
         — restart recovery LANDED at engine scope: forkpoint/blockstore/
         safety reload, store↔index↔checkpoint reconciliation (spec-tail
         rollback + index backfill), canonical commits on a dedicated worker
         (app latency off the consensus loop), per-event WAL fsync dropped
         for timestamp records, 0xff-prefixed block-id iteration fix,
         checkpoint high-cert sanitization. TestEngineRestart (solo) +
         TestEngineMultiNodeRestart (4-node, TCP + RaptorCast variants,
         blocksync catch-up) cover it.
         + spec-exec feasibility SPIKE (WS-4b item 1 — DONE: nested-branch
         commit protocol proven vs linear, see bridge/specexec_test.go)
Phase 3  Track B: RaptorCast networking (raptor → dataplane+wireauth →
         peerdisc → raptorcast primary/secondary → executor integration).
         TCP stays as point-to-point fallback (blocksync/statesync) — matches
         upstream's hybrid design.
         — LANDED at engine scope: buildRaptorcast wires peers_file +
         validator binding + wall-clock name-record seq (fixes stale-seq
         handshake deadlock); peerdisc re-pings bootstrap peers on refresh
         (fixes permanent stranding when startup pings are lost);
         peerdisc_refresh_ms engine knob; multi-node raptorcast devnet +
         restart test green.
Phase 4  Feature completeness — LANDED on the monadbft-go side:
         tx leader-forwarding (upstream EthTxPoolForwardingManager
         semantics), blocksync over the RaptorCast datapath (4-process
         kill/restart devnet), replay-sync statesync executor over the
         upstream wire envelope, epoch-boundary validator transition test,
         CometBFT-RPC compat shim (status/block/block_results/validators/
         commit/broadcast_tx_sync/tx), Prometheus exporter + -metrics-addr.
         DEFERRED: evidence→x/evidence (upstream is TODO-2 as well — needs a
         formal equivocation-proof→abci.Misbehavior design), x/consensuskeys
         (cosmos-evm-side module, Phase-1 seam work), ProcessProposal (n/a —
         upstream validates in BlockPolicy.check_coherency).
Phase 5  Deferred/speculative execution (WS-4b) — LANDED: SpecApp executes
         on the canonical store (FinalizeBlock+Commit at proposal/vote time),
         ledger reuses results on finalization, EvmBlockPolicy verifies
         embedded delayed results, StateRead serves the in-flight spec index,
         async spec worker off the node loop, statesync replay + rejoin e2e,
         apphash parity vs canonical replay. delay ≥ 2 (seq-1 is never
         spec'd — see AGENTS/tests for the SDK finalize-slot constraint).
Phase 6  Hardening: crash matrix, byzantine/twins, fuzzing, dual-run replay,
         devnet soak; optional live-chain migration tooling (WS-8).
         — PARTIAL: restart matrix samples stop heights (1,2,5,8) covering
         spec-flight/checkpoint windows; engine-level statesync rejoin
         (TestEngineStatesyncRejoin) covers wiped-node rejoin through both
         the panic→target→supervised-restart arc and the
         preserved-safety-watermark held-sync arc over TCP; TestCometParity
         is the semantic dual-run oracle (same tx → identical EVM state;
         app-hash equality is invalid cross-engine since EIP-2935 stores the
         consensus block hash — documented in bridge/parity_test.go).
         REMAINING: multi-node kill matrix at proposal/vote/commit windows,
         byzantine/twins, fuzzing, long soak.
```

Rationale for the order:
- Phase 1 first because it shrinks the blast radius while still on a working
  engine — every refactor is regression-testable against CometBFT itself.
- A5 before RaptorCast even though RaptorCast is v1 scope: daemon, devnet,
  statesync and soak all need *a* real transport early, TCP is ~10x less code,
  and upstream keeps TCP as the fallback dataplane anyway.
- The spec-exec *spike* rides in Phase 2 (cheap, de-risks the biggest unknown);
  the full build lands in Phase 5 once transport+feature completeness exist.
- Phases 3 and 4 are independent and can run in parallel if resourced.
- Deferred exec lands after feature completeness because it reworks the
  ledger/policy/stateread seam — better on a stabilized, well-tested bridge.

### Per-phase acceptance

- **P0**: per-height golden JSON corpus (block/header/receipts/logs/traces,
  event stream) captured from a CometBFT evmd chain — the regression oracle.
- **P1**: `rg cometbft` in root module confined to adapter/compat packages;
  `make test-unit` + `cd evmd && go test -tags=test ./tests/integration/...`
  green.
- **P2**: 4-validator multi-process devnet finalizes ≥1000 blocks on TCP;
  `kill -9` mid-round → clean restart, no double-sign, ledger consistency;
  eth-rpc smoke (`eth_sendRawTransaction` → `eth_getTransactionReceipt`) works.
  **Spec-exec spike answered**: a PoC demonstrates a branched `FinalizeBlock`
  committed later out-of-band with identical app hash vs sync execution.
- **P3**: raptor encoder/decoder symbol-exact vs Rust vectors; 4-validator
  devnet on UDP+wireauth+raptorcast with no TCP consensus traffic on the
  validator path; fault-injection (loss/reorder) soak.
- **P4**: lagging node catches up via SDK-snapshot statesync; validator churn
  flows through `x/consensuskeys` → epoch boundary; equivocation evidence
  lands in `x/evidence`; comet-RPC-compat passes wallet/explorer smoke suite.
- **P5**: `execution_delay>0` chain finalizes with proofs: app hashes match a
  sync-mode run of the same tx workload; proposal's embedded delayed results
  verify via the real policy; orphan-branch discard leaves no state residue.
- **P6**: crash matrix green; twin-test equivocation scenarios; dual-run
  replay = empty JSON diff vs the P0 oracle; perf benchmark published
  (block time, finality lag, mempool throughput vs CometBFT baseline).

---

## 4. Test plan (cumulative)

| Layer | Tests |
|---|---|
| Port fidelity | existing conformance vectors; keep porting remaining Rust unit tests (vote_state/pacemaker/safety suites are the spec) |
| Swarm sim | extend fault-injection matrix (partitions, dup, reorder, equivocation); port monad-twins byzantine harness |
| Crash | kill -9 at proposal/vote/commit/ledger points; WAL replay → identical resumption; restart during epoch boundary & statesync |
| Integration | multi-process devnet; mempool→proposal→inclusion→receipt round-trip; epoch rotation; validator join/leave |
| Compat | golden-JSON diff per height (P0 oracle); comet-RPC endpoint matrix; websocket subscriptions; indexer parity |
| Migration (if in scope) | run comet chain → halt → swap engine → continue; historical queries across the boundary |
| Perf | block-time sweep (250ms–1s), finality lag, mempool throughput, raptorcast vs tcp fanout latency at N=50/100 validators |

---

## 5. Risks (ranked)

1. **Speculative execution on SDK state** — now v1 scope and the hardest
   remaining engineering: branching `FinalizeBlock` across pipelined blocks.
   Mitigation: Phase-2 feasibility spike before the Phase-5 build; worst case
   falls back to `execution_delay=0` (sync mode still yields consensus-layer
   gains: single BLS vote round, pipelined proposals, ~2-block finality lag
   vs comet's serial propose/commit).
2. **RaptorQ codec correctness** — RaptorCast's foundation; subtle math bugs
   become corrupt blocks at scale, not crashes. Mitigation: symbol-exact
   fixture validation vs Rust `monad-raptor` before B2 starts.
3. **`maybeStatesync` orchestration** — a real catch-up trigger currently
   panics by design; until WS-5 lands, a lagging validator crashes.
4. **Epoch-locked valsets vs jailing** — slashed validators retain consensus
   weight until the epoch boundary; mitigations are shorter epochs and
   documentation. Protocol-inherent, not fixable without departing from
   MonadBFT.
5. **Tx-hash / block-hash identity drift** — must be frozen deliberately or
   RPC/indexer/EIP-2935 silently break.
6. **WAL replay correctness** — the one piece of crash-safety that's never
   been exercised end-to-end; Phase-2 acceptance gate.
7. **ProcessProposal gap** — without it, structurally-invalid-but-well-formed
   proposals get structurally validated only (matches Rust's check_coherency,
   no re-execution); ensure this is an accepted semantic, not an oversight.
8. **Event-bus emulation fidelity** — subscription backpressure/ordering
   bugs will surface as flaky `logs`/`newHeads` behavior, not crashes; needs
   dedicated slow-subscriber tests.
9. **CometBFT DB compat readers** — `indexer_cmd.go`, `client/block` read raw
   schemas; a converter is fiddly, a dual-reader is safer.
10. **IBC-out gap** — remote chains can't verify us until façade/new client;
    accepted for v1, but every month deferred lengthens the eventual
    counterparty-deployment lead time.
11. **Dependency drift** — bridge pins evm/evmd via `replace` to a local
    checkout; track cosmos/evm upstream and SDK v0.54 bumps on a cadence.

---

## 6. Repo/module organization (recommended)

```
monadbft-go/                     (unchanged pure core)
  cmd/monadnode/                 NEW: wall-clock node library + main
  net/tcp/                       NEW: A5 transport
  net/{raptor,dataplane,wireauth,peerdisc,raptorcast}/   Track B
  bridge/                        (already exists; promote to production)
    daemon.go                    wires MonadState ↔ app ↔ transport ↔ WAL

cosmos-evm (fork)
  engine/                        NEW: ConsensusClient/EventSource/BlockStore
    comet/                       CometBFT impl (Phase 1 default)
    monad/                       MonadBFT impl (imports bridge)
  x/consensuskeys/               NEW
  server/                        refactored to engine interfaces
  rpc/, indexer/, client/        repointed to engine interfaces
```

Module hygiene: `engine/monad` may need its own go.mod (bridge does) to keep
the pure-core boundary; keep `replace` discipline documented.

---

## 7. Decisions taken / remaining open questions

**Taken (2026-09-28):**
- Deployment target: **both** — new-chain path is primary; live-chain
  migration support built as optional tooling (dual-reader default, §WS-8).
- IBC: **not v1** — document the IBC-out break; `ibctm` client module stays
  so we can still verify CometBFT counterparties.
- Transport: **RaptorCast in v1** — TCP first as dev substrate + permanent
  fallback dataplane (upstream parity).
- Execution: **deferred/speculative execution is core** — `execution_delay>0`
  ships in v1; sync mode stays as config fallback.

## Production-review pass 1 (landed)

See `PROD-REVIEW.md` for the full findings + status. Landed this pass:

- bounded in-memory retention (`retain_blocks`) + durable pruning
  (`prune_keep_blocks`) with Pebble store fallback; O(1) id/hash/tx indexes
- production `EvmBlockValidator` (randao round-sig + exec-header + tx sig
  checks) replacing `MockValidator` on all wiring paths
- authenticated TCP handshake (signed transcript → claimed NodeId verified;
  impostor connections rejected)
- `EngineConfig.Validate()` + `metrics_addr` Prometheus endpoint +
  `monadbft.json` first-boot scaffolding + `transport=none` warning
- chain params moved to `chaincfg.DefaultParams` with `monadbft.json`
  overrides (tx/gas/byte limits, vote pace, ts latency, fleet sizing)
- RPC: `block_search`, `tx_search` height ranges, `net_info` real peers,
  `block_by_hash` via persisted comet-hash index
- tests: EVM-tx integrity e2e (8 senders × 3 txs, 4-node TCP devnet,
  balances/nonces/apphash verified), retention-window store fallback,
  config-validation table tests; benchmarks: `BenchmarkFinalizeBlockEvm`
  (~2.4K evm_tx/s serial on M1 Pro — see PROD-REVIEW for the >10K analysis),
  `BenchmarkConsensusCommit`.

**Still open:**
1. Where does the code land: **fork of cosmos/evm consumed downstream**, or
   intended as upstream contribution? (changes how aggressively to hide
   CometBFT vs. keep it as a selectable engine; also affects the §6 layout —
   upstream contribution argues for `engine/` selectable backends)
2. Validator-set size target? (tunes raptorcast group size/redundancy, epoch
   length, and whether TCP-only would ever suffice)
3. Block-time target? (tunes `chaincfg`: `delta`, `vote_pace`, block gas/byte
   limits; also whether `execution_delay=1` vs `2` is the right default)
4. Are full nodes / archive nodes in scope for v1 (drives Track-B B5)?
