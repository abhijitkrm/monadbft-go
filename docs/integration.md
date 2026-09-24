# Integrating MonadBFT with a Cosmos SDK app

This guide explains how the `bridge/` module drives a Cosmos SDK application
(evmd) with MonadBFT consensus in-process — the same shape a production daemon
would use, minus the network transport.

## The executor seam

The consensus core is a pure synchronous state machine:

```
event → MonadState.update → []Command  (LedgerCommand / TxPoolCommand /
                                        ValSetCommand / RouterCommand / ...)
```

Commands are executed by pluggable executors. The swarm simulator uses mock
executors; the bridge swaps in ABCI-backed ones — nothing else changes.

| `swarm` interface | Bridge impl | What it does |
|---|---|---|
| `Ledger` | `bridge.Ledger` | `CommitFinalized` → `FinalizeBlock` + `Commit` (one app height per consensus seqnum); `CommitProposed`/`CommitVoted` → store the block for blocksync serving |
| `TxPool` | `bridge.TxPool` | `TxPoolCreateProposal` → `ReapTxs` + `PrepareProposal` → `EvMempoolProposal`; `SendTransaction`/`InsertForwardedTxs` → `CheckTx` + `InsertTx` |
| `ValSetUpdater` | `bridge.ValSet` | `ValSetNotifyFinalized` at epoch-boundary commits → snapshot app valset → `EvUpdateValidators` |
| — (blocktree) | `bridge.StateRead` | `ExecutionStateRead` over committed app-hash results (delayed-execution result lookup) |
| `StateSync` | `bridge.NopStateSync` | stub — SDK snapshot sync is a later milestone |

Consensus events that carry no app interaction (`BlockCommit`, `EnterRound`,
`Reset` on the txpool) are no-ops — the app's own hooks inside
`FinalizeBlock`/`Commit` handle mempool lifecycle.

## Height and seqnum

Consensus `SeqNum` maps 1:1 to app height (`seq n ↔ height n`; seq 0 is
genesis — `InitChain` covers it, no `FinalizeBlock`).

## Block bodies and execution results

`bridge/protocol.go` defines the exec lane:

- `EvmBody` — `Txs [][]byte`, SDK-encoded txs (RLP list of byte strings —
  same shape as Monad's `EthBlockBody.transactions`).
- `EvmFinalizedHeader` — `{SeqNum, AppHash}` — the delayed execution result
  later headers bind via `delayed_execution_results`.
- `EvmProposedHeader` — empty; the consensus header already carries
  seqnum/timestamp/author.

## decided_last_commit

`FinalizeBlock` gets `DecidedLastCommit` built from the **parent QC's signer
bitmap**, mapped into `abci.VoteInfo` entries in the app's canonical
validator-set order (`App.LastCommit`). This keeps `x/slashing` and
`x/distribution` BeginBlocker accounting working. The genesis QC carries no
signers, so height-1 gets an empty `CommitInfo` — same as CometBFT.

## ⚠ The pipelining rule — PrepareProposal height

`RequestPrepareProposal.Height` is **the app's next committed height**
(`committed tip + 1`), **not** the consensus seqnum.

The evm mempool selects txs validated at `req.Height - 1` — CometBFT's
sequential model where proposals always sit one above the committed tip.
MonadBFT pipelines ~2 seqs ahead of finalization, so a seqnum-heighted request
would make the mempool's `heightsync` wait on a height that can only be
reached *through* this proposal — a deadlock. Selecting at the committed tip
is also semantically right: execution is deferred to finalization anyway.

`ReapNewValidTxs` returns only unreaped txs, so in-flight proposals stay
disjoint. Caveat: a tx reaped into an orphaned (timed-out) proposal stays
marked reaped but uncommitted — resurrection is a follow-up.

## ⚠ App requirements

What the app side must satisfy (all handled by `NewEvmdApp`):

1. **Mempool height sync needs block-head notifications.** evmd installs
   `SetPrepareCheckStater` → `NotifyNewBlock()` when no CometBFT event bus
   exists, which fires inside `Commit` — this is what advances the mempool's
   internal `heightsync`. If you wire a different app, ensure something calls
   `mempool.NotifyNewBlock()` per commit (or set an event bus).
2. **Mempool appOpts**: `evm.mempool.insert-queue-size` (e.g. 5000 — 0 makes
   every `InsertTx` fail "queue full") and `evm.mempool.pending-tx-proposal-timeout`.
3. **Slashing signing infos must exist in genesis** for every genesis
   validator. `GenesisStateWithValSet` inserts validators already `Bonded`,
   so staking's `AfterValidatorBonded` hook never fires and no signing info
   is created — the first non-empty `DecidedLastCommit` then fails with
   "no validator signing info found". `NewEvmdApp` seeds them manually.
4. **Bonded pool funding**: `GenesisStateWithValSet` only funds one
   `bondAmt` regardless of validator count — top it up to `N × bondAmt`
   or bank InitGenesis fails on supply mismatch.
5. **Consensus params**: `Block.MaxGas` must be nonzero (`-1` = unlimited or
   a real limit). Before the first `Commit`, `execModeCheck` has no params —
   `CheckTx` rejects every tx with "exceeds block gas limit". Submit txs only
   after height 1 commits.
6. **EVM-funded accounts** need `ethsecp256k1` keys so the SDK account
   address equals the EVM address (keccak derivation). Plain SDK `secp256k1`
   keys produce a *different* address and can't spend via `MsgEthereumTx`.

## Putting it together

```go
vals := bridge.MakeValidators(4)                     // deterministic testnet keys
app, evmApp, err := bridge.NewEvmdApp(bridge.EvmdConfig{
    ChainID:    "mychain",
    EVMChainID: 9001,
    Home:       t.TempDir(),
}, vals)                                             // InitChain'd app + bridge.App

builders, err := bridge.NewNodes([]*bridge.App{app /*, ...*/}, vals, bridge.DefaultConfig())
nodes := builders.Build()                            // swarm.Nodes — deterministic driver
```

`NewEvmdApp` performs: `evmd.NewExampleApp` on a MemDB → genesis fixups
(denom metadata, `EvmDenom`, `NoBaseFee`, slashing signing infos, bonded-pool
top-up) → `server.NewCometABCIWrapper` (adapts the SDK's context-free ABCI
methods onto CometBFT's context-aware `abci.Application`) → `InitChain` with
the shared genesis.

For a *production* app you'd construct the real app (not `NewExampleApp` on a
MemDB) and feed it through `bridge.NewApp(server.NewCometABCIWrapper(app), vals)`
— the bridge only needs the `abci.Application` interface plus the validator
key mapping.

## Multi-app processes

evmd keeps a **global** EVM chain config — `x/vm/keeper.NewKeeper` calls
`SetChainConfig` which refuses a second set. Under `-tags=test`,
`evmtypes.NewEVMConfigurator().ResetTestConfig()` resets it between app
constructions (all nodes share one chain ID, so the global stays consistent).
In production each validator is its own process, so this only matters for
in-process testnets.

## Validator sets

`App.ValidatorSetData()` converts the app's canonical valset
(genesis + applied `ValidatorUpdates`) into MonadBFT `ValidatorSetData`
(sorted by NodeId — the QC signer-bit order). `bridge.ValSet` snapshots it at
each epoch-boundary commit into the newly-locked epoch and serves historical
epochs from its own table.

Today the cons-key ↔ MonadBFT-key binding is established by genesis tooling
(`MakeValidators`). The on-chain registry (`x/consensuskeys`) that makes this
a first-class chain primitive is tracked in
[migration.md](migration.md#xconsensuskeys-registry).
