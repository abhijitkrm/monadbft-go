# Migrating a Cosmos-EVM chain from CometBFT to MonadBFT

This guide covers what changes for an existing CometBFT-based Cosmos-EVM
chain (or a new chain choosing MonadBFT): the data model, validator keys,
genesis, mempool, and operational differences. It documents the current
prototype mapping and flags the pieces still in flight.

## TL;DR

MonadBFT replaces CometBFT as the consensus engine. The Cosmos SDK
application is untouched — it still sees ordinary ABCI 2.0 calls
(`InitChain`, `FinalizeBlock`, `Commit`, `CheckTx`, `PrepareProposal`). The
bridge translates MonadBFT's pipelined consensus into those calls.

```
CometBFT:  propose(H) → prevote → precommit → commit(H) → propose(H+1) …
           (sequential — consensus, execution, and commit are one pipeline)

MonadBFT:  propose(seq N) while N-1, N-2 still in flight (pipelined)
           2-chain commit: seq N finalizes when QCs on N and N+1 form
           execution happens at finalization, ~2 seqs behind the tip
```

## Mapping: CometBFT → MonadBFT

| CometBFT concept | MonadBFT equivalent |
|---|---|
| height | `SeqNum` (1:1 — seq n ↔ app height n; seq 0 = genesis) |
| prevote + precommit quorum | one aggregated vote round → Quorum Certificate (BLS aggregate) |
| `decided_last_commit` (CommitInfo votes) | parent-QC signer bitmap → `VoteInfo` in canonical valset order |
| proposer (comet valset order) | MonadBFT leader election — weighted round-robin over stake |
| mempool gossip (ReapTxs broadcast) | `InsertTx`/`CheckTx` into the local `ExtMempool`; proposer reaps at proposal time |
| validator set per height | **locked per epoch** (`epoch_length` blocks); updates apply at epoch-boundary commits |
| instant finality at commit | finality at 2-chain commit — the committed tip trails the proposed tip by ~2 blocks |

## Validator keys — three keys per validator

| Key | Role | Where it lives |
|---|---|---|
| ed25519 cons key | SDK validator identity (staking, slashing, `ValidatorUpdate`) | app state / keystore |
| secp256k1 | MonadBFT `NodeId` — message signatures, peer identity | node config |
| BLS12-381 | vote/timeout aggregation — QC/TC signatures | node config |

CometBFT validators only have the ed25519 key. Migration therefore needs a
binding: `consAddr → (secp256k1 pubkey, BLS pubkey)`.

### x/consensuskeys registry *(planned — not yet implemented)*

A small SDK module holding `valoper → {secp256k1 pubkey, BLS pubkey}` with
self-signed proof-of-possession:

- genesis: initial binding emitted by genesis tooling
- tx: `MsgSetConsensusKeys` (validator updates its MonadBFT keys)
- the bridge joins `ValidatorUpdates` (power, from staking) with the registry
  to build MonadBFT `ValidatorSetData`

Until it exists, the binding is injected at genesis by
`bridge.MakeValidators`/`bridge.App` — sufficient for fixed testnets, not for
real validator churn.

## Consensus params and genesis

`RequestInitChain.ConsensusParams` must carry a nonzero `Block.MaxGas`
(`-1` = unlimited, or a real limit). Zero makes `CheckTx` reject every
transaction ("exceeds block gas limit").

evmd-specific genesis fixups (see `bridge/evmdapp.go`, all done by
`NewEvmdApp`):

- `x/slashing` **signing infos** for every genesis validator — genesis
  validators are created already `Bonded`, so the `AfterValidatorBonded`
  hook never fires; without seeded infos the first non-empty
  `decided_last_commit` errors with "no validator signing info found".
- bonded pool balance `= N_validators × bondAmt` (the SDK test helper only
  funds one).
- `x/feemarket` `NoBaseFee` for deterministic test chains (optional).
- funded test accounts use `ethsecp256k1` keys so SDK address == EVM address.

## Mempool configuration

The evm mempool is not optional plumbing — `PrepareProposal` reaps from it.
Required appOpts (see `evmd/tests/integration` `NewAppOptionsWithFlagHomeAndChainID`):

```toml
[evm.mempool]
insert-queue-size = 5000            # 0 → every InsertTx fails "queue full"
pending-tx-proposal-timeout = "250ms"
```

Head tracking: the mempool's `heightsync` only advances on
`NotifyNewBlock`. CometBFT drives this via the block-executor event bus; under
MonadBFT nothing publishes `NewBlockHeader` events, so the app must call it
per commit — evmd does this internally via `SetPrepareCheckStater` when no
event bus is set. Custom apps: call `mempool.NotifyNewBlock()` after `Commit`
or wire an event bus.

## Txs: submission and propagation

- **Submit**: `CheckTx` + `InsertTx` (or JSON-RPC — it lands in the same
  `ExtMempool`). No CometBFT mempool gossip exists; forwarding paths in the
  bridge are a placeholder until the networking track lands.
- **Selection**: the proposer's `PrepareProposal` selects txs valid at the
  **committed tip**, not the proposal's seqnum (pipelining — see
  [integration.md](integration.md#-the-pipelining-rule--prepareproposal-height)).
- **Inclusion ordering/fairness**: `ReapNewValidTxs` returns unreaped txs;
  a tx reaped into an orphaned proposal is not automatically re-proposed
  (prototype limitation).

## Epochs and validator-set changes

CometBFT applies `ValidatorUpdates` at the next height. MonadBFT locks a
validator set per epoch:

- pick `epoch_length` (e.g. 100 blocks);
- at each epoch-boundary commit, the bridge snapshots the app's post-update
  canonical set and emits `EvUpdateValidators` for the newly-locked epoch;
- `ValidatorUpdates` returned by `FinalizeBlock` still apply to app state
  immediately — they only affect **consensus** at the next epoch boundary.

Consequence: a validator set change takes effect for consensus at the next
epoch boundary, not the next block. Slashing/jailing of a voting validator
removes app-side power immediately but cannot change the locked consensus
set mid-epoch.

## Operational differences

| CometBFT | MonadBFT bridge |
|---|---|
| `FinalizeBlock` at every height, sequentially | `FinalizeBlock`+`Commit` only for *finalized* blocks, in seq order, catching up ancestors as needed |
| every validator executes every proposal's txs at ProcessProposal | no `ProcessProposal` re-execution in the hot path (structural `check_coherency` only — matches Rust `EthBlockPolicy`); execution is single-pass at finalization |
| block result = execution result, same height | app hash binds into consensus `execution_delay` blocks later via `delayed_execution_results` (`execution_delay ≥ 2` required so the base seq is finalized) |
| crash recovery: comet WAL + blockstore | MonadBFT WAL + forkpoint + consensus block store (see `store/`, `wal/`); app state recovery unchanged |
| statesync: comet snapshots | bridge `NopStateSync` today; SDK snapshot restore (`OfferSnapshot`/`ApplySnapshotChunk`) is the plan |

## What still needs building (production checklist)

1. `x/consensuskeys` — on-chain cons↔MonadBFT key registry (see above).
2. Transport: the swarm currently uses deterministic in-memory routing;
   production needs the Track-B RaptorCast stack (or the A5 thin
   loopback/TCP interop transport for interop testing).
3. `ProcessProposal` wiring if you want app-side proposal *rejection* beyond
   structural checks (note: it cannot re-execute — pipelined proposals are
   ahead of the finalized tip; only non-execution validation is possible).
4. Speculative/deferred execution (`execution_delay > 0` real semantics):
   today the bridge executes synchronously at finalization with results bound
   retroactively; true Monad deferred execution needs speculative
   `FinalizeBlock` on branched state.
5. State sync via SDK snapshots; tx resurrection for orphaned proposals;
   RPC surface (consensus status, evidence).
