# monadbft-go

A Go port of [MonadBFT](https://github.com/category-labs/monad-bft) — Monad's
pipelined two-phase BFT consensus — for the Cosmos-EVM stack.

The consensus core is a behavioral port of the Rust implementation: same
pacemaker, vote/no-endorsement accounting, safety rules, block tree, and
RLP wire encodings (byte-identical against Rust fixtures). Execution is
decoupled through a small executor seam, so the same engine runs the
deterministic swarm simulator *and* a real Cosmos SDK application.

## Status

| Milestone | State |
|---|---|
| A0 — types, crypto (secp256k1 + BLS12-381), RLP, wire formats | ✅ done — conformance-tested against Rust fixtures |
| A1 — consensus core (pacemaker, vote/NE state, safety, blocktree) | ✅ done |
| A2 — `monadstate` + deterministic swarm prototype | ✅ done — multi-node swarm, blocksync, epochs, latency |
| A3 — persistence (WAL, forkpoint, block store, crash-restart) | ✅ done — restart scenarios match Rust semantics |
| A4 — ABCI bridge + `evmd` integration | ✅ milestone — 4-node in-process testnet finalizes EVM blocks with identical app hashes, real `MsgEthereumTx` inclusion |
| A4e — `x/consensuskeys` registry module | ⬜ pending — see [docs/migration.md](docs/migration.md) |
| A5 — loopback/TCP interop transport | ⬜ pending |
| Track B — RaptorCast networking (raptor codec, dataplane, wireauth, peerdisc) | ⬜ pending |

See [PLAN.md](PLAN.md) for the full roadmap and the Rust↔Go crate map.

## Repository layout

Two Go modules — the consensus core is deliberately free of Cosmos/CometBFT
dependencies; all SDK glue lives in `bridge/`:

```
.                        module github.com/abhijitkrm/monadbft-go  (pure Go, no cosmos deps)
├── types/               Round, Epoch, SeqNum, NodeId, Hash, RouterTarget
├── crypto/              secp256k1 (protocol sigs), BLS12-381 (cert sigs), signing domains
├── cstypes/             headers, bodies, votes, QC/TC/NEC, checkpoints (RLP-tagged)
├── validator/           stake-weighted ValidatorSet, EpochManager, leader election
├── consensus/           messages, Pacemaker, VoteState, NoEndorsementState, Safety
├── consensusstate/      ConsensusState — the main state machine (events → commands)
├── blocktree/           pending block tree, coherency, 2-chain commit
├── blocksync/           block sync requester/responder
├── monadstate/          MonadState dispatch, Live/Sync modes, forkpoint
├── glue/                MonadEvent / Command contract (the executor seam)
├── swarm/               deterministic swarm simulator (virtual clock, in-memory transport)
├── store/, wal/         consensus block store, forkpoint, write-ahead event log
│
└── bridge/              module github.com/abhijitkrm/monadbft-go/bridge
    ├── protocol.go      exec.Protocol for the EVM lane (tx-list body, app-hash results)
    ├── app.go           App wrapper: validator bookkeeping, decided_last_commit
    ├── evmdapp.go       in-process evmd construction + genesis tooling
    ├── ledger.go        swarm.Ledger: FinalizeBlock+Commit per finalized block
    ├── txpool.go        swarm.TxPool: ReapTxs+PrepareProposal, CheckTx+InsertTx
    ├── valset.go        swarm.ValSetUpdater: ValidatorUpdates → epoch valsets
    ├── stateread.go     ExecutionStateRead over committed app-hash results
    └── node.go          NodeBuilder wiring into the swarm driver
```

The core is a **pure synchronous state machine** — `update(event) -> []Command`,
exactly like Rust. All I/O (ledger, mempool, validator registry, network)
lives behind the `swarm` executor interfaces, which is what makes the swarm
simulator and the ABCI bridge interchangeable.

## Building and testing

Go 1.25.9+, CGO enabled (the SDK/evmd deps require it).

```bash
# core: build, vet, full test suite
go build ./...
go vet ./...
go test ./...

# bridge: separate module; tests require -tags=test (cosmos-evm convention —
# the test-only EVMConfigurator/ResetTestConfig lives behind it)
cd bridge
go test -tags=test -v .
```

Bridge tests spin up real in-process `evmd` apps:

- `TestBridgeOneNode` — 1 validator, 12 finalized blocks
- `TestBridgeFourNodes` — 4 validators, byte-identical app hashes
- `TestBridgeTxInclusion` — a signed `MsgEthereumTx` flows CheckTx → mempool →
  PrepareProposal → FinalizeBlock → committed on all nodes

## Docs

- [docs/integration.md](docs/integration.md) — wiring MonadBFT into a Cosmos
  SDK app: executor seam, genesis tooling, mempool requirements, height
  semantics, pitfalls found during bring-up.
- [docs/migration.md](docs/migration.md) — moving a CometBFT-based Cosmos-EVM
  chain to MonadBFT: key binding, consensus params, epochs, operational
  differences.
- [PLAN.md](PLAN.md) — the port roadmap, Rust crate map, and design decisions.
