# monadbft-go

A Go port of [MonadBFT](https://github.com/category-labs/monad-bft) — Monad's
pipelined two-phase BFT consensus — as a drop-in consensus engine for
[Cosmos-EVM](https://github.com/cosmos/evm) (evmd).

The consensus core is a behavioral port of the Rust implementation: same
pacemaker, vote/no-endorsement accounting, safety rules, block tree, RaptorCast
networking, and RLP wire encodings (byte-identical against Rust fixtures).
Execution is decoupled through a small executor seam, so the same engine runs
the deterministic swarm simulator *and* a real Cosmos SDK application —
selected at startup via `evmd start --engine=monadbft`.

## Repositories

| Repo | Contents |
|---|---|
| **[abhijitkrm/monadbft-go](https://github.com/abhijitkrm/monadbft-go)** (this) | Consensus core (pure Go, zero Cosmos/CometBFT deps) + `bridge/` module wiring it into a Cosmos SDK app |
| **[abhijitkrm/monad-evm](https://github.com/abhijitkrm/monad-evm)** | Maintained fork of `cosmos/evm` — adds the pluggable engine seam (`engine/`), `evmd --engine` flag, and the `evmd start` monadbft integration. `upstream` remote tracks `cosmos/evm` for sync |

The two repos work together: `bridge/go.mod` `replace`s `github.com/cosmos/evm`
at the sibling path `../../monad-evm`, so clone them side by side:

```bash
git clone https://github.com/abhijitkrm/monadbft-go.git
git clone https://github.com/abhijitkrm/monad-evm.git   # must sit next to monadbft-go/
# parent dir now contains:  monadbft-go/  monad-evm/
```

## Status

| Milestone | State |
|---|---|
| A0 — types, crypto (secp256k1 + BLS12-381), RLP, wire formats | ✅ done — conformance-tested against Rust fixtures |
| A1 — consensus core (pacemaker, vote/NE state, safety, blocktree) | ✅ done |
| A2 — `monadstate` + deterministic swarm prototype | ✅ done |
| A3 — persistence (WAL, forkpoint, block store, crash-restart) | ✅ done — restart semantics match Rust |
| A4 — ABCI bridge + `evmd` integration | ✅ done — 4-node devnet, real `MsgEthereumTx`, byte-identical app hashes |
| A4e — `x/consensuskeys` registry module | ⬜ pending — validator-set rotation still goes through genesis; see [docs/migration.md](docs/migration.md) |
| A5 — TCP transport (authenticated handshake) | ✅ done |
| Track B — RaptorCast (raptor codec, dataplane, wireauth, peer discovery) | ✅ done — multi-node restart + statesync tested |
| Production pass 1 ([docs/prod-review.md](docs/prod-review.md)) | ✅ retention+indexes, EvmBlockValidator, TCP auth, config validation, metrics, RPC gap-fill, e2e/bench |
| Deferred-execution parallel EVM (≥10K TPS) | ⬜ pending — see [stats](#measured-stats-apple-m1-pro-arm64-single-process) |

## Repository layout

Two Go modules — the consensus core is deliberately free of Cosmos/CometBFT
dependencies; all SDK glue lives in `bridge/`:

```
.                        module github.com/abhijitkrm/monadbft-go  (pure Go, no cosmos deps)
├── types/               Round, Epoch, SeqNum, NodeId, Hash, RouterTarget
├── crypto/              secp256k1 (protocol sigs), BLS12-381 (cert sigs), signing domains
├── cstypes/             headers, bodies, votes, QC/TC/NEC, checkpoints (RLP-tagged)
├── validation/          stateless inbound-message checks (QC verify, sigs)
├── validator/           stake-weighted ValidatorSet, EpochManager, leader election
├── consensus/           messages, Pacemaker, VoteState, NoEndorsementState, Safety
├── consensusstate/      ConsensusState — the main state machine (events → commands)
├── blocktree/           pending block tree, coherency, 2-chain commit
├── blocksync/           block sync requester/responder
├── statesync/           state sync orchestration (target tracking, sync→live)
├── monadstate/          MonadState dispatch, Live/Sync modes, forkpoint
├── raptorcast/          RaptorQ encoder/decoder, group routing, soft quotas
├── glue/                MonadEvent / Command contract (the executor seam)
├── swarm/               deterministic swarm simulator (virtual clock, mock executors)
├── node/                production node loop — transport selection, auth TCP, metrics
├── chaincfg/            chain parameters (gas/byte limits, base fee) — from monadbft.json
├── store/, wal/         PebbleDB block store, forkpoint, write-ahead event log
└── cmd/monadbft-node/   standalone dev daemon (no evmd needed)

    bridge/              module github.com/abhijitkrm/monadbft-go/bridge
    ├── protocol.go      exec.Protocol for the EVM lane (tx-list body, app-hash results)
    ├── app.go           App wrapper: validator bookkeeping, decided_last_commit, retention
    ├── evmdapp.go       in-process evmd construction + genesis tooling (FundedSenders)
    ├── engine.go        monadEngine: engine seam impl, config validation, metrics server
    ├── ledger.go        swarm.Ledger + Pebble-backed finalized-block persistence
    ├── validator.go     EvmBlockValidator — randao sig, exec fields, tx sanity screens
    ├── persist.go       ResultStore — results/valsets/tx-hash/cmt-hash indexes (prunable)
    ├── txpool.go, valset.go, stateread.go, specapp.go   executor impls (incl. speculative exec)
    ├── client.go        CometBFT-rpc-compatible client over the ledger
    ├── rpc.go           HTTP JSON-RPC shim (block/tx search, net_info, status, commit…)
    └── node.go          NodeBuilder wiring into the swarm driver
```

The core is a **pure synchronous state machine** — `update(event) -> []Command`,
exactly like Rust. All I/O lives behind the `swarm` executor interfaces, which
is what makes the swarm simulator and the ABCI bridge interchangeable.

## Building and testing

Go 1.25.9+, CGO enabled (SDK deps). Clone layout per [Repositories](#repositories).

```bash
# core: build, vet, full unit suite (incl. race where tagged)
cd monadbft-go
go build ./... && go vet ./... && go test ./...

# bridge: separate module; tests require -tags=test (cosmos-evm convention —
# test-only EVMConfigurator/ResetTestConfig lives behind it)
cd bridge
go test -tags=test -v .
```

## Running a node (evmd + MonadBFT)

`monad-evm`'s `evmd` binary accepts `--engine=monadbft` on `start`:

```bash
cd monad-evm/evmd && go build -o evmd .
./evmd init mynode --chain-id monad-1

# first `start` scaffolds config/monadbft.json + generates config/monad.key.json
# (secp256k1 + BLS consensus keys) if either is missing:
./evmd start --engine=monadbft   # scaffolded transport "none" = single-node dev chain
```

### `monadbft.json` — engine config

Lives in `<home>/config/`. Scaffolded with defaults on first boot if absent;
all fields validated at `start` — out-of-bounds values fail fast.

| Field | Default | Meaning |
|---|---|---|
| `transport` | `"none"` | `"tcp"` · `"raptorcast"` · `"none"` (single-node only) |
| `tcp_address` | `"0.0.0.0:9000"` | TCP listen addr (transport=tcp) |
| `udp_port` | `8000` | raptorcast dataplane port |
| `auth_port` | `9000` | peer-discovery auth port |
| `key_file` | `monad.key.json` | this node's consensus keys — auto-generated if missing |
| `validators_file` | — | genesis key bindings (see below) |
| `peers_file` | — | signed bootstrap records (see below) |
| `epoch_length` | `0` | seqnums per epoch (`0` = single epoch) |
| `execution_delay` | `4` | deferred-execution lag (must be ≥2) |
| `delta_ms` | `400` | round-trip estimate → timeout `δ*3 + vote_pace + δ` ≈ 1.9 s |
| `statesync_threshold` | `1000` | seqnums behind before state-sync triggers |
| `peerdisc_refresh_ms` | `5000` | peer-discovery refresh interval |
| `bind_ip` / `max_num_peers` / `max_group_size` | `0.0.0.0` / `200` / `10` | raptorcast bind + peerdisc cap + raptor group size |
| `advertise_ip` | `bind_ip` | self name-record address; **required** when bind_ip is unspecified (`0.0.0.0`) — peers dial what this record advertises |
| `metrics_addr` | `""` | Prometheus scrape addr, e.g. `"127.0.0.1:9090"` |
| `retain_blocks` | `4096` | in-memory window for committed blocks/results (0 = unbounded) |
| `prune_keep_blocks` | `0` | durable Pebble retention (0 = keep all history) |
| `beneficiary` | self cons addr | block-proposer fee recipient (20-byte hex) |
| `base_fee` | `100000000000` | initial base fee, wei (100 gwei) |
| `tx_limit` / `proposal_gas_limit` / `proposal_byte_limit` / `vote_pace_ms` / `timestamp_latency_ms` | chain defaults | proposal/chain-parameter overrides |

`validators_file` — genesis binding of consensus keys to Monad keys (one
entry per genesis validator):

```json
{"validators": [{
  "cons_pubkey": "<ed25519-hex-32B>",   // the SDK consensus pubkey
  "secp_pubkey": "<secp256k1-hex-33B>", // Monad protocol pubkey → NodeId
  "bls_pubkey":  "<bls12-381-hex-48B>"  // certificate pubkey
}]}
```

`peers_file` — JSON array of signed bootstrap records
(`node/bootstrap.go`, mirrors upstream `node.toml [[peers]]`):

```json
[{
  "address": "10.0.0.2:9000",            // host:port — fills tcp+udp unless split below
  "tcp_port": 9000, "udp_port": 8000,    // optional overrides
  "record_seq_num": 1,
  "secp256k1_pubkey": "<hex-33B>",
  "name_record_sig": "<hex-65B-recoverable>", // self-signed name record
  "auth_port": 9000,
  "direct_udp_port": 8000, "encrypted_tcp_port": 9001  // optional
}]
```

### Multi-node devnet — `bridge/cmd/devnet`

Scaffolds a complete fleet: SDK-side homes via `evmd testnet init-files`,
then per-node `monad.key.json`, shared `validators.json` (cons→secp/bls
bindings) + `peers.json` (signed name records), and per-node `monadbft.json`
with unique ports. JSON-RPC/WS/gRPC ports are offset per node so the fleet
can coexist with a locally running node.

```bash
cd bridge && go build -o devnet ./cmd/devnet
./devnet init-files -n 4 -o ./devnet-run -evmd /path/to/evmd \
    -transport tcp            # or raptorcast | none
./devnet start -o ./devnet-run -evmd /path/to/evmd
#   → 4 evmd processes, prefixed logs, Ctrl-C stops all
#   → metrics at 127.0.0.1:9100+i, JSON-RPC :8645+i, WS :8746+i,
#     CometBFT-compat RPC :36657+i (off 26657 to dodge real CometBFT)
```

### Soak — `devnet soak`

Sustained-load evidence run: `init-files --fund N` writes N funded
ethsecp256k1 accounts into genesis + `soak-keys.json`; `soak` then drives
signed transfers at a target rate, samples per-node height/RSS/disk/
apphash-parity, optionally SIGKILLs a node and times its rejoin, and ends
with a post-load settle/drain check. JSON report at
`<out>/soak-report.json`. See `docs/soak-findings.md` for current results
and the two release-blocking defects it caught.

```bash
./devnet init-files -n 4 -o ./devnet-run -evmd /path/to/evmd --fund 8
./devnet soak -o ./devnet-run -evmd /path/to/evmd     -duration 3m -rate 200 -kill 2 -kill-after 45s
```

The generated fleet is single-host (all records advertise `-ip`,
default `127.0.0.1`). For multi-host: set `-ip` to a routable address on
each host's generation run, or hand-edit `peers.json` records +
`advertise_ip` per node — the `validators.json` binding file is
host-agnostic and shared as-is.

## Observability

- `metrics_addr` serves a Prometheus text endpoint. The metrics tree is
  exported flat as `monadbft_<group>_<field>` —
  `monadbft_consensus_events_commit_block`,
  `monadbft_consensus_events_local_timeout`,
  `monadbft_blocksync_events_request_timeout`,
  `monadbft_node_state_*`, `monadbft_validation_errors_*` — counters and
  gauges only, live-scraped from atomics.
- The engine log line carries `node_id`, `round`, `seq` on every event.
- RPC: CometBFT-compatible `status`, `block`, `block_by_hash`, `block_search`,
  `tx`, `tx_search` (`tx.hash`, `tx.height`), `commit`, `validators`,
  `net_info` (real peer list), `broadcast_tx_*`.

## Measured stats (Apple M1 Pro, arm64, single process)

| Metric | Result |
|---|---|
| **Serial EVM throughput** — `BenchmarkFinalizeBlockEvm` (512-tx block, real secp256k1-signed transfers, full `FinalizeBlock`+`Commit`) | **~2,300–2,400 evm_tx/s** (~246 µs/tx) |
| Where the 246 µs goes | secp256k1 pubkey recovery + SDK tx decode + GC pressure dominate; `Commit` itself is ~1 ms/block |
| **Empty-block commit loop** — `BenchmarkConsensusCommit` | **~0.83 ms/block** (~1,200 blocks/s app-side ceiling) |
| Round timeout (`delta_ms=400`, `vote_pace=300ms`) | worst-case `δ*3 + vote_pace + δ` ≈ 1.9 s per round |
| Core unit suite (`go test ./...`) | green — incl. `node/` TCP-auth + 4-node restart (217 s), RLP conformance vs Rust fixtures |
| Bridge suite (`go test -tags=test -v .`) | green — 31 test funcs across e2e, restart matrix, statesync rejoin, crash-window liveness, parity, persistence |

**On the 10K-TPS target:** the serial pipeline tops out at ~2.4K evm_tx/s on
this hardware — the bound is execution, not consensus (deferred execution
already decouples block rate from app throughput until the backlog fills
`execution_delay`). Reaching 10K+ needs Monad's parallel-EVM execution
(BlockSTM-style, `monad-execution`) — not yet ported; tracked in
[docs/prod-review.md](docs/prod-review.md).

## E2E / correctness coverage

- `TestEvmIntegrityTransfers` — 8 funded senders × 3 signed transfers on a
  live 4-node TCP devnet; asserts inclusion, results, gas, recipient balances,
  sender nonces, and byte-identical app hashes across all nodes.
- `TestEngineMultiNodeRestart` / `TestEngineRaptorcastRestart` /
  `TestEngineCrashWindowRejoin` — kill + restart liveness matrices on TCP and
  RaptorCast transports (crash windows at each phase boundary).
- `TestEngineStatesyncRejoin` — behind-threshold node state-syncs and rejoins.
- `TestPersistenceAndRestart` — WAL/forkpoint/safety durability across crashes.
- `TestCometParity*` — bridge vs real CometBFT driving identical tx sets;
  app-hash parity oracle.
- `TestTCPHandshakeRejectsImpostor` — NodeId-claim authentication.
- `TestRetentionFallback` — pruned heights still serve from Pebble indexes.

## Durability

`blocks/` (Pebble), `bridge-results/` (Pebble: results + `tx/` + `chash/` +
`vs/` indexes), `wal/` (rotating event chunks), `forkpoint.rlp`,
`safety.rlp` (double-sign watermarks), `statesync-target.rlp` — all writes are
atomic (tmp+rename) and fsync'd before dependent commands run. Watermark
writes are diffed so only real changes hit disk.

## Docs

- [docs/integration.md](docs/integration.md) — wiring MonadBFT into a Cosmos
  SDK app: executor seam, genesis tooling, height semantics, pitfalls.
- [docs/migration.md](docs/migration.md) — moving a CometBFT-based Cosmos-EVM
  chain to MonadBFT: key binding, epochs, operational differences.
- [PLAN.md](PLAN.md) — Rust↔Go crate map and port design decisions.
- [docs/porting-plan.md](docs/porting-plan.md) — production porting + integration workstream plan.
- [docs/prod-review.md](docs/prod-review.md) — production findings + implementation status.
