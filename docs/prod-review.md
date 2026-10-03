# Production review — monadbft-go + cosmos-evm integration

Method: traced every state accumulator, RPC read path, validation path, and
config knob against upstream `monad-bft` (divergences verified in the Rust
source), plus the wiring in `bridge/engine.go` and `evmd`/`server`.
Findings ordered by severity. Status column tracks resolution.

---

## 1. Production-blocking

### 1.1 Unbounded in-memory retention — memory and boot time grow O(chain height)

Three independent accumulators, none ever pruned:

| Holder | Content | Ref |
|---|---|---|
| `Ledger.blocks` / `Ledger.committed` | every observed block (incl. orphans) / every committed block, forever | `bridge/ledger.go:37-38` |
| `App.results` / `App.valSets` / `App.txIndex` | per-height full result entry (txs + results + events), per-height valset, every tx hash | `bridge/app.go:117-126` |
| `ResultStore.Load()` | decodes **entire** history into memory at boot; `AttachStore` replays valsets 1..tip | `bridge/persist.go:121-175` |

At 1s blocks with ~100KB blocks, `App.results` alone retains ~8.6 GB/day, and
restart time grows linearly forever. The only deletes are `truncateIndex`
(crash repair above tip).

**Fix:** retention window (e.g. `retain_blocks` config) — serve older heights
from the Pebble stores on demand; add `ResultStore.Get(h)`; replace `txIndex`
with a bounded LRU or a Pebble `tx/` index; on `AttachStore`, load only the tip
window and valset meta.

### 1.2 Hot RPC paths are O(chain height)

- `Client.BlockByHash` walks **every height tip→1**, calling `SynthBlock` (full
  block build + hash) per candidate (`bridge/client.go:133-149`) — this is the
  `eth_getBlockByHash`/`HeaderByHash` path. At 1M blocks: minutes per call.
- `committedBlockByID` (HTTP `block_by_hash`), `certifierQC` (`Commit(tip)`
  fallback, polled by dashboards), `committedSeq` (per statesync request) are
  all linear scans (`bridge/ledger.go:553-597`).

**Fix:** maintain `id → seq` in the ledger (or use the blockstore's existing
`blk/{id}` index — already O(1) in Pebble) and track max-seq as a field.
`BlockByHash` becomes: id → seq → `committedBlock(seq)`.

### 1.3 Real block validation missing — `MockValidator` wired in production

`bridge/engine.go:272` wires `blocktree.MockValidator`, which only checks
header/body payload-id (`blocktree/blocktree.go:320-336`). Upstream production
wires `EthBlockValidator` (`monad-node/src/main.rs:389`), which checks:

- the **randao round signature** against the author pubkey — in the Go port
  `cstypes.VerifyRoundSignature` is **dead code** (zero callers);
- execution-header fields: `transactions_root == computed`,
  `number == seq_num`, `gas_limit == chain params`,
  `mix_hash == round_signature.hash`, base-fee fields (only base-fee is
  checked, via `EvmBlockPolicy`);
- tx-body validation (signatures/nonces/fees) at consensus time.

Impact: a proposer can bias randao/mix_hash freely, craft headers whose
execution fields disagree with the body (served over RPC and into EIP-2935
history), and honest validators vote on bodies nothing validated at consensus
(upstream rejects the block). Proposal-level QC verification *is* correct
(`validation.Validate → VerifyTip → VerifyQC`) — not a safety break, but the
largest upstream divergence in the validation path.

**Fix:** port `EthBlockValidator` into the bridge and wire it in place of
`MockValidator` (the `BlockValidator` interface already matches the Rust trait
shape).

### 1.4 TCP handshake has no authentication → connection eviction

`node/tcp.go`'s handshake exchanges bare NodeIds; `register` keys connections
by the *claimed* id and `old.drop()`s the existing connection when the new one
is in the preferred direction (`node/tcp.go:366-378`). Anyone who can reach the
port can claim a validator's NodeId and permanently evict its link (consensus
messages are signature-verified so injection fails, but blocksync/statesync
availability for that pair dies). Upstream's TCP has no identity state at all
— it routes by address, so this eviction vector is port-specific.

**Fix:** sign a nonce with the claimed key during the handshake (one secp
signature per connection), or drop id-keyed registration for address-keyed
routing like upstream.

---

## 2. Ops gaps

1. **`monadbft.json` is only read, never scaffolded.** Fresh `evmd init` +
   `--engine=monadbft` boots with `transport: "none"` — a validator can
   silently run without networking. Fix: scaffold in `init`/`testnet`, and
   fail fast when `transport=none` unless an explicit dev flag.
2. **Consensus metrics are not exposed in the shipped path.**
   `metrics.PrometheusHandler` is only served by `cmd/monadbft-node` (dev
   daemon); the evmd-embedded engine registers no `/metrics` for consensus
   internals. No per-peer labels/histograms either (tree-walk exporter emits
   flat counters/gauges).
3. **No pruning/retention config** for `blocks/` and `bridge-results/` — disk
   grows forever (WAL is the one bounded store: 8×1GiB chunks). CometBFT
   operators expect `pruning` knobs; add retain-window + compaction config.
4. **Comet-RPC compat HTTP shim is library-only** — `NewRPCServer` has no
   production caller; external tooling expecting `:26657` gets nothing. It
   also lacks body-size/rate limits (unbounded `json.Decode`). The in-process
   client covers embedded RPC/stream/indexer paths — a scope decision, but
   should be explicit.
5. **RPC stubs:** `block_search` unimplemented, `net_info` returns empty
   peers, `dump_consensus_state`/`consensus_state` empty, `tx_search` limited
   to `tx.hash`/`tx.height`, no WS `/subscribe` on the HTTP server.
6. **`x/consensuskeys` missing** — validator churn still requires genesis
   re-binding; top *feature* blocker for staking/epoch rotation in production
   (already tracked in the plan).
7. **Evidence emission absent** — equivocation is detected in `vote_state`
   but never surfaces; slashing stays off (tracked; upstream is also TODO).

---

## 3. Tuning notes

- **Chain params come from the simulator package.** `bridge/engine.go` (and 4
  other production files) import `swarm` for `DefaultChainParams()`/`MinBaseFee`
  — production gas limit 150M, byte limit 1.5MB, vote pace 300ms, all test
  defaults. Move params into `chaincfg` with per-chain config; wire from
  genesis/config.
- **Round timer = `delta*3 + vote_pace + local_processing`** with
  `local_processing = delta` (`consensus/pacemaker.go:111-114`) → ~1.9s
  worst-case round at defaults (delta 400ms). Block-time target drives
  `delta_ms`; for WAN fleets delta must exceed p99 one-way latency × 2 — and
  `TimestampLatencyEstimateNs` is hardcoded to 10ms in the engine wiring
  (raise for WAN).
- **Blocksync request timeout is `7*delta`** (~2.8s at defaults) — tight for
  WAN payload fetches; make it a config multiplier.
- **Hardcoded raptorcast/peerdisc knobs** in `buildRaptorcast`
  (MaxNumPeers 200, MaxGroupSize 10, request timeout 5s, prune thresholds) —
  surface in `EngineConfig` before validator-count tuning.
- **Config validation is one check** (`execution_delay ≥ 2`). `delta_ms ≤ 0`,
  `statesync_threshold ∈ {0,1}` (→ `LiveToStatesync = 0`, `StartExecution = 0`),
  negative refresh values all pass silently into consensus. Validate with
  bounds and cross-checks (`StatesyncToLive < LiveToStatesync`).

---

## 4. Verified solid (checked, no action)

- WAL chunk rotation + oldest-chunk pruning; wireauth replay filter
  fixed-size (WireGuard-style); raptorcast soft quotas (1000 slots / 20MB per
  author); timer wheel deletes on fire/cancel; blockbuffer `ReRoot` prunes
  `fullBlocks`/`blockHeaders`/`payloadCache`; vote/NE state prunes per round
  via `StartNewRound`; `BlockSyncRequests` self-cleans by round; spec maps
  bounded by delay window.
- Safety durability ordering: fsync'd atomic writes, watermark snapshot diffed
  so only real changes hit disk, written **before** publish commands execute
  (`node.go:495`).
- `BlockStore` closed-guard, `ErrClosed`-tolerant ledger writes,
  statesync-target lifecycle (idempotent re-apply, stale-clear at boot),
  supervisor restart with per-boot executors.

## Suggested priority

1. Retention windows (1.1) + RPC indexes (1.2) — compounding; a long-running
   chain dies on memory/boot/latency first.
2. `EthBlockValidator` port (1.3) — consensus-layer correctness vs upstream.
3. TCP handshake signing (1.4).
4. Config validation + `monadbft.json` scaffolding + metrics endpoint
   (2.1–2.3) — the "an operator can deploy this" checklist.
5. Chain-params move out of `swarm` + WAN tuning knobs (3).

---

## Status (as of implementation pass 1)

- [x] 1.1 retention windows + on-demand serving — `retain_blocks` mem window,
      `prune_keep_blocks` durable pruning; BlockStore `GetFinalized`/
      `BlocksSince`/`PruneBelow`; ResultStore `Get`/`LoadRecent`/`PruneBefore`;
      ledger + App bounded maps with store fallback
- [x] 1.2 RPC indexes / O(1) lookups — `blk/seq/pld/fin` + `tx/` + `chash/` +
      `vs/` keyspaces; `committedByID`/`certifiers`/`maxCommitted` maps;
      `BlockByHash` and `/block_by_hash` index-backed (both comet hash and
      consensus id accepted)
- [x] 1.3 production block validator — `bridge/validator.go`
      (`EvmBlockValidator`): randao round-sig verify, seq continuity, exec
      payload fields, tx decode + sig + chain-id checks. Wired into engine +
      test node paths in place of `blocktree.MockValidator`. Remaining vs
      upstream: state-dependent checks (nonce/balance) need the
      extending-branch account view — noted as follow-up.
- [x] 1.4 TCP handshake auth — `node/tcp.go` handshake v2: NodeId + nonce
      exchange then `DomainTCPAuth`-signed transcript per side; impostor
      claims rejected pre-registration. Raptorcast dataplane left
      address-routed (upstream-shaped, no id-keyed map).
- [x] 2.1–2.3 config — `EngineConfig.Validate()` (delta/delay/statesync/
      retain/prune/epoch/beneficiary/bind-ip), `metrics_addr` serves
      `monadbft_`-prefixed Prometheus counters (resolves curNode per request
      → survives statesync restarts), `monadbft.json` auto-scaffolds on
      first boot, `transport=none` warns loudly.
- [x] 2.5 partial — `block_search` + `tx_search` height ranges (syntax.Parse
      AST), `net_info` real peers via `Client.SetPeersFunc(node.Peers)`.
      Remaining: `dump_consensus_state`/`consensus_state` content, WS
      `/subscribe` on the HTTP shim (in-process `Client.Subscribe` covers the
      embedded path), body-size/rate limits on the shim.
- [x] 3.x tuning surfaces — `chaincfg.DefaultParams()` canonical home
      (swarm delegates); `monadbft.json` overrides: `tx_limit`,
      `proposal_gas_limit`, `proposal_byte_limit`, `vote_pace_ms`,
      `timestamp_latency_ms`, `max_num_peers`, `max_group_size`,
      `retain_blocks`, `prune_keep_blocks`.

## Measured (M1 Pro, in-process evmd)

- `BenchmarkFinalizeBlockEvm`: **~2,400 evm_tx/s** serial FinalizeBlock+Commit
  (512-tx blocks; ~246µs/tx — ante secp256k1 recovery + SDK decode + GC).
  Commit itself is ~1ms/block. **10K TPS requires parallel EVM execution**
  (BlockSTM-style, upstream's mechanism) — tracked as future work; with
  deferred execution the consensus pipeline does not wait on exec, so the
  committed-block rate is independent of this number until exec backlog hits
  the delay window.
- `BenchmarkConsensusCommit`: empty-block FinalizeBlock+Commit rate.
- `TestEvmIntegrityTransfers`: 8 funded senders × 3 signed transfers through
  a 4-node TCP devnet — inclusion, success results, gas, recipient balance,
  sender nonces, cross-node apphash equality.
- `TestEngineConfigValidate` / `TestRetentionFallback` / store window tests.

## Still open (next pass)

- [ ] `x/consensuskeys` module (validator churn without genesis rebinding)
- [ ] evidence emission + slashing (upstream also TODO)
- [ ] parallel/optimistic EVM execution for the >10K TPS target
- [ ] WS `/subscribe` + consensus-state RPC content + shim rate limits
- [ ] `evmd init`/`testnet` writes `validators.json`/`peers.json`/`monad.key.json`
      (currently the scaffold covers `monadbft.json` only)
- [ ] ops tooling: backup/restore scripts for `blocks/`+`wal/`+app DB
