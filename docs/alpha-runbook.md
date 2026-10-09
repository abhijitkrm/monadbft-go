# v0.1.0-alpha — operator runbook

Scope of this alpha: **8 validators, fixed genesis validator set, TCP
transport, final-only execution**, evaluated against stock CometBFT evmd on
the same hardware and load. Large validator sets, RaptorCast at scale,
`x/consensuskeys`, epochs and IBC are out of scope (see "Known limits").

## 1. Build

Both repositories must be checked out **side by side** — the fork's
`evmd/go.mod` resolves the engine with `replace … => ../../monadbft-go`:

```bash
mkdir -p ~/monadbft && cd ~/monadbft
git clone https://github.com/abhijitkrm/monadbft-go
git clone -b monadbft-engine-seam https://github.com/abhijitkrm/monad-evm
(cd monadbft-go && git checkout v0.1.0-alpha.1)
(cd monad-evm   && git checkout v0.1.0-alpha.1)

# evmd (always links the MonadBFT backend; --engine selects at start)
(cd monad-evm && make install)            # → $(go env GOPATH)/bin/evmd
# devnet tool (init / start / soak / bench)
(cd monadbft-go/bridge && go build -o ~/bin/devnet ./cmd/devnet)
# app-hash divergence triage
(cd monadbft-go/bridge && go build -o ~/bin/apphash-diff ./cmd/apphash-diff)
```

Requirements: Go ≥ 1.25.9, a C toolchain (CGO), Linux or macOS. Raise the
open-file limit before running 8 nodes on one host: `ulimit -n 65536`.

## 2. Single-host 8-validator devnet

```bash
devnet init-files -n 8 -o ~/net/monad -evmd $(which evmd) \
  -engine monadbft -transport tcp -chain-id monad-1 -fund 256
devnet start -o ~/net/monad -evmd $(which evmd)       # Ctrl-C stops the fleet
```

`init-files` scaffolds `node{0..7}/evmd` homes via `evmd testnet
init-files --single-host`, then lays the MonadBFT files on top:
`monad.key.json` per node, shared `validators.json` + `peers.json`, and a
per-node `config/monadbft.json`. `-fund N` adds N deterministic funded EVM
accounts (`soak-keys.json`) used by the load generator.

Each node's raw output is appended to `node{i}/evmd/evmd.log`.

### Ports (node i)

| Surface | Port |
|---|---|
| Consensus TCP | 9000+i |
| CometBFT-compat RPC (`/status`, `/block`, `/broadcast_tx_*`) | 36657+i |
| Prometheus `/metrics` (consensus counters, `monadbft_` prefix) | 9100+i |
| Ethereum JSON-RPC | 8645+i |
| gRPC / gRPC-web | 9190+i / 9990+i |
| Ethereum JSON-RPC WebSocket | 8746+i |

### Key `monadbft.json` settings (consensus-critical ones must match fleet-wide)

| Field | Default | Notes |
|---|---|---|
| `execution_mode` | `final` | **consensus-critical.** `final`: the app executes finalized blocks only; `speculative`: legacy SpecApp path (A/B only) |
| `execution_delay` | 5 | **consensus-critical.** Proposal N embeds the result of a finalized height ≤ N−delay. Execution slack ≈ delay−2 blocks; raise it if `rx_execution_lagging` climbs |
| `delta_ms` | 400 | round-timer base; for WAN must exceed 2× p99 one-way latency |
| `vote_pace_ms` | 300 | **consensus-critical.** minimum time between a validator's votes — the block-time floor |
| `retain_blocks` / `prune_keep_blocks` | 4096 / 0 | memory window / disk retention (0 = archive) |
| `metrics_addr`, `rpc_addr` | set by init-files | |
| `rpc_rate_per_sec` / `rpc_rate_burst` | 0 (= 60/s, burst 120) | per-IP limit on the RPC shim; devnet sets −1 (unlimited, loopback-bound). Never disable on a public bind |

### Multi-host

Run `init-files` once with `-ip <advertise-ip>` per host layout, or edit
`peers.json` / each `monadbft.json` (`tcp_address`, `advertise_ip`) so every
node advertises a routable address; copy the shared `validators.json`,
`peers.json` and `genesis.json` to all hosts unchanged.

## 3. Soak and A/B benchmark against CometBFT

The same tool drives both engines with an identical signed-EVM-transfer
load and measures from the client side (node0 `/status` polled every
50ms): committed TPS, mean block interval, and **submit → final+executed
latency** p50/p90/p99.

```bash
# MonadBFT
devnet init-files -n 8 -o ~/net/monad -evmd $(which evmd) -engine monadbft -fund 256
devnet soak -o ~/net/monad -evmd $(which evmd) -duration 10m -rate 1000 -workers 32 \
  -kill 2 -kill-after 3m -sample 15s

# CometBFT baseline (tuned: timeout_commit 300ms — the evmd scaffold default of 5s
# would be a straw man; sweep with -comet-commit-timeout)
devnet init-files -n 8 -o ~/net/comet -evmd $(which evmd) -engine comet -fund 256 \
  -comet-commit-timeout 300ms
devnet soak -o ~/net/comet -evmd $(which evmd) -duration 10m -rate 1000 -workers 32 \
  -kill 2 -kill-after 3m -sample 15s
```

`soak` exits non-zero unless **all** of these hold, and writes
`<dir>/soak-report.json` either way:

- zero `panic:` / `fatal error:` lines in any node's `evmd.log`;
- every height 1..min(final) has an identical block id **and** app hash on
  every node (covers the heights the killed node replayed);
- no live sample where two nodes at the same height report different app
  hashes;
- the killed node recovers to tip; every node advances during the settle.

Both engines share genesis, including the tuned slashing parameters
(`-signed-blocks-window 10000`, `-min-signed-per-window 0.05`, see Known
limits). Compare `perf.*` across the two reports. Sweep `-rate` upward to
find each engine's saturation point (committed TPS stops tracking offered
rate, latency p99 climbs).

## 4. Backup and restore

`scripts/node-backup.sh` takes **cold** snapshots — `application.db`,
`bridge-results/` and `monadbft/blocks/` are separate databases with no
cross-store atomic snapshot. A cold copy is always self-consistent: on boot
the bridge reconciles the app store and result index to the persisted
forkpoint (rollback above it, backfill below it).

```bash
# stop the node (SIGTERM, wait for exit), then:
scripts/node-backup.sh snapshot ~/net/monad/node3/evmd /backups            # keys excluded
scripts/node-backup.sh verify   /backups/node3-evmd-<ts>.tar.gz
scripts/node-backup.sh restore  /backups/node3-evmd-<ts>.tar.gz ~/net/monad/node3/evmd
```

What a home holds:

| Path | Contents |
|---|---|
| `config/monad.key.json`, `priv_validator_key.json`, `node_key.json` | **secrets** — back up separately, encrypted; excluded from snapshots unless `--include-keys` |
| `config/genesis.json`, `monadbft.json`, `app.toml`, `config.toml` | configuration |
| `data/application.db`, EVM/tx indexers | Cosmos app state |
| `data/bridge-results/` | per-height execution results (Pebble) |
| `data/monadbft/blocks/`, `wal/` | consensus block store (Pebble) + write-ahead log |
| `data/monadbft/forkpoint.rlp`, `validators.rlp` | consensus resume point |
| `data/monadbft/safety.rlp` | **vote watermarks** — see below |

**Equivocation hazard.** Restoring an *older* `safety.rlp` onto a validator
that voted after the snapshot can make it vote twice in a round. `restore`
keeps whichever `safety.rlp` is newer (the node's or the archive's); if the
node's copy is lost, it warns — keep that validator offline until the
network has moved well past the snapshot before starting it.

Recovery alternatives: a wiped node (keep `safety.rlp`) rejoins by
statesync automatically; a node that is merely behind blocksyncs.

## 5. What to watch

- `monadbft_…rx_execution_lagging` — blocks left unvoted because execution
  hadn't produced the needed result. Steady growth ⇒ raise
  `execution_delay` or the box is too slow for the offered load.
- `…local_timeout`, `…handle_proposal` — round timeouts vs proposals; a
  freeze shows timeouts climbing while `commit_block` stalls.
- `/status` heights across nodes; `evmd.log` for `panic:`.
- **App-hash divergence** (a node stops advancing; CometBFT logs
  `CONSENSUS FAILURE … wrong Block.Header.AppHash`, MonadBFT shows
  `rx_bad_state_root` / the node's proposals never get votes): stop the
  nodes and run `apphash-diff ~/net/x/node{0..7}/evmd` — it prints the
  first divergent height and the module stores that differ. Keep the homes
  and send the output.

## 6. Known limits (alpha)

- **Fixed validator set.** `epoch_length` defaults to never: the consensus
  set is the genesis set. App-side staking changes (including jailing)
  affect rewards/bonding only — a jailed validator keeps voting.
- **Liveness accounting.** A MonadBFT QC carries only the first 2f+1 votes
  (6 of 8), so honest validators are routinely absent from
  `DecidedLastCommit`. Devnet genesis therefore uses a long signed-blocks
  window and a 5% floor; a validator consistently slower than its peers
  (e.g. far away on a WAN) can still be under-counted for rewards.
- **No vote retry on late execution.** A proposal whose embedded result the
  validator hasn't executed yet is not voted on; the round times out
  (backpressure). Size `execution_delay` so execution keeps up.
- **Orphaned-proposal txs** stay marked reaped in the mempool until it
  re-admits them (no resurrection yet).
- IBC (counterparties verifying this chain), `x/consensuskeys`, evidence
  emission, WS `/subscribe` on the RPC shim — not implemented.
- Hot backups are not supported.
