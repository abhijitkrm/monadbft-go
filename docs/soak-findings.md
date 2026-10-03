# Soak findings — multi-node devnet under load

Evidence from `devnet soak` runs (commit `04265ca`), 4-validator TCP devnet,
Apple M1 Pro, `monad-1` chain, sustained signed-EVM-transfer load.

## What works (verified)

- **Fleet lockstep**: all 4 nodes advance committed heights together under
  sustained load (sampled every 10–15s, identical heights).
- **Throughput acceptance**: ~128–140 tx/s accepted into mempools at a
  200 tx/s offer rate (per-sender nonce-continuity submissions; rejections
  counted and retried, mostly during the kill window).
- **Restart recovery**: SIGKILLed validator rejoins and reaches tip in
  ~7–10s (durable replay: WAL + watermarks + forkpoint resume all log
  cleanly).
- **Bounded resources**: RSS ~230→360MB per node over ~2.5min under load;
  disk growth ~50MB/node; no runaway.
- **App-hash parity**: sampled `latest_app_hash` agrees across live nodes
  at equal heights (parity check skips lagging restart nodes).

## Defects caught by soak (release blockers)

### 1. Mempool rechecker panic under sustained load — **critical**

Nodes 0 and 3 crashed mid-run with:

```
panic: failed to get latest context for rechecker:
  failed to load state at height 775; version mismatch on immutable
  IAVL tree; version does not exist. Version has either been pruned, or
  is for a future block height (latest height: 775)
  [cosmos/cosmos-sdk@v0.54.3/baseapp/abci.go:1407]
```

The mempool rechecker calls `get latest context` → loads state at the
app's reported last height. Under monadbft's commit ordering (deferred
execution), the reported height can be a version IAVL has not yet
materialized → panic rather than retry. Not restart-specific — any node
under sustained tx load is exposed.

**Likely fix locations**: `mempool/` rechecker context acquisition in
monad-evm (tolerate not-yet-visible version / retry), or the bridge's
last-height reporting so it only exposes materialized versions.

### 2. Post-restart commit stall — **critical**

SIGKILLed node restarts, replays WAL/watermarks, reconnects, receives
proposals (`handle_proposal=52`) and votes (`vote_received=36`,
`created_qc=12`), fetches blocksync payloads from peers
(`payload_response_successful=50`, `request_failed_no_peers=0`) — but
`commit_block=0` permanently. Frozen at its restored height while the
fleet advances.

`dump_consensus_state` on the stuck node reports `height="0"`,
`step="no commits yet"`, and only **1 peer**.

Open hypotheses (not yet diagnosed):
- blocksync'd payloads land but the commit path gates on something the
  resumed forkpoint can't satisfy (parent-chain continuity / ledger gap)
- QC forms for rounds the node treats as already-finalized
- peer-set visibility: only 1 peer recorded → request fan-out limited

### 3. App-hash divergence at restored height — **needs diagnosis**

At the stuck node's last persisted height, `/block?height=81` returns the
**same block hash** as peers but a **different `app_hash`**
(`BBF33F4E…` vs peers' `5346FA10…`). The RPC synthesizes `app_hash` from
the local result store, so this is either:

- a replay/result-store artifact (interim speculative result persisted
  where peers serve the finalized one), or
- genuine execution divergence on the restart path (would be a
  determinism bug — parity tests pass in-process, so suspect the
  deferred-exec replay path specifically)

## Reproduce

```bash
devnet init-files -n 4 -o /tmp/soaknet -evmd /path/to/evmd \
  -transport tcp -chain-id monad-1 -fund 8
devnet soak -o /tmp/soaknet -evmd /path/to/evmd \
  -duration 120s -rate 200 -kill 2 -kill-after 35s -sample 15s
# report → /tmp/soaknet/soak-report.json
```

`--fund N` injects N deterministic ethsecp256k1 accounts into every
genesis (auth account + `atest` balance + bank supply) and writes
`soak-keys.json`. Soak then signs transfers per sender with strict nonce
continuity (a rejected tx retries its nonce), spreads them across node
RPCs (`36657+i`), samples heights/RSS/disk/apphash-parity, optionally
SIGKILLs and times rejoin, then verifies settle/drain post-load.

## Report fields

`submitted` / `rejected` counts, `samples[]` (heights, rss_mb, disk_mb,
apphash_parity), `kill_node` / `restarted` / `recovered_to_tip` /
`recovery_secs`, `settle_heights` (post-load drain check),
`final_heights`, `apphash_parity_fails`.
