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

### 1. Mempool rechecker panic under sustained load — **FIXED**

Nodes 0 and 3 crashed mid-run with:

```
panic: failed to get latest context for rechecker:
  failed to load state at height 775; version mismatch on immutable
  IAVL tree; version does not exist ... (latest height: 775)
```

**Root cause**: the bridge's speculative executor rewinds the commit
multistore (`RollbackToVersion` deletes versions) on orphan lineages.
The mempool rechecker's `GetLatestContext` went straight to
`BaseApp.CreateQueryContext` with no lock — a context built mid-rewind
resolved `LatestVersion` ahead of the materialized IAVL trees →
`ErrVersionDoesNotExist` → `runReorg` panicked.

**Fix** (monad-evm `96a76e9f` + monadbft-go `326504e`):
- `EVMD.SpecLock` — shared mutex; the mempool ctx callback holds it
  across `CreateQueryContext`; `SpecApp.rewindLocked` and
  `App.RollbackTo` hold it across `RollbackToVersion`. The
  LatestVersion→GetImmutable window is serialized.
- `runReorg` panic → log + skip (next head event retries). A node must
  never panic on a transient ctx error — defense in depth even outside
  this race.

**Verification**: two subsequent 180s soaks at 200 tx/s — **zero
panics** (previously 2 crashes in comparable windows).

### 2. Post-restart commit "stall" — **diagnosed: slashing jail**

SIGKILLed node restarts, replays WAL/watermarks, reconnects to all 3
peers, receives proposals and votes, forms QCs, fetches blocksync
payloads — then `commit_block` stops permanently.

**Root cause**: `x/slashing` jails the validator for liveness.
`signed_blocks_window=100`, `min_signed_per_window=0.5`, and at ~3
blocks/s a ~10s restart misses enough blocks to jail once the rolling
window fills — logs show
`slashing and jailing validator due to liveness fault ... jailed_until`.
The node keeps gossiping but is out of the valset, so it emits no
commits — correct-by-design behavior, not a consensus defect. After
`downtime_jail_duration` (600s) it would unjail and have to catch up.

Operational notes for real devnets:
- kill/restart drills on live devnets will jail validators — expected.
- Whether a jailed node should still *follow* the chain (execute
  commits without voting) rather than freeze is an engine behavior
  question — currently it stops committing entirely, so post-unjail it
  must blocksync the gap.
- For longer restart tests, `-kill-after` timing vs the 100-block
  window determines whether the node gets jailed before the run ends.

### 3. App-hash divergence at restored height — **likely artifact, watch**

At the stuck node's last persisted height, `/block?height=81` returned the
**same block hash** as peers but a **different `app_hash`**
(`BBF33F4E…` vs peers' `5346FA10…`). The RPC synthesizes `app_hash` from
the local result store — the leading explanation is a deferred-exec
phase artifact (stalled node's result at h reflects a different
replay/finalization phase than peers' settled values), not consensus
divergence: block hashes matched and the soak's sampled parity check
reported `parity=True` at equal heights in every run. Worth one
verification pass on the next soak before closing.

### 4. Fleet-wide freeze at h=184 — **seen once, not reproduced**

One soak run (the first post-fix run) showed all three live nodes
frozen at h=184 for 45+s while mempools kept accepting. Did not
reproduce on the next identical run — possibly a transient related to
the version-deletion race the SpecLock fix now serializes. If it
recurs, the diagnostic is per-node `consensus_events_local_timeout`
and `handle_proposal` deltas during the freeze.

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
