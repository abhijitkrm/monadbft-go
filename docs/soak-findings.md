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

### 2. Post-restart commit stall — **root-caused, fixed**

SIGKILLed node restarts, replays WAL/watermarks, reconnects, fetches
blocksync payloads — then `commit_block` stops permanently while rounds
churn via TCs. Three compounding defects were found and fixed, verified
by an in-process 4-node reproduction
(`TestEngineMultiNodeRestartUnderLoad`, ~50% failure → deterministic
pass):

1. **Speculative job loss** — the async spec worker dropped jobs when
   its queue was full or when a chain-check raced a canonical commit;
   `drainSpec` treated enqueue as execution and retired the pending
   entry, leaving a permanent hole in the spec frontier →
   `ErrNotAvailableYet` → `rx_execution_lagging` → livelock. Fixed by
   keeping pending entries until `SpecResultID` confirms and re-driving
   the queue on every worker completion (`OnDone`), plus a `WouldChain`
   pre-flight to avoid busy spin-retries.
2. **Stale speculative index** — `SpecResultID` returned `bySeq[h]`
   without checking the entry's block ID, so a fork at the same height
   could serve the wrong appHash into a proposal (permanently
   incoherent block). Fixed: stale mapping → honest miss.
3. **Validator-set timing nondeterminism** (the deep one) —
   `finalizeRequest` built `DecidedLastCommit` and `NextValidatorsHash`
   from `a.appSet`, the *tip-scoped* mutable set. Spec execution races
   commits, so the same canonical block produced different requests
   depending on how many validator updates (e.g. the restarted node's
   own slashing-jail removal) had applied when the request was built —
   replayed heights diverged in exactly `distribution`+`staking` state
   (vote-reward allocation), then the blocktree rejected live
   proposals' embedded results → permanent incoherence. Captured live:
   peers' spec request for block 102 carried 4 votes (with the killed
   node ABSENT), node0's carried 3. Fixed by height-scoping:
   `DecidedLastCommit` resolves the set validating `seq-1`
   (`valSets[seq-2]`), `NextValidatorsHash` the set validating `seq`
   (`valSets[seq-1]`); `SpecApp` now folds validator updates along its
   own lineage (`spec.valSets`) so spec requests resolve identically
   across the canonical↔spec boundary. Same fix applied to
   `PrepareProposal` (`LocalLastCommit`/`NextValidatorsHash`) and the
   informational `commitJSON`/`dump_consensus_state` vote rendering.

Also note (operational, not a bug): `x/slashing` does jail the
restarted validator (`signed_blocks_window=100` at ~3 blk/s) — its
validator update is what fed defect 3.

### 3. App-hash divergence at restored height — **confirmed real, fixed**

The same-block-ID/different-`app_hash` seen in soak was *not* a
cosmetic artifact — it was defect 3 above: replayed canonical blocks
produced divergent distribution/staking state on the restarted node.
Per-store commit-hash comparison localized the divergence; the request
capture (`reqCaps`) diffed the exact `RequestFinalizeBlock` fields.
After the height-scoping fix the restarted node's apphash matches
peers at every height across repeated runs.

### 4. Fleet-wide freeze at h=184 — **seen once, not reproduced**

One soak run (the first post-fix run) showed all three live nodes
frozen at h=184 for 45+s while mempools kept accepting. Did not
reproduce on the next identical run — possibly a transient related to
the version-deletion race the SpecLock fix now serializes. If it
recurs, the diagnostic is per-node `consensus_events_local_timeout`
and `handle_proposal` deltas during the freeze.

## 2026-10-09 — final-only execution, 8 validators, A/B vs CometBFT

Execution moved to finalized blocks only (`FinalOnlyPolicy`, see
porting-plan D4 revision). Live 8-validator devnet on real binaries, soak
gate = zero panics + full 1..tip block-id/app-hash audit + zero duplicate
inclusions + kill recovery.

- **All 7 MonadBFT runs PASS** (200–1500 tx/s, incl. kill/restart, 8 s
  recovery). `rx_execution_lagging` = 0 everywhere.
- **Duplicate inclusion bug found and fixed.** Under final-only execution
  the mempool validates ~4 blocks behind the proposal frontier, and every
  upcoming leader receives forwarded txs → each re-proposed them; 40 348 tx
  slots carried 20 963 distinct txs in the first 200 blocks, repeats failed
  `invalid nonce`. Fix: proposals exclude txs carried by the extending chain
  or by finalized-not-yet-executed blocks (`TxPool.inflightTxs`), with the
  selection byte budget widened by their size. Gate: `perf.duplicate_txs`.
- **CometBFT baseline app-hash divergence** (1 of 5 runs, 600 tx/s): node0's
  `bank` store differed at h=46 → `CONSENSUS FAILURE`. `apphash-diff`
  localized it; not reproduced in 2 reruns nor in-process
  (`TestParallelExecDeterminism`, `…ConcurrentCheckTx`: BlockSTM with one hot
  recipient, ± concurrent CheckTx). Open; MonadBFT path serializes
  CheckTx with block execution (`App.opMu`), CometBFT's local client doesn't.
- Saturation (1500 tx/s) is machine-bound on the 8-core laptop for both
  engines; MonadBFT degrades into round timeouts (3–4 s blocks), CometBFT
  into empty blocks. Needs the dedicated server.

Numbers: `release-notes-v0.1.0-alpha.1.md`.

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
