# v0.1.0-alpha.1 — release notes

First alpha of MonadBFT as the consensus engine for Cosmos-EVM (`evmd
--engine=monadbft`). Intended for **evaluation on a dedicated server with 8
validators**, with the stock CometBFT engine as the comparison baseline.
Not for production or value-bearing networks.

Pin: `monadbft-go@v0.1.0-alpha.1` + `monad-evm@v0.1.0-alpha.1` (branch
`monadbft-engine-seam`), checked out side by side. Operator guide:
[`alpha-runbook.md`](alpha-runbook.md).

## What changed since the pre-alpha

### Final-only execution (the stability change)

The pre-alpha executed QC'd-but-unfinalized blocks speculatively *on the
app's own store* and rolled orphans back with `RollbackToVersion`. That
contradicts what every SDK subsystem assumes (`Commit` = final) and was the
root of the rechecker panic, the version-deletion race, and the
speculative-index bugs.

Upstream Monad executes speculatively too — but on TrieDB, which keeps
proposed results per block ID side by side; the SDK's single linear IAVL
history can't. So this release adapts the *block policy* instead:

- the app executes **finalized blocks only**;
- block N embeds the execution result of a **finalized** height `s` with
  `r(parent) ≤ s ≤ N − execution_delay` (`bridge/policy.go`,
  `FinalOnlyPolicy`). On the happy path this is exactly `N − delay`, as
  upstream; after timeouts it lags instead of deadlocking;
- validators verify `s` against their own finalized execution and *wait*
  (no vote) while it executes;
- the consensus core is unchanged except statesync reading the root's
  embedded result height instead of `root − delay` (identical behavior
  under a fixed delay).

`execution_mode: "speculative"` keeps the old path for A/B only.
Default `execution_delay` is now 5 (execution slack ≈ delay − 2 blocks).

### Fixes found by the alpha soak/bench harness

- **Duplicate tx inclusion** (would have shipped otherwise): with
  final-only execution the mempool validates against state several blocks
  behind the proposal frontier, so every upcoming leader (they all receive
  forwarded txs) re-proposed the same txs; repeats failed on nonce (~50% of
  block space wasted, failed receipts for successful txs). Proposals now
  exclude txs already carried by the extending chain or by finalized,
  not-yet-executed blocks; selection budget is widened accordingly.
- RPC shim per-IP rate limit is configurable (`rpc_rate_per_sec`,
  `rpc_rate_burst`; devnets bind RPC to loopback and disable it).
- devnet: `mempool.type = "app"` (evmd refuses the scaffold default).
- test harness: swarm simulations commit synchronously (no background app
  work racing the process-global test EVM config).

### Tooling

- `devnet init-files -engine monadbft|comet` — the same tool scaffolds a
  stock CometBFT network (tuned `timeout_commit`, default 300ms instead of
  the scaffold's 5s) for like-for-like comparison.
- `devnet soak` is a release gate: exits non-zero on any panic, any height
  whose block id or app hash differs across nodes (full 1..tip audit, not
  sampled), any duplicate tx inclusion, a killed node that never recovers,
  or a node that stops advancing. Reports client-observed committed TPS,
  block interval, submit→final+executed latency p50/p90/p99, and per-node
  consensus counters (timeouts, execution-lag).
- `apphash-diff` — finds the first height where stopped nodes' app hashes
  diverge and names the differing module stores.
- `scripts/node-backup.sh` — cold snapshot / verify / restore that never
  moves vote watermarks (`safety.rlp`) backwards.

## Measured (development laptop — NOT the target hardware)

Apple M1 Pro, 8 cores / 32 GB, **all 8 validators + load generator on one
machine** — every tx is CheckTx'd and executed 8× on shared cores, so
absolute numbers are machine-bound. Signed EVM transfers from 256 funded
senders, all to one recipient (worst case for parallel execution). Same
genesis, same harness, CometBFT `timeout_commit = 300ms`.

| Offered load | Metric | MonadBFT (final) | CometBFT (tuned) |
|---|---|---|---|
| 200 tx/s, node killed + restarted | committed tx/s | 167 | 180 |
| | block interval | 629 ms | 651 ms |
| | latency p50 / p99 | 2.05 s / 3.9 s | **0.92 s** / 4.7 s |
| | kill → back at tip | 8 s | 4 s |
| 600 tx/s, 3 runs each | committed tx/s | **382–391** | 241–371 |
| | block interval | **0.99–1.09 s** | 0.91–2.93 s |
| | latency p50 / p99 | 3.3–3.6 s / **5.9–6.6 s** | 2.3–4.5 s / 12–26 s |
| | soak result | **3/3 PASS** | 2/3 PASS (1 app-hash consensus failure) |
| 1500 tx/s | | machine saturated: round timeouts, 3–4 s blocks | machine saturated: mostly empty blocks |

Reading it honestly:

- At light load CometBFT has the better **median** latency: a MonadBFT
  block is final two rounds after it is proposed, and on an 8-node LAN a
  round costs about what a CometBFT height does. MonadBFT's wins are
  **throughput and tail latency under load** (consensus never waits on
  execution) and stability.
- MonadBFT ingests fewer submissions per second than CometBFT here because
  the bridge serializes CheckTx against block execution (see Known issues).
- Correctness across all 7 MonadBFT soak runs (200–1500 tx/s, incl.
  kill/restart): zero panics and zero cross-node block-id/app-hash
  mismatches at any height; zero duplicate inclusions in every run after
  the dedup fix (the first run is how the bug was found).

The dedicated-server runs are the real evaluation — use the A/B commands in
the runbook and sweep `-rate` to each engine's saturation point.

## Known issues

- **App-hash divergence observed once on the CometBFT path** (1 of 5
  CometBFT runs; 1 of 3 at 600 tx/s): one node's `bank` store diverged at one
  height → CometBFT `CONSENSUS FAILURE`, node halted. Not reproduced in two
  identical reruns or in-process (`TestParallelExecDeterminism*`: BlockSTM
  with a single hot recipient, with and without concurrent CheckTx).
  Never observed on MonadBFT (7 runs). The bridge serializes
  CheckTx/InsertTx with FinalizeBlock/Commit under `App.opMu`; CometBFT's
  local ABCI client does not — a plausible but **unconfirmed** explanation.
  If it occurs on the server: stop the nodes and run `apphash-diff` on
  their homes; please send the output.
- **Ingestion throughput**: the same serialization makes CheckTx wait while
  a block executes. Deliberately kept until the divergence above is
  understood.
- **No vote retry on late execution**: a block whose embedded result a
  validator hasn't executed yet isn't voted on; the round times out. Not
  observed below saturation (`rx_execution_lagging` = 0 in all runs).
- **Overload degrades into timeouts** rather than smaller blocks: at
  saturation, rounds time out (~1.9 s each). Raise `delta_ms` on slow
  hardware; proposal limits are `tx_limit` / `proposal_byte_limit`.
- Memory grows during runs (≈270 → 500 MB per node over 2 min under load);
  not yet characterized over hours — watch RSS in long soaks.
- Fixed validator set; liveness accounting uses QC signers (first 2f+1
  only) — devnet genesis uses a 10 000-block window with a 5% floor; IBC,
  `x/consensuskeys`, evidence: not implemented. See runbook §6.

## Upgrade notes

Not upgrade-compatible with pre-alpha devnets: `execution_mode` and
`execution_delay` are consensus-critical and changed defaults. Start fresh
networks (`devnet init-files`).
