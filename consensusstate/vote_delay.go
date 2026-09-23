package consensusstate

import (
	"sort"

	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/types"
)

const voteDelayWindowMs uint64 = 5 * 60 * 1000

// nsToMs — Rust ns_to_ms: u128 ns -> u64 ms (saturating).
func nsToMs(timestampNs types.U128) uint64 {
	hi := timestampNs.Hi()
	if hi > 0 {
		return ^uint64(0)
	}
	return timestampNs.Lo() / 1_000_000
}

// VoteDelayTimerStart — Rust VoteDelayTimerStart.
type VoteDelayTimerStart struct {
	Round       types.Round
	StartedAtMs uint64
}

type timedVoteDelaySample struct {
	recordedAtMs           uint64
	readyAfterTimerStartMs uint64
}

// voteDelayMetricsWindow — Rust VoteDelayMetricsWindow: sliding window of
// vote-ready-latency samples driving p50/p90/p99 gauges.
type voteDelayMetricsWindow struct {
	samples []timedVoteDelaySample // FIFO order (recordedAtMs ascending)
}

func (w *voteDelayMetricsWindow) recordReadyAfterTimerStart(nowMs, readyMs uint64, m *metrics.Metrics) {
	w.prune(nowMs)
	w.samples = append(w.samples, timedVoteDelaySample{nowMs, readyMs})
	w.updateMetrics(m)
}

func (w *voteDelayMetricsWindow) refresh(nowMs uint64, m *metrics.Metrics) {
	if w.prune(nowMs) {
		w.updateMetrics(m)
	}
}

func (w *voteDelayMetricsWindow) prune(nowMs uint64) bool {
	cutoff := nowMs - minU64(nowMs, voteDelayWindowMs)
	pruned := false
	for len(w.samples) > 0 && w.samples[0].recordedAtMs < cutoff {
		w.samples = w.samples[1:]
		pruned = true
	}
	return pruned
}

func minU64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func (w *voteDelayMetricsWindow) updateMetrics(m *metrics.Metrics) {
	m.VoteDelay.ReadyAfterTimerStartP50Ms.Set(0)
	m.VoteDelay.ReadyAfterTimerStartP90Ms.Set(0)
	m.VoteDelay.ReadyAfterTimerStartP99Ms.Set(0)
	if len(w.samples) == 0 {
		return
	}
	values := make([]uint64, len(w.samples))
	for i, s := range w.samples {
		values[i] = s.readyAfterTimerStartMs
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	m.VoteDelay.ReadyAfterTimerStartP50Ms.Set(percentile(values, 50))
	m.VoteDelay.ReadyAfterTimerStartP90Ms.Set(percentile(values, 90))
	m.VoteDelay.ReadyAfterTimerStartP99Ms.Set(percentile(values, 99))
}

// percentile — Rust percentile: ceil(len*p/100)-th smallest (1-indexed).
func percentile(sorted []uint64, p uint64) uint64 {
	rank := (uint64(len(sorted))*p + 99) / 100
	if rank < 1 {
		rank = 1
	}
	return sorted[rank-1]
}
