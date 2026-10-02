package node

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// TimestamperConfig — Rust monad-updaters::timestamper::TimestamperConfig.
// Mirrors swarm.TimestamperConfig but lives here so production nodes don't
// import the simulator.
type TimestamperConfig struct {
	// Period between TimestampUpdate events (Rust default 10ms).
	Period time.Duration
	// TimestampDrift — per-tick artificial drift (test hook; 0 in prod).
	TimestampDrift time.Duration

	MaxAdjustDeltaNs uint64
	AdjustPeriod     int // must be odd (median window)
}

// DefaultTimestamperConfig — Rust TimestamperConfig::default().
func DefaultTimestamperConfig() TimestamperConfig {
	return TimestamperConfig{
		Period:           10 * time.Millisecond,
		TimestampDrift:   0,
		MaxAdjustDeltaNs: 10_000_000_000,
		AdjustPeriod:     9,
	}
}

// timestampAdjuster — port of monad-updaters::timestamp::TimestampAdjuster
// (identical to swarm's copy; kept here to keep the dependency direction
// node←core only).
//
// Folds the median of every `adjustmentPeriod` (odd) signed deltas into the
// running adjustment, which the timestamper applies to the wall clock when
// emitting TimestampUpdate events.
type timestampAdjuster struct {
	adjustment       int64
	adjustmentPeriod int
	deltas           []int64 // sorted
	maxDeltaNs       uint64
}

func newTimestampAdjuster(maxDeltaNs uint64, adjustmentPeriod int) *timestampAdjuster {
	if adjustmentPeriod%2 != 1 {
		panic("median accuracy expects odd period")
	}
	return &timestampAdjuster{
		adjustmentPeriod: adjustmentPeriod,
		maxDeltaNs:       maxDeltaNs,
	}
}

func (a *timestampAdjuster) handleAdjustment(t cstypes.TimestampAdjustment) {
	delta := t.Delta.Lo()
	if t.Delta.Hi() != 0 || delta > a.maxDeltaNs {
		delta = a.maxDeltaNs
	}
	var signed int64
	if delta > math.MaxInt64 {
		signed = 0
	} else {
		signed = int64(delta)
	}
	if t.Direction == cstypes.TimestampAdjustBackward {
		signed = -signed
	}

	i := sort.Search(len(a.deltas), func(i int) bool { return a.deltas[i] >= signed })
	a.deltas = append(a.deltas, 0)
	copy(a.deltas[i+1:], a.deltas[i:])
	a.deltas[i] = signed

	if len(a.deltas) == a.adjustmentPeriod {
		a.adjustment += a.deltas[len(a.deltas)/2]
		a.deltas = a.deltas[:0]
	}
}

// timestamper — production Timestamper: emits EvTimestampUpdate at a fixed
// wall-clock period, carrying (now + accumulated drift + median adjustment).
type timestamper struct {
	mu       sync.Mutex
	adjuster *timestampAdjuster
	period   time.Duration
	drift    time.Duration
	driftAcc time.Duration
	done     chan struct{}
	stopped  sync.Once
}

func newTimestamper(cfg TimestamperConfig) *timestamper {
	return &timestamper{
		adjuster: newTimestampAdjuster(cfg.MaxAdjustDeltaNs, cfg.AdjustPeriod),
		period:   cfg.Period,
		drift:    cfg.TimestampDrift,
		done:     make(chan struct{}),
	}
}

// adjustedNow — Rust adjusted_time over wall clock. Preserves the upstream
// quirk: the ns-tracked adjustment is applied via Duration::from_millis.
func (t *timestamper) adjustedNow() time.Duration {
	t.mu.Lock()
	adjust := t.adjuster.adjustment
	t.driftAcc += t.drift
	drift := t.driftAcc
	t.mu.Unlock()

	var abs uint64
	if adjust < 0 {
		abs = uint64(-(adjust + 1)) + 1
	} else {
		abs = uint64(adjust)
	}
	delta := time.Duration(abs) * time.Millisecond
	base := time.Duration(time.Now().UnixNano()) + drift
	if adjust < 0 {
		if delta > base {
			return 0
		}
		return base - delta
	}
	return base + delta
}

// handle — TimestampCommand::AdjustDelta. Called on the node loop goroutine.
func (t *timestamper) handle(cmds []glue.TimestampCommand) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, cmd := range cmds {
		if c, ok := cmd.(glue.TimestampAdjustDelta); ok {
			t.adjuster.handleAdjustment(c.Adj)
		}
	}
}

// start emits EvTimestampUpdate every period until stop.
func (t *timestamper) start(sink EventSink) {
	go func() {
		ticker := time.NewTicker(t.period)
		defer ticker.Stop()
		for {
			select {
			case <-t.done:
				return
			case <-ticker.C:
				sink(glue.EvTimestampUpdate{
					Timestamp: types.U128FromUint64(uint64(t.adjustedNow().Nanoseconds())),
				})
			}
		}
	}()
}

func (t *timestamper) stop() {
	t.stopped.Do(func() { close(t.done) })
}
