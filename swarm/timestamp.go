package swarm

import (
	"math"
	"sort"
	"time"

	"github.com/abhijitkrm/monadbft-go/cstypes"
)

// TimestampAdjuster — port of monad-updaters::timestamp::TimestampAdjuster.
//
// Collects TimestampAdjustment deltas from consensus; once `adjustmentPeriod`
// (odd) deltas have accumulated, folds the median into the running adjustment.
type TimestampAdjuster struct {
	adjustment       int64
	adjustmentPeriod int
	deltas           []int64 // sorted
	maxDeltaNs       uint64
}

func NewTimestampAdjuster(maxDeltaNs uint64, adjustmentPeriod int) *TimestampAdjuster {
	if adjustmentPeriod%2 != 1 {
		panic("median accuracy expects odd period")
	}
	return &TimestampAdjuster{
		adjustmentPeriod: adjustmentPeriod,
		maxDeltaNs:       maxDeltaNs,
	}
}

func (a *TimestampAdjuster) addDelta(delta int64) {
	i := sort.Search(len(a.deltas), func(i int) bool { return a.deltas[i] >= delta })
	a.deltas = append(a.deltas, 0)
	copy(a.deltas[i+1:], a.deltas[i:])
	a.deltas[i] = delta

	if len(a.deltas) == a.adjustmentPeriod {
		a.adjustment += a.deltas[len(a.deltas)/2]
		a.deltas = a.deltas[:0]
	}
}

// determineSignedDelta — Rust determine_signed_delta: cap at max_delta_ns, then
// apply direction.
func (a *TimestampAdjuster) determineSignedDelta(t cstypes.TimestampAdjustment) int64 {
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
	return signed
}

// HandleAdjustment — Rust handle_adjustment (TimestampCommand::AdjustDelta).
func (a *TimestampAdjuster) HandleAdjustment(t cstypes.TimestampAdjustment) {
	a.addDelta(a.determineSignedDelta(t))
}

func (a *TimestampAdjuster) Adjustment() int64 { return a.adjustment }

// TimestamperConfig — Rust TimestamperConfig.
type TimestamperConfig struct {
	Period         time.Duration
	TimestampDrift time.Duration

	MaxAdjustDeltaNs uint64
	AdjustPeriod     int
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

// Timestamper — Rust Timestamper: produces TimestampUpdateEvent ticks at a
// fixed period, applying accumulated drift + median adjustment.
type Timestamper struct {
	events          []time.Duration // front = next tick
	period          time.Duration
	timestampDrift  time.Duration
	driftAdjustment time.Duration
	adjuster        *TimestampAdjuster
}

func NewTimestamper(startTime time.Duration, config TimestamperConfig) *Timestamper {
	return &Timestamper{
		events:         []time.Duration{startTime},
		period:         config.Period,
		timestampDrift: config.TimestampDrift,
		adjuster:       NewTimestampAdjuster(config.MaxAdjustDeltaNs, config.AdjustPeriod),
	}
}

// NextTick — Rust next_tick: pop front, push front+period, apply drift and
// median adjustment.
func (t *Timestamper) NextTick() time.Duration {
	tick := t.events[0]
	t.events[0] += t.period

	t.driftAdjustment += t.timestampDrift
	return t.adjustedTime(tick)
}

// PeekNext — Rust peek_next.
func (t *Timestamper) PeekNext() (time.Duration, bool) {
	if len(t.events) == 0 {
		return 0, false
	}
	return t.events[0], true
}

// adjustedTime — Rust adjusted_time. NOTE: the adjustment (tracked in ns) is
// applied via Duration::from_millis upstream — this preserves that behavior.
func (t *Timestamper) adjustedTime(tick time.Duration) time.Duration {
	adjust := t.adjuster.Adjustment()
	var abs uint64
	if adjust < 0 {
		abs = uint64(-(adjust + 1)) + 1 // i64 abs without overflow
	} else {
		abs = uint64(adjust)
	}
	delta := time.Duration(abs) * time.Millisecond
	if adjust < 0 {
		base := tick + t.driftAdjustment
		if delta > base {
			return 0 // saturating_sub
		}
		return base - delta
	}
	return tick + t.driftAdjustment + delta
}

// Adjuster — access to the inner TimestampAdjuster (AdjustDelta commands).
func (t *Timestamper) Adjuster() *TimestampAdjuster { return t.adjuster }
