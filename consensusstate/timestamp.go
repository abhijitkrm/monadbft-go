package consensusstate

import (
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/types"
)

// BlockTimestamp — Rust timestamp::BlockTimestamp: local wall clock (ns) plus
// proposal timestamp validation.
type BlockTimestamp struct {
	localTimeNs       types.U128
	maxDeltaNs        types.U128
	latencyEstimateNs types.U128 // TODO upstream: needs an upper-bound
}

func NewBlockTimestamp(maxDeltaNs, latencyEstimateNs types.U128) *BlockTimestamp {
	if latencyEstimateNs.IsZero() {
		panic("consensusstate: latency estimate must be > 0")
	}
	return &BlockTimestamp{
		maxDeltaNs:        maxDeltaNs,
		latencyEstimateNs: latencyEstimateNs,
	}
}

func (b *BlockTimestamp) UpdateTime(t types.U128) { b.localTimeNs = t }

func (b *BlockTimestamp) GetCurrentTime() types.U128 { return b.localTimeNs }

// GetValidBlockTimestamp — Rust get_valid_block_timestamp: max(local,
// prev+1), keeping timestamps strictly monotonic.
func (b *BlockTimestamp) GetValidBlockTimestamp(prevBlockTs types.U128) types.U128 {
	if b.localTimeNs.Cmp(prevBlockTs) <= 0 {
		return prevBlockTs.Inc()
	}
	return b.localTimeNs
}

func (b *BlockTimestamp) validBounds(timestamp, voteDelayNs types.U128) bool {
	maxDelta := b.maxDeltaNs.Add(voteDelayNs)
	lower := b.localTimeNs.SaturatingSub(maxDelta)
	upper := b.localTimeNs.Add(maxDelta)
	return lower.Cmp(timestamp) <= 0 && timestamp.Cmp(upper) <= 0
}

// ValidBlockTimestamp — Rust valid_block_timestamp. Returns the local-time
// adjustment if the proposal timestamp is acceptable, else nil.
func (b *BlockTimestamp) ValidBlockTimestamp(
	prevBlockTs, currBlockTs, voteDelayNs types.U128,
	isReproposal bool,
) *cstypes.TimestampAdjustment {
	if isReproposal {
		// can't validate precise bounds of a reproposal — require monotonic
		// increase and less than local time
		if currBlockTs.Cmp(prevBlockTs) > 0 && currBlockTs.Cmp(b.localTimeNs) < 0 {
			return &cstypes.TimestampAdjustment{
				Delta:     types.U128{},
				Direction: cstypes.TimestampAdjustForward,
			}
		}
		return nil
	}
	delta, ok := currBlockTs.CheckedSub(prevBlockTs)
	// block timestamp must be strictly monotonically increasing
	if !ok || delta.IsZero() {
		return nil
	}
	if !b.validBounds(currBlockTs, voteDelayNs) {
		return nil
	}
	adjustment := b.localTimeNs.AbsDiff(currBlockTs).SaturatingSub(b.latencyEstimateNs)
	dir := cstypes.TimestampAdjustBackward
	if currBlockTs.Cmp(b.localTimeNs) > 0 {
		dir = cstypes.TimestampAdjustForward
	}
	return &cstypes.TimestampAdjustment{Delta: adjustment, Direction: dir}
}
