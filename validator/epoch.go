package validator

import (
	"fmt"
	"sort"

	"github.com/abhijitkrm/monadbft-go/types"
)

// EpochManager mirrors Rust EpochManager: tracks (epoch -> start round)
// and schedules epoch starts on boundary blocks.
type EpochManager struct {
	EpochLength     types.SeqNum
	EpochStartDelay types.Round

	epochStarts map[types.Epoch]types.Round
	sorted      []types.Epoch // epochs sorted ascending
}

func NewEpochManager(epochLength types.SeqNum, epochStartDelay types.Round, knownEpochs map[types.Epoch]types.Round) *EpochManager {
	em := &EpochManager{
		EpochLength:     epochLength,
		EpochStartDelay: epochStartDelay,
		epochStarts:     make(map[types.Epoch]types.Round),
	}
	for e, r := range knownEpochs {
		em.insertEpochStart(e, r)
	}
	return em
}

func (em *EpochManager) insertEpochStart(epoch types.Epoch, round types.Round) {
	if existing, ok := em.epochStarts[epoch]; ok {
		if existing != round {
			panic(fmt.Sprintf("conflicting epoch start round: epoch %d: %d != %d", epoch, existing, round))
		}
		return
	}
	em.epochStarts[epoch] = round
	em.sorted = append(em.sorted, epoch)
	sort.Slice(em.sorted, func(i, j int) bool { return em.sorted[i] < em.sorted[j] })
}

// ScheduleEpochStart — if block is the last in its epoch, schedule the next
// epoch at block_round + epoch_start_delay.
func (em *EpochManager) ScheduleEpochStart(blockNum types.SeqNum, blockRound types.Round) {
	if !blockNum.IsBoundaryBlock(em.EpochLength) {
		return
	}
	next := types.Epoch(blockNum.ToEpoch(em.EpochLength).Uint64() + 1)
	em.insertEpochStart(next, blockRound+em.EpochStartDelay)
}

func (em *EpochManager) GetEpochStart(epoch types.Epoch) (types.Round, bool) {
	r, ok := em.epochStarts[epoch]
	return r, ok
}

// GetEpoch returns the epoch containing round: the latest epoch whose start
// round is <= round. Rust: epoch_starts.iter().rfind(|k| k.1 <= round)
func (em *EpochManager) GetEpoch(round types.Round) (types.Epoch, bool) {
	var found types.Epoch
	ok := false
	for _, e := range em.sorted {
		if em.epochStarts[e] <= round {
			found, ok = e, true
		} else {
			break
		}
	}
	return found, ok
}

// EpochStarts returns the map for inspection/serialization.
func (em *EpochManager) EpochStarts() map[types.Epoch]types.Round {
	return em.epochStarts
}
