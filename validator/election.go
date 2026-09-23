package validator

import (
	"encoding/binary"
	"math/big"

	"github.com/abhijitkrm/monadbft-go/types"
)

// WeightedRoundRobin ports monad-validator::weighted_round_robin.
// Leader for a round = stake-weighted random pick seeded by
// ChaCha20Rng::seed_from_u64(round).
type WeightedRoundRobin struct{}

// seedFromU64 replicates rand_core 0.6.4 SeedableRng::seed_from_u64 —
// PCG32 expansion of the u64 seed into 32 bytes.
func seedFromU64(state uint64) [32]byte {
	const mul = uint64(6364136223846793005)
	const inc = uint64(11634580027462260723)
	var seed [32]byte
	for i := 0; i < 32; i += 4 {
		state = state*mul + inc
		xorshifted := uint32(((state >> 18) ^ state) >> 27)
		rot := uint32(state >> 59)
		x := xorshifted>>rot | xorshifted<<(32-rot)
		binary.LittleEndian.PutUint32(seed[i:], x)
	}
	return seed
}

var u256Max = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// randomize256WithRng — Rust randomize_256_with_rng: rejection-sample a
// U256 < m from the ChaCha stream (LE bytes).
func randomize256(stream *chacha20Stream, m *big.Int) *big.Int {
	// max = U256::MAX - (U256::MAX - m + 1) % m
	max := new(big.Int).Sub(u256Max, m)
	max.Add(max, big.NewInt(1))
	max.Mod(max, m)
	max.Sub(u256Max, max)
	var b [32]byte
	for {
		stream.fill(b[:])
		r := new(big.Int).SetBytes(reverse(b[:]))
		if r.Cmp(max) <= 0 {
			return r.Mod(r, m)
		}
	}
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[len(b)-1-i] = c
	}
	return out
}

// LeaderElection — Rust leader_election::LeaderElection trait.
type LeaderElection interface {
	GetLeader(round types.Round, valSet *ValidatorSet) types.NodeId
}

// GetLeader — Rust WeightedRoundRobin::get_leader(round, validators).
func (w WeightedRoundRobin) GetLeader(round types.Round, valSet *ValidatorSet) types.NodeId {
	return w.getLeader(round, valSet.Members(), func(id types.NodeId) types.Stake {
		s, _ := valSet.StakeOf(id)
		return s
	})
}

// getLeader — the raw algorithm; members must be in sorted (map) order and
// zero-stake entries are skipped.
func (WeightedRoundRobin) getLeader(round types.Round, members []types.NodeId, stakeOf func(types.NodeId) types.Stake) types.NodeId {
	var bounds []struct {
		id    types.NodeId
		bound *big.Int // cumulative stake upper bound (exclusive index space)
	}
	total := new(big.Int)
	for _, id := range members {
		s := stakeOf(id)
		if s.IsZero() {
			continue
		}
		total.Add(total, s.Big())
		bounds = append(bounds, struct {
			id    types.NodeId
			bound *big.Int
		}{id, new(big.Int).Set(total)})
	}
	if len(bounds) == 0 {
		panic("election: no validator has positive stake")
	}
	seed := seedFromU64(round.Uint64())
	stream := newChaCha20Stream(seed)
	stakeIndex := randomize256(stream, total)
	// binary search: first bound > stake_index
	lo, hi := 0, len(bounds)
	for lo < hi {
		mid := (lo + hi) / 2
		if bounds[mid].bound.Cmp(stakeIndex) > 0 {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return bounds[lo].id
}
