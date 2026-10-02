package raptorcast

import (
	"container/list"
	"errors"
	"math/big"

	"github.com/abhijitkrm/monadbft-go/types"
)

// Chunk assignment — ports monad-raptorcast packet/assigner.rs.
//
// A ChunkAssignment maps chunk ids (0..numChunks) to validator targets.
// ChunkTarget.rebroadcastTargets is upstream's optional deterministic
// rebroadcast set; for regular (v0) chunks it is always nil and rebroadcast
// is decided at receive time via group.try_rebroadcast.

var (
	ErrTooManyChunks        = errors.New("too many chunks")
	ErrMerkleTreeTooDeep    = errors.New("merkle tree depth too large")
	ErrAppMessageTooLarge   = errors.New("app message too large")
	ErrAppMessageEmpty      = errors.New("app message empty")
	ErrEncoderFailed        = errors.New("raptor encoder creation failed")
	ErrChunkIDOverflow      = errors.New("chunk id overflow")
	ErrGroupNotFound        = errors.New("group not found")
	ErrInvalidAuthor        = errors.New("invalid author")
	ErrRedundancyTooHigh    = errors.New("redundancy too high")
	ErrSegmentTooSmall      = errors.New("segment size too small")
	ErrSegmentTooLarge      = errors.New("segment size too large")
	ErrMerkleTreeTooShallow = errors.New("merkle tree depth too small")
)

// chunkTarget — Rust ChunkTarget.
type chunkTarget struct {
	nodeIndex int
	// reserved for the deterministic (v1) scheme; always nil for v0.
	rebroadcastTargets []int
}

// chunkAssignment — Rust ChunkAssignment.
type chunkAssignment struct {
	nodes   []types.NodeId // ordered nodes referenced by index
	targets []chunkTarget  // len == num chunks
}

func (a *chunkAssignment) numChunks() int { return len(a.targets) }

func newChunkAssignment(capacity int, nodes []types.NodeId) *chunkAssignment {
	return &chunkAssignment{nodes: nodes, targets: make([]chunkTarget, 0, capacity)}
}

// unicast — Rust ChunkAssignment::unicast.
func unicastAssignment(recipient types.NodeId, numChunks int) *chunkAssignment {
	a := newChunkAssignment(numChunks, []types.NodeId{recipient})
	a.pushRange(0, 0, numChunks)
	return a
}

func (a *chunkAssignment) pushRange(nodeIndex, start, end int) {
	for i := start; i < end; i++ {
		a.push(nodeIndex, i)
	}
}

func (a *chunkAssignment) push(nodeIndex, chunkID int) {
	a.targets = append(a.targets, chunkTarget{nodeIndex: nodeIndex})
}

// chunkRouting resolves a chunk id to its recipient and rebroadcast set
// (Rust ChunkRouting). Used by the receive side to decide rebroadcasts.
type chunkRouting struct {
	recipient types.NodeId
	target    chunkTarget
	nodes     []types.NodeId
}

// resolveChunkID — Rust ChunkAssignment::resolve_chunk_id.
func (a *chunkAssignment) resolveChunkID(chunkID int) (chunkRouting, bool) {
	if chunkID < 0 || chunkID >= len(a.targets) {
		return chunkRouting{}, false
	}
	t := a.targets[chunkID]
	if t.nodeIndex >= len(a.nodes) {
		return chunkRouting{}, false
	}
	return chunkRouting{recipient: a.nodes[t.nodeIndex], target: t, nodes: a.nodes}, true
}

// rebroadcastTargets — Rust ChunkRouting::rebroadcast_targets: explicit list
// when present, else all nodes except the recipient.
func (r chunkRouting) rebroadcastTargets() []types.NodeId {
	if r.target.rebroadcastTargets != nil {
		out := make([]types.NodeId, 0, len(r.target.rebroadcastTargets))
		for _, i := range r.target.rebroadcastTargets {
			if i < len(r.nodes) {
				out = append(out, r.nodes[i])
			}
		}
		return out
	}
	out := make([]types.NodeId, 0, len(r.nodes))
	for _, n := range r.nodes {
		if n != r.recipient {
			out = append(out, n)
		}
	}
	return out
}

// maxTriples — monad_raptor::r10::lt::MAX_TRIPLES (u16 chunk-id bound).
const maxTriples = 1 << 16

// materialize — Rust ChunkAssignment::materialize: one Chunk per target.
func (a *chunkAssignment) materialize(segmentLen int) ([]*chunk, error) {
	if len(a.targets) == 0 {
		return nil, nil
	}
	if a.numChunks() > maxTriples {
		return nil, ErrTooManyChunks
	}
	chunks := make([]*chunk, 0, len(a.targets))
	for chunkID, t := range a.targets {
		chunks = append(chunks, &chunk{
			chunkID:   chunkID,
			recipient: a.nodes[t.nodeIndex],
			payload:   make([]byte, segmentLen),
		})
	}
	return chunks, nil
}

// partition — Rust Partition trait.
type partition interface {
	shuffle(seed [32]byte)
	assign(numBaseSymbols int, redundancy Redundancy) (*chunkAssignment, error)
	numChunksHint(numBaseSymbols int, redundancy Redundancy) (int, bool)
}

// evenPartition — Rust EvenPartition (full-node groups).
type evenPartition struct {
	nodes []types.NodeId
}

func (p *evenPartition) shuffle(seed [32]byte) {
	rng := newChaCha20Rng(seed)
	rng.shuffle(len(p.nodes), func(i, j int) {
		p.nodes[i], p.nodes[j] = p.nodes[j], p.nodes[i]
	})
}

func (p *evenPartition) assign(numBaseSymbols int, redundancy Redundancy) (*chunkAssignment, error) {
	numSymbols, ok := redundancy.scale(numBaseSymbols)
	if !ok {
		return nil, ErrTooManyChunks
	}
	a := newChunkAssignment(numSymbols, append([]types.NodeId(nil), p.nodes...))
	numNodes := len(p.nodes)
	if numNodes == 0 {
		return a, nil
	}
	for chunkID := 0; chunkID < numSymbols; chunkID++ {
		a.push(chunkID%numNodes, chunkID)
	}
	return a, nil
}

func (p *evenPartition) numChunksHint(numBaseSymbols int, redundancy Redundancy) (int, bool) {
	return evenPartitionNumChunks(numBaseSymbols, redundancy)
}

func evenPartitionNumChunks(numBaseSymbols int, redundancy Redundancy) (int, bool) {
	return redundancy.scale(numBaseSymbols)
}

// stakePartition — Rust StakePartition: validators (author excluded) with
// stake-proportional chunk obligations assigned round-robin.
type stakePartition struct {
	validators []stakedNode
	totalStake types.Stake
}

type stakedNode struct {
	id    types.NodeId
	stake types.Stake
}

// stakePartitionFromGroup — Rust StakePartition::from_group: drops the
// author, sums the remaining stake.
func stakePartitionFromGroup(group *validatorGroupView) *stakePartition {
	p := &stakePartition{}
	var total types.Stake
	for _, m := range group.members {
		if m == group.author {
			continue
		}
		s := group.stakeOf(m)
		p.validators = append(p.validators, stakedNode{id: m, stake: s})
		total = total.Add(s)
	}
	p.totalStake = total
	return p
}

func (p *stakePartition) snapshotNodes() []types.NodeId {
	nodes := make([]types.NodeId, len(p.validators))
	for i, v := range p.validators {
		nodes[i] = v.id
	}
	return nodes
}

func (p *stakePartition) shuffle(seed [32]byte) {
	rng := newChaCha20Rng(seed)
	rng.shuffle(len(p.validators), func(i, j int) {
		p.validators[i], p.validators[j] = p.validators[j], p.validators[i]
	})
}

func (p *stakePartition) assign(numBaseSymbols int, redundancy Redundancy) (*chunkAssignment, error) {
	if len(p.validators) == 0 {
		return newChunkAssignment(0, nil), nil
	}
	a, ok := p.assignRoundRobin(numBaseSymbols, redundancy)
	if !ok {
		return nil, ErrTooManyChunks
	}
	return a, nil
}

func (p *stakePartition) numChunksHint(numBaseSymbols int, redundancy Redundancy) (int, bool) {
	groupSize := len(p.validators) + 1 // add back the author
	return stakePartitionNumChunksHint(numBaseSymbols, redundancy, groupSize)
}

func stakePartitionNumChunksHint(numBaseSymbols int, redundancy Redundancy, groupSize int) (int, bool) {
	numValidators := groupSize - 1 // exclude author
	if numValidators < 0 {
		return 0, false
	}
	numScaled, ok := redundancy.scale(numBaseSymbols)
	if !ok {
		return 0, false
	}
	return numScaled + numValidators, true
}

// obligation — Rust StakePartition::obligation: (whole chunks, remainder)
// for `stake * scaledSymbols / totalStake`.
func (p *stakePartition) obligation(numScaledSymbols int, stake types.Stake) (int, types.Stake, bool) {
	if stake.IsZero() {
		return 0, types.Stake{}, false
	}
	stakeBig := new(big.Int).SetBytes(stake.Bytes[:])
	prod := new(big.Int).Mul(stakeBig, big.NewInt(int64(numScaledSymbols)))
	totalBig := new(big.Int).SetBytes(p.totalStake.Bytes[:])
	if totalBig.Sign() == 0 {
		return 0, types.Stake{}, false
	}
	quo, rem := new(big.Int).QuoRem(prod, totalBig, new(big.Int))
	if !quo.IsUint64() {
		return 0, types.Stake{}, false
	}
	quoU := quo.Uint64()
	if quoU > uint64(^uint(0)>>1) {
		return 0, types.Stake{}, false
	}
	var remStake types.Stake
	rem.FillBytes(remStake.Bytes[:])
	return int(quoU), remStake, true
}

// assignRoundRobin — Rust StakePartition::assign_round_robin: each validator
// gets floor(share) plus one rounding chunk if the remainder is nonzero;
// chunks are dealt round-robin over remaining obligations, final survivor
// takes its remainder in one range.
func (p *stakePartition) assignRoundRobin(numBaseSymbols int, redundancy Redundancy) (*chunkAssignment, bool) {
	capacity, ok := p.numChunksHint(numBaseSymbols, redundancy)
	if !ok {
		return nil, false
	}
	numScaled, ok := redundancy.scale(numBaseSymbols)
	if !ok {
		return nil, false
	}
	a := newChunkAssignment(capacity, p.snapshotNodes())

	type oblig struct {
		nodeIndex int
		remaining int
	}
	remaining := list.New()
	for i, v := range p.validators {
		whole, rem, ok := p.obligation(numScaled, v.stake)
		if !ok {
			return nil, false
		}
		total := whole
		if !rem.IsZero() {
			total++
		}
		remaining.PushBack(oblig{nodeIndex: i, remaining: total})
	}

	chunkID := 0
	for remaining.Len() > 0 {
		if remaining.Len() == 1 {
			e := remaining.Front()
			o := e.Value.(oblig)
			remaining.Remove(e)
			a.pushRange(o.nodeIndex, chunkID, chunkID+o.remaining)
			break
		}
		// One pass: give each still-obligated validator a single chunk,
		// dropping exhausted validators. Rust uses VecDeque::retain_mut,
		// a single in-place pass in order.
		for e := remaining.Front(); e != nil; {
			next := e.Next()
			o := e.Value.(oblig)
			if o.remaining == 0 {
				remaining.Remove(e)
				e = next
				continue
			}
			a.push(o.nodeIndex, chunkID)
			chunkID++
			o.remaining--
			e.Value = o
			if o.remaining == 0 {
				remaining.Remove(e)
			}
			e = next
		}
	}

	if a.numChunks() < numScaled || a.numChunks() > capacity {
		return nil, false
	}
	return a, true
}
