package swarm

import (
	"fmt"
	"math"
	"reflect"
	"time"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/types"
)

// NodesTerminator — Rust NodesTerminator: decides when the swarm driver stops.
type NodesTerminator interface {
	ShouldTerminate(nodes *Nodes, nextTick time.Duration) bool
}

// UntilTerminator — Rust UntilTerminator: stop on tick/block/epoch/round/step
// budget, whichever hits first.
type UntilTerminator struct {
	untilTick  time.Duration
	untilBlock int
	untilEpoch types.Epoch
	untilRound types.Round
	untilStep  int
}

func NewUntilTerminator() *UntilTerminator {
	return &UntilTerminator{
		untilTick:  time.Duration(math.MaxInt64), // Duration::MAX
		untilBlock: int(^uint(0) >> 1),
		untilEpoch: types.Epoch(^uint64(0)),
		untilRound: types.Round(^uint64(0)),
		untilStep:  int(^uint(0) >> 1),
	}
}

func (t *UntilTerminator) UntilTick(tick time.Duration) *UntilTerminator {
	t.untilTick = tick
	return t
}
func (t *UntilTerminator) UntilBlock(n int) *UntilTerminator {
	t.untilBlock = n
	return t
}
func (t *UntilTerminator) UntilRound(r types.Round) *UntilTerminator {
	t.untilRound = r
	return t
}
func (t *UntilTerminator) UntilEpoch(e types.Epoch) *UntilTerminator {
	t.untilEpoch = e
	return t
}
func (t *UntilTerminator) UntilStep(n int) *UntilTerminator {
	if n < 1 {
		panic("until_step must be >= 1")
	}
	t.untilStep = n
	return t
}

// ShouldTerminate — Rust should_terminate. The step counter decrements on
// every call, matching upstream.
func (t *UntilTerminator) ShouldTerminate(nodes *Nodes, nextTick time.Duration) bool {
	shouldTerminate := t.untilStep == 0 ||
		nextTick > t.untilTick ||
		anyNode(nodes, func(nd *Node) bool {
			return nd.Executor.Ledger().FinalizedBlocksLen() > t.untilBlock
		}) ||
		allNodes(nodes, func(nd *Node) bool {
			cs := nd.State.Consensus()
			return cs != nil && cs.Consensus.GetCurrentEpoch() >= t.untilEpoch
		}) ||
		anyNode(nodes, func(nd *Node) bool {
			cs := nd.State.Consensus()
			return cs != nil && cs.Consensus.GetCurrentRound() > t.untilRound
		})
	t.untilStep--
	return shouldTerminate
}

// ProgressTerminator — Rust ProgressTerminator: run until every monitored node
// has at least `expected` finalized blocks, then assert ledgers agree on the
// prefix. Panics on timeout.
type ProgressTerminator struct {
	nodesMonitor map[ID]int
	timeout      time.Duration
}

func NewProgressTerminator(nodesMonitor map[ID]int, timeout time.Duration) *ProgressTerminator {
	return &ProgressTerminator{nodesMonitor: nodesMonitor, timeout: timeout}
}

// ExtendAll — Rust extend_all.
func (p *ProgressTerminator) ExtendAll(progress int) {
	for id := range p.nodesMonitor {
		p.nodesMonitor[id] += progress
	}
}

func (p *ProgressTerminator) ShouldTerminate(nodes *Nodes, _ time.Duration) bool {
	if nodes.tick > p.timeout {
		actual := map[ID]int{}
		for id, nd := range nodes.states {
			actual[id] = nd.Executor.Ledger().FinalizedBlocksLen()
		}
		panic(fmt.Sprintf("ProgressTerminator timed-out, expecting progress %v, got %v",
			p.nodesMonitor, actual))
	}

	var longest []FinalizedBlock
	for id, expectedLen := range p.nodesMonitor {
		nd := nodes.states[id]
		if nd == nil {
			panic(fmt.Sprintf("monitored node %v does not exist", id))
		}
		blocks := nd.Executor.Ledger().GetFinalizedBlocks()
		if len(blocks) < expectedLen {
			return false
		}
		if len(blocks) > len(longest) {
			longest = blocks
		}
	}
	if longest == nil {
		panic("must have at least 1 monitored node")
	}

	// Once the termination condition is met, every ledger's first expected_len
	// blocks must equal the longest ledger's prefix (and seq_nums must be
	// consecutive starting at genesis+1).
	for id, expectedLen := range p.nodesMonitor {
		blocks := nodes.states[id].Executor.Ledger().GetFinalizedBlocks()
		bySeq := make(map[types.SeqNum]*cstypes.ConsensusFullBlock, len(blocks))
		for _, b := range blocks {
			bySeq[b.SeqNum] = b.Block
		}

		nextSeq := types.GENESIS_SEQ_NUM.Add(types.SeqNum(1))
		for i, ref := range longest {
			if i >= expectedLen {
				break
			}
			if ref.Block.GetSeqNum() != nextSeq {
				panic(fmt.Sprintf("block %d doesn't exist", nextSeq.Uint64()))
			}
			b, ok := bySeq[ref.SeqNum]
			if !ok {
				panic(fmt.Sprintf("node %v missing block %d", id, nextSeq.Uint64()))
			}
			if !reflect.DeepEqual(*b, *ref.Block) {
				panic(fmt.Sprintf("node %v ledger diverges at seq %d", id, ref.SeqNum.Uint64()))
			}
			nextSeq++
		}
	}
	return true
}

func anyNode(n *Nodes, f func(*Node) bool) bool {
	for _, nd := range n.states {
		if f(nd) {
			return true
		}
	}
	return false
}

func allNodes(n *Nodes, f func(*Node) bool) bool {
	for _, nd := range n.states {
		if !f(nd) {
			return false
		}
	}
	return true
}
