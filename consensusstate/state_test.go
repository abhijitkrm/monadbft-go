package consensusstate_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/testutil"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// node bundles a consensus State with its keys and observed commits.
type node struct {
	id      types.NodeId
	st      *consensusstate.State
	key     *crypto.SecpKeyPair
	certKey *crypto.BlsKeyPair
	ts      *consensusstate.BlockTimestamp

	finalized []*cstypes.ConsensusFullBlock
	voted     []*cstypes.ConsensusFullBlock
}

type harness struct {
	nodes []*node
	vem   *validator.ValidatorsEpochMapping
	em    *validator.EpochManager
	cfg   *consensusstate.Config
	now   types.U128
}

func newHarness(t *testing.T, n int) *harness {
	t.Helper()
	var valData []validator.ValidatorData
	var mapEntries []struct {
		NodeId     types.NodeId
		CertPubKey crypto.BlsPubKey
	}
	for i := 0; i < n; i++ {
		kp := testutil.GetKey(uint64(i + 1))
		ck := testutil.GetCertKey(uint64(i + 1))
		id := types.NewNodeId(kp.PubKey())
		valData = append(valData, validator.ValidatorData{
			NodeId:     id,
			Stake:      types.StakeFromUint64(1),
			CertPubKey: ck.PubKey(),
		})
		mapEntries = append(mapEntries, struct {
			NodeId     types.NodeId
			CertPubKey crypto.BlsPubKey
		}{id, ck.PubKey()})
	}
	vem := validator.NewValidatorsEpochMapping()
	vem.Insert(types.Epoch(1), valData, validator.NewValidatorMapping(mapEntries))

	em := validator.NewEpochManager(types.SeqNum(1000), types.Round(20),
		map[types.Epoch]types.Round{1: 0})

	cfg := &consensusstate.Config{
		Delta: time.Second,
		ChainConfig: chaincfg.StaticConfig{P: chaincfg.Params{
			TxLimit:           10_000,
			ProposalGasLimit:  300_000_000,
			ProposalByteLimit: 4_000_000,
			VotePace:          time.Second,
		}},
		LiveToStatesyncThreshold:   10_000,
		StatesyncToLiveThreshold:   5_000,
		StartExecutionThreshold:    5_000,
		TimestampLatencyEstimateNs: types.U128FromUint64(1),
	}

	h := &harness{
		vem: vem,
		em:  em,
		cfg: cfg,
		now: types.U128FromUint64(1_000_000_000_000),
	}

	root := blocktree.RootInfo{
		Round:   types.GENESIS_ROUND,
		SeqNum:  types.GENESIS_SEQ_NUM,
		Epoch:   types.GENESIS_EPOCH,
		BlockId: types.GENESIS_BLOCK_ID,
	}
	highCert := cstypes.RoundCertFromQC(cstypes.GenesisQC())

	for i := 0; i < n; i++ {
		kp := testutil.GetKey(uint64(i + 1))
		ck := testutil.GetCertKey(uint64(i + 1))
		ts := consensusstate.NewBlockTimestamp(
			types.U128FromUint64(1_000_000_000_000_000),
			types.U128FromUint64(1))
		ts.UpdateTime(h.now)
		cs := consensusstate.NewConsensusState(em, cfg, root, *highCert)
		h.nodes = append(h.nodes, &node{
			id:      types.NewNodeId(kp.PubKey()),
			key:     kp,
			certKey: ck,
			ts:      ts,
			st: &consensusstate.State{
				Consensus:      cs,
				Metrics:        &metrics.Metrics{},
				EpochManager:   em,
				BlockPolicy:    blocktree.PassthruBlockPolicy{},
				ValEpochMap:    vem,
				Election:       validator.WeightedRoundRobin{},
				Version:        1,
				BlockValidator: blocktree.MockValidator{},
				BlockTimestamp: ts,
				NodeId:         types.NewNodeId(kp.PubKey()),
				Config:         cfg,
				Keypair:        kp,
				CertKeypair:    ck,
			},
		})
	}
	return h
}

// buildProposal turns a CmdCreateProposal into the ProposalMessage the
// txpool/executor layer would emit (Rust: proposal assembly in MonadState).
func buildProposal(n *node, cmd consensusstate.CmdCreateProposal) messages.ProposalMessage {
	body := cstypes.ConsensusBlockBody{Inner: cstypes.ConsensusBlockBodyInner{
		ExecutionBody: &exec.MockBody{Data: []byte(fmt.Sprintf("block-%d", cmd.SeqNum))},
	}}
	header := cstypes.ConsensusBlockHeader{
		BlockRound:              cmd.Round,
		Epoch:                   cmd.Epoch,
		QC:                      cmd.HighQC,
		Author:                  cmd.NodeId,
		SeqNum:                  cmd.SeqNum,
		TimestampNs:             cmd.TimestampNs,
		RoundSignature:          cmd.RoundSignature,
		DelayedExecutionResults: cmd.DelayedExecutionResults,
		ExecutionInputs:         &exec.MockProposedHeader{},
		BlockBodyId:             body.GetId(),
	}
	tip := cstypes.NewConsensusTip(n.key, header, cmd.FreshProposalCertificate)
	return messages.ProposalMessage{
		ProposalRound: cmd.Round,
		ProposalEpoch: cmd.Epoch,
		Tip:           tip,
		BlockBody:     body,
		LastRoundTC:   cmd.LastRoundTC,
	}
}

// nodeCmds pairs the commands a node emitted with that node — deliveries
// produce commands on the *recipient*, which must be processed under it.
type nodeCmds struct {
	n    *node
	cmds []consensusstate.Command
}

// execCmds drains commands emitted by src: delivers protocol messages,
// builds proposals from CreateProposal, records commits on the emitting
// node. Delivery results are queued FIFO, matching async executor semantics.
func (h *harness) execCmds(src *node, cmds []consensusstate.Command) {
	queue := []nodeCmds{{src, cmds}}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		for _, cmd := range item.cmds {
			switch c := cmd.(type) {
			case consensusstate.CmdPublish:
				queue = append(queue, h.deliver(c.Target, c.Message)...)
			case consensusstate.CmdPublishToFullNodes:
				// no full nodes in this harness — drop
			case consensusstate.CmdCreateProposal:
				prop := buildProposal(item.n, c)
				for _, dst := range h.nodes {
					queue = append(queue, nodeCmds{dst,
						dst.st.HandleProposalMessage(item.n.id, prop)})
				}
			case consensusstate.CmdCommitBlocks:
				switch c.Commit.Kind {
				case consensusstate.CommitFinalized:
					item.n.finalized = append(item.n.finalized, c.Commit.Block)
				case consensusstate.CommitVoted:
					item.n.voted = append(item.n.voted, c.Commit.Block)
				}
			}
		}
	}
}

// deliver routes one signed consensus message to its target(s) and returns
// each recipient's resulting commands, tagged with the recipient.
func (h *harness) deliver(target types.RouterTarget, msg messages.Validated) []nodeCmds {
	var out []nodeCmds
	deliver := func(dst *node) {
		pm := msg.Obj().Message
		var cmds []consensusstate.Command
		switch pm.Kind {
		case messages.PMProposal:
			cmds = dst.st.HandleProposalMessage(msg.Author, *pm.Proposal)
		case messages.PMVote:
			cmds = dst.st.HandleVoteMessage(msg.Author, *pm.Vote)
		case messages.PMTimeout:
			cmds = dst.st.HandleTimeoutMessage(msg.Author, *pm.Timeout)
		case messages.PMRoundRecovery:
			cmds = dst.st.HandleRoundRecoveryMessage(msg.Author, *pm.RoundRecovery)
		case messages.PMNoEndorsement:
			cmds = dst.st.HandleNoEndorsementMessage(msg.Author, *pm.NoEndorsement)
		case messages.PMAdvanceRound:
			cmds = dst.st.HandleAdvanceRoundMessage(msg.Author, *pm.AdvanceRound)
		}
		out = append(out, nodeCmds{dst, cmds})
	}
	switch target.Kind {
	case types.RouterBroadcast, types.RouterRaptorcast:
		for _, dst := range h.nodes {
			deliver(dst)
		}
	case types.RouterPointToPoint, types.RouterDirectPointToPoint:
		if dst := h.findNode(target.To); dst != nil {
			deliver(dst)
		}
	}
	return out
}

func (h *harness) findNode(id types.NodeId) *node {
	for _, n := range h.nodes {
		if n.id == id {
			return n
		}
	}
	return nil
}

// timeoutAll fires the local round timer on every node and processes all
// resulting traffic (timeout broadcasts → TC → new round → proposals...).
func (h *harness) timeoutAll() {
	var pending []nodeCmds
	for _, n := range h.nodes {
		pending = append(pending, nodeCmds{n,
			n.st.HandleTimeoutExpiry(n.st.Consensus.Pacemaker.GetCurrentRound())})
	}
	for _, p := range pending {
		h.execCmds(p.n, p.cmds)
	}
}

func TestConsensusSmoke(t *testing.T) {
	h := newHarness(t, 4)

	// Genesis: pacemaker starts at round 1, but Safety prevents proposing or
	// voting in the first round (highest_* init = current_round) — everyone
	// times out, forming TC(1), and the chain really starts at round 2.
	h.timeoutAll()
	for _, n := range h.nodes {
		if got := n.st.Consensus.Pacemaker.GetCurrentRound(); got < 2 {
			t.Fatalf("after TC(1): node %s at round %d, want >= 2", n.id, got)
		}
	}

	// Each timeout wave stalls only if the leader can't make progress; happy
	// path needs no further timeouts — proposals cascade via pump inside
	// execCmds. Drive rounds by timing out only when the chain stalls.
	for wave := 0; wave < 10; wave++ {
		done := true
		for _, n := range h.nodes {
			if len(n.finalized) < 3 {
				done = false
			}
		}
		if done {
			break
		}
		h.timeoutAll()
	}

	for i, n := range h.nodes {
		if len(n.finalized) < 3 {
			t.Fatalf("node %d finalized %d blocks, want >= 3", i, len(n.finalized))
		}
		for j, b := range n.finalized {
			want := types.SeqNum(uint64(j) + 1)
			if b.Header.SeqNum != want {
				t.Fatalf("node %d finalized[%d] seqnum %d, want %d",
					i, j, b.Header.SeqNum, want)
			}
		}
	}
}
