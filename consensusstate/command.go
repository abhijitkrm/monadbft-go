// Package consensusstate ports monad-consensus-state: the top-level
// consensus state machine that turns validated protocol messages and local
// timer events into ConsensusCommands (publish/schedule/commit/sync).
package consensusstate

import (
	"time"

	"github.com/abhijitkrm/monadbft-go/consensus"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Command — Rust ConsensusCommand. Consumed by the MonadState layer which
// maps them onto router/timer/ledger/txpool executors.
type Command interface{ isConsensusCmd() }

// CmdEnterRound — emitted whenever the pacemaker enters a new round
// (drives router epoch/round state).
type CmdEnterRound struct {
	Epoch types.Epoch
	Round types.Round
}

// CmdPublish — send a signed consensus message to RouterTarget. Delivery is
// NOT guaranteed; retry is handled at the state-machine level.
type CmdPublish struct {
	Target  types.RouterTarget
	Message messages.Validated
}

// CmdPublishToFullNodes — disseminate to this validator's full-node group.
type CmdPublishToFullNodes struct {
	Epoch         types.Epoch
	Round         types.Round
	BroadcastMode types.FullnodeBroadcastMode
	Message       messages.Validated
}

// CmdSchedule — schedule a local round timeout for `Round` in `Duration`.
type CmdSchedule struct {
	Round    types.Round
	Duration time.Duration
}

// CmdScheduleReset — cancel the scheduled round timeout.
type CmdScheduleReset struct{}

// CmdCreateProposal — ask the txpool/mempool to build a block proposal.
type CmdCreateProposal struct {
	NodeId                   types.NodeId
	Epoch                    types.Epoch
	Round                    types.Round
	SeqNum                   types.SeqNum
	HighQC                   cstypes.QuorumCertificate
	RoundSignature           cstypes.RoundSignature
	LastRoundTC              *cstypes.TimeoutCertificate
	FreshProposalCertificate *cstypes.FreshProposalCertificate

	TxLimit           uint64
	ProposalGasLimit  uint64
	ProposalByteLimit uint64
	Beneficiary       [20]byte
	TimestampNs       types.U128

	ExtendingBlocks         []*cstypes.ConsensusFullBlock
	DelayedExecutionResults []exec.FinalizedHeader
}

// CommitKind — Proposed | Voted | Finalized (Rust OptimisticPolicyCommit).
type CommitKind uint8

const (
	CommitProposed CommitKind = iota + 1
	CommitVoted
	CommitFinalized
)

// OptimisticPolicyCommit — Rust OptimisticPolicyCommit.
type OptimisticPolicyCommit struct {
	Kind        CommitKind
	Block       *cstypes.ConsensusFullBlock
	IsCanonical bool // Proposed only
}

// CmdCommitBlocks — commit blocks to the ledger at the given finality stage.
type CmdCommitBlocks struct {
	Commit OptimisticPolicyCommit
}

// CmdRequestSync — request blocks from peers (serviced by blocksync).
type CmdRequestSync struct {
	Range cstypes.BlockRange
}

// CmdCancelSync — cancel an outstanding blocksync request.
type CmdCancelSync struct {
	Range cstypes.BlockRange
}

// CmdRequestStateSync — too far behind: request a statesync with the new
// blocktree root and high_qc.
type CmdRequestStateSync struct {
	Root   cstypes.ConsensusBlockHeader
	HighQC cstypes.QuorumCertificate
}

// CmdTimestampUpdate — adjust local timestamp estimate.
type CmdTimestampUpdate struct {
	Adj cstypes.TimestampAdjustment
}

// CmdScheduleVote — schedule the vote timer for `Round` in `Duration`.
type CmdScheduleVote struct {
	Duration time.Duration
	Round    types.Round
}

func (CmdEnterRound) isConsensusCmd()         {}
func (CmdPublish) isConsensusCmd()            {}
func (CmdPublishToFullNodes) isConsensusCmd() {}
func (CmdSchedule) isConsensusCmd()           {}
func (CmdScheduleReset) isConsensusCmd()      {}
func (CmdCreateProposal) isConsensusCmd()     {}
func (CmdCommitBlocks) isConsensusCmd()       {}
func (CmdRequestSync) isConsensusCmd()        {}
func (CmdCancelSync) isConsensusCmd()         {}
func (CmdRequestStateSync) isConsensusCmd()   {}
func (CmdTimestampUpdate) isConsensusCmd()    {}
func (CmdScheduleVote) isConsensusCmd()       {}

// FromPacemakerCommand — Rust ConsensusCommand::from_pacemaker_command:
// translates pacemaker outputs into publish/schedule commands.
func FromPacemakerCommand(
	keypair *crypto.SecpKeyPair,
	certKeypair *crypto.BlsKeyPair,
	version uint32,
	cmd consensus.PacemakerCommand,
) []Command {
	switch c := cmd.(type) {
	case consensus.CmdEnterRound:
		advRound := messages.ConsensusMessage{
			Version: version,
			Message: messages.ProtocolMessage{
				Kind: messages.PMAdvanceRound,
				AdvanceRound: &messages.AdvanceRoundMessage{
					LastRoundCertificate: c.HighCert,
				},
			},
		}
		return []Command{
			CmdEnterRound{Epoch: c.Epoch, Round: c.Round},
			CmdPublishToFullNodes{
				Epoch:         c.Epoch,
				Round:         c.HighCert.Round(),
				BroadcastMode: types.FullnodeBroadcast,
				Message:       messages.Sign(advRound, keypair),
			},
		}
	case consensus.CmdPrepareTimeout:
		tmMsg := messages.NewTimeoutMessage(
			certKeypair, c.Timeout, c.HighExtend, c.SafeToVote, c.LastRC)
		msg := messages.ConsensusMessage{
			Version: version,
			Message: messages.ProtocolMessage{
				Kind:    messages.PMTimeout,
				Timeout: &tmMsg,
			},
		}
		return []Command{
			CmdPublish{
				// TODO should this be sent to epoch of next round?
				Target:  types.BroadcastTarget(c.Timeout.Epoch),
				Message: messages.Sign(msg, keypair),
			},
		}
	case consensus.CmdSchedule:
		return []Command{CmdSchedule{Round: c.Round, Duration: c.Duration}}
	case consensus.CmdScheduleReset:
		return []Command{CmdScheduleReset{}}
	}
	return nil
}
