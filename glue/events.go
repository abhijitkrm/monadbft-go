package glue

import (
	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/types"
)

// MonadEvent — Rust MonadEvent enum: inputs to MonadState::update.
type MonadEvent interface{ isMonadEvent() }

type evBase struct{}

func (evBase) isMonadEvent() {}

// ---------------------------------------------------------------------------
// ConsensusEvent — Rust ConsensusEvent.
// ---------------------------------------------------------------------------

type ConsensusEvent interface {
	MonadEvent
	isConsensusEvent()
}

type consEvBase struct{ evBase }

func (consEvBase) isConsensusEvent() {}

// EvConsensusMessage — Message{sender, unverified_message}.
type EvConsensusMessage struct {
	consEvBase
	Sender            types.NodeId
	UnverifiedMessage messages.Unverified
}

// EvConsensusTimeout — Timeout(round).
type EvConsensusTimeout struct {
	consEvBase
	Round types.Round
}

// EvConsensusBlockSync — BlockSync{block_range, full_blocks}.
type EvConsensusBlockSync struct {
	consEvBase
	BlockRange cstypes.BlockRange
	FullBlocks []cstypes.ConsensusFullBlock
}

// EvConsensusSendVote — SendVote(round).
type EvConsensusSendVote struct {
	consEvBase
	Round types.Round
}

// ---------------------------------------------------------------------------
// BlockSyncEvent — Rust BlockSyncEvent.
// ---------------------------------------------------------------------------

type BlockSyncEvent interface {
	MonadEvent
	isBlockSyncEvent()
}

type bsEvBase struct{ evBase }

func (bsEvBase) isBlockSyncEvent() {}

// EvBlockSyncRequest — Request{sender, request} (a peer asking us).
type EvBlockSyncRequest struct {
	bsEvBase
	Sender  types.NodeId
	Request blocksync.RequestMessage
}

// EvBlockSyncTimeout — Timeout(request) (outbound request timed out).
type EvBlockSyncTimeout struct {
	bsEvBase
	Request blocksync.RequestMessage
}

// EvBlockSyncSelfRequest — SelfRequest{requester, block_range}.
type EvBlockSyncSelfRequest struct {
	bsEvBase
	Requester  blocksync.SelfRequester
	BlockRange cstypes.BlockRange
}

// EvBlockSyncSelfCancelRequest — SelfCancelRequest{requester, block_range}.
type EvBlockSyncSelfCancelRequest struct {
	bsEvBase
	Requester  blocksync.SelfRequester
	BlockRange cstypes.BlockRange
}

// EvBlockSyncResponse — Response{sender, response}.
type EvBlockSyncResponse struct {
	bsEvBase
	Sender   types.NodeId
	Response blocksync.ResponseMessage
}

// EvBlockSyncSelfResponse — SelfResponse{response} (from own ledger).
type EvBlockSyncSelfResponse struct {
	bsEvBase
	Response blocksync.ResponseMessage
}

// ---------------------------------------------------------------------------
// ValidatorEvent — Rust ValidatorEvent::UpdateValidators.
// ---------------------------------------------------------------------------

type ValidatorEvent interface {
	MonadEvent
	isValidatorEvent()
}

type valEvBase struct{ evBase }

func (valEvBase) isValidatorEvent() {}

type EvUpdateValidators struct {
	valEvBase
	ValidatorSetDataWithEpoch ValidatorSetDataWithEpoch
}

// ---------------------------------------------------------------------------
// MempoolEvent — Rust MempoolEvent.
// ---------------------------------------------------------------------------

type MempoolEvent interface {
	MonadEvent
	isMempoolEvent()
}

type mpEvBase struct{ evBase }

func (mpEvBase) isMempoolEvent() {}

// EvMempoolProposal — Proposal{...}: the txpool's response to CreateProposal.
type EvMempoolProposal struct {
	mpEvBase
	Epoch          types.Epoch
	Round          types.Round
	SeqNum         types.SeqNum
	HighQC         cstypes.QuorumCertificate
	TimestampNs    types.U128
	RoundSignature cstypes.RoundSignature

	BaseFee       uint64
	BaseFeeTrend  uint64
	BaseFeeMoment uint64

	DelayedExecutionResults []exec.FinalizedHeader
	ProposedExecutionInputs ProposedExecutionInputs

	LastRoundTC              *cstypes.TimeoutCertificate
	FreshProposalCertificate *cstypes.FreshProposalCertificate
}

// ProposedExecutionInputs — Rust ProposedExecutionInputs { header, body }.
type ProposedExecutionInputs struct {
	Header exec.ProposedHeader
	Body   exec.Body
}

// EvMempoolForwardedTxs — ForwardedTxs{sender, txs}.
type EvMempoolForwardedTxs struct {
	mpEvBase
	Sender types.NodeId
	Txs    [][]byte
}

// EvMempoolForwardTxs — ForwardTxs(txs): forward to upcoming leaders.
type EvMempoolForwardTxs struct {
	mpEvBase
	Txs [][]byte
}

// ---------------------------------------------------------------------------
// StateSyncEvent — Rust StateSyncEvent.
// ---------------------------------------------------------------------------

type StateSyncEvent interface {
	MonadEvent
	isStateSyncEvent()
}

type ssEvBase struct{ evBase }

func (ssEvBase) isStateSyncEvent() {}

// EvStateSyncInbound — Inbound(from, network_message).
type EvStateSyncInbound struct {
	ssEvBase
	From    types.NodeId
	Message StateSyncNetworkMessage
}

// EvStateSyncOutbound — Outbound(to, network_message, completion).
type EvStateSyncOutbound struct {
	ssEvBase
	To      types.NodeId
	Message StateSyncNetworkMessage
	// Completion chan func() — completion signal sender (omitted in Go mock).
}

// EvStateSyncDoneSync — DoneSync(seq_num): execution finished syncing.
type EvStateSyncDoneSync struct {
	ssEvBase
	SeqNum types.SeqNum
}

// EvStateSyncBlockSync — BlockSync{block_range, full_blocks}.
type EvStateSyncBlockSync struct {
	ssEvBase
	BlockRange cstypes.BlockRange
	FullBlocks []cstypes.ConsensusFullBlock
}

// EvStateSyncRequestSync — RequestSync{root, high_qc}: consensus re-sync.
type EvStateSyncRequestSync struct {
	ssEvBase
	Root   cstypes.ConsensusBlockHeader
	HighQC cstypes.QuorumCertificate
}

// ---------------------------------------------------------------------------
// ControlPanelEvent — Rust ControlPanelEvent.
// ---------------------------------------------------------------------------

type ControlPanelEvent interface {
	MonadEvent
	isControlPanelEvent()
}

type cpEvBase struct{ evBase }

func (cpEvBase) isControlPanelEvent() {}

type EvGetMetrics struct{ cpEvBase }

type EvClearMetrics struct{ cpEvBase }

type EvUpdateLogFilter struct {
	cpEvBase
	Filter string
}

type EvGetPeers struct {
	cpEvBase
	Peers GetPeers
}

type EvGetFullNodes struct {
	cpEvBase
	FullNodes GetFullNodes
}

type EvReloadConfig struct {
	cpEvBase
	Request  bool // ReloadConfig::Request vs Response
	Response string
}

// ---------------------------------------------------------------------------
// ConfigEvent — Rust ConfigEvent.
// ---------------------------------------------------------------------------

type ConfigEvent interface {
	MonadEvent
	isConfigEvent()
}

type cfgEvBase struct{ evBase }

func (cfgEvBase) isConfigEvent() {}

// ConfigUpdate — Rust ConfigUpdate.
type ConfigUpdate struct {
	DedicatedFullNodes     []types.NodeId
	PrioritizedFullNodes   []types.NodeId
	BlocksyncOverridePeers []types.NodeId
}

// KnownPeersUpdate — Rust KnownPeersUpdate.
type KnownPeersUpdate struct {
	KnownPeers           []PeerEntry
	DedicatedFullNodes   []types.NodeId
	PrioritizedFullNodes []types.NodeId
}

type EvConfigUpdate struct {
	cfgEvBase
	Update ConfigUpdate
}

type EvKnownPeersUpdate struct {
	cfgEvBase
	Update KnownPeersUpdate
}

type EvConfigLoadError struct {
	cfgEvBase
	Err string
}

// ---------------------------------------------------------------------------
// Leaf events (not nested enums).
// ---------------------------------------------------------------------------

// EvTimestampUpdate — TimestampUpdateEvent(t): wall-clock feed to timestamper.
type EvTimestampUpdate struct {
	evBase
	Timestamp types.U128
}

// EvSecondaryRaptorcastPeersUpdate — SecondaryRaptorcastPeersUpdate{...}.
type EvSecondaryRaptorcastPeersUpdate struct {
	evBase
	ExpiryRound       types.Round
	ConfirmGroupPeers []types.NodeId
}
