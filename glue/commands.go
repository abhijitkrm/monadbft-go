package glue

import (
	"time"

	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Command — Rust Command enum: the single output type of MonadState::update.
// Sub-command families are expressed as narrower interfaces so SplitCommands
// can re-group a flat []Command into per-executor lists, mirroring Rust's
// Command::split_commands.
type Command interface{ isCommand() }

type cmdBase struct{}

func (cmdBase) isCommand() {}

// ---------------------------------------------------------------------------
// RouterCommand — Rust RouterCommand.
// ---------------------------------------------------------------------------

type RouterCommand interface {
	Command
	isRouterCommand()
}

type routerCmdBase struct{ cmdBase }

func (routerCmdBase) isRouterCommand() {}

// Publish — RouterCommand::Publish{target, message} (no priority).
type RouterPublish struct {
	routerCmdBase
	Target  types.RouterTarget
	Message *VerifiedMonadMessage
}

// RouterPublishWithPriority — PublishWithPriority.
type RouterPublishWithPriority struct {
	routerCmdBase
	Target   types.RouterTarget
	Message  *VerifiedMonadMessage
	Priority UdpPriority
}

// RouterPublishToFullNodes — PublishToFullNodes{epoch, round, broadcast_mode, message}.
type RouterPublishToFullNodes struct {
	routerCmdBase
	Epoch         types.Epoch
	Round         types.Round
	BroadcastMode types.FullnodeBroadcastMode
	Message       *VerifiedMonadMessage
}

// RouterAddEpochValidatorSet — AddEpochValidatorSet{epoch, epoch_start, validator_set}.
type RouterAddEpochValidatorSet struct {
	routerCmdBase
	Epoch        types.Epoch
	EpochStart   types.Round
	ValidatorSet []ValidatorStake
}

// ValidatorStake — (NodeId, Stake) pair.
type ValidatorStake struct {
	NodeId types.NodeId
	Stake  types.Stake
}

// RouterUpdateCurrentRound — UpdateCurrentRound(epoch, round).
type RouterUpdateCurrentRound struct {
	routerCmdBase
	Epoch types.Epoch
	Round types.Round
}

// RouterGetPeers / RouterUpdatePeers / RouterGetFullNodes / RouterUpdateFullNodes.
type RouterGetPeers struct{ routerCmdBase }

type RouterUpdatePeers struct {
	routerCmdBase
	PeerEntries          []PeerEntry
	DedicatedFullNodes   []types.NodeId
	PrioritizedFullNodes []types.NodeId
}

type RouterGetFullNodes struct{ routerCmdBase }

type RouterUpdateFullNodes struct {
	routerCmdBase
	DedicatedFullNodes   []types.NodeId
	PrioritizedFullNodes []types.NodeId
}

// ---------------------------------------------------------------------------
// TimerCommand — Rust TimerCommand.
// ---------------------------------------------------------------------------

type TimerCommand interface {
	Command
	isTimerCommand()
}

type timerCmdBase struct{ cmdBase }

func (timerCmdBase) isTimerCommand() {}

// TimerSchedule — Schedule{duration, variant, on_timeout}.
type TimerSchedule struct {
	timerCmdBase
	Duration  time.Duration
	Variant   TimeoutVariant
	OnTimeout MonadEvent
}

// TimerScheduleReset — ScheduleReset(variant).
type TimerScheduleReset struct {
	timerCmdBase
	Variant TimeoutVariant
}

// TimeoutVariant — Rust TimeoutVariant: Pacemaker | BlockSync(req) | SendVote.
type TimeoutVariant struct {
	Kind    TimeoutVariantKind
	Request blocksync.RequestMessage // BlockSync only
}

type TimeoutVariantKind uint8

const (
	TVPacemaker TimeoutVariantKind = iota + 1
	TVBlockSync
	TVSendVote
)

var TimeoutVariantPacemaker = TimeoutVariant{Kind: TVPacemaker}
var TimeoutVariantSendVote = TimeoutVariant{Kind: TVSendVote}

func TimeoutVariantBlockSync(r blocksync.RequestMessage) TimeoutVariant {
	return TimeoutVariant{Kind: TVBlockSync, Request: r}
}

// ---------------------------------------------------------------------------
// LedgerCommand — Rust LedgerCommand.
// ---------------------------------------------------------------------------

type LedgerCommand interface {
	Command
	isLedgerCommand()
}

type ledgerCmdBase struct{ cmdBase }

func (ledgerCmdBase) isLedgerCommand() {}

// LedgerCommit — LedgerCommit(OptimisticCommit).
type LedgerCommit struct {
	ledgerCmdBase
	Commit OptimisticCommit
}

// LedgerFetchHeaders — LedgerFetchHeaders(BlockRange).
type LedgerFetchHeaders struct {
	ledgerCmdBase
	Range cstypes.BlockRange
}

// LedgerFetchPayload — LedgerFetchPayload(body_id).
type LedgerFetchPayload struct {
	ledgerCmdBase
	BodyID cstypes.ConsensusBlockBodyId
}

// OptimisticCommit — Rust OptimisticCommit: Proposed|Voted|Finalized over a
// full block (the ledger's type-abstracted commit).
type OptimisticCommit struct {
	Kind        CommitKind
	Block       *cstypes.ConsensusFullBlock
	IsCanonical bool // Proposed only
}

type CommitKind uint8

const (
	CommitProposed CommitKind = iota + 1
	CommitVoted
	CommitFinalized
)

// ---------------------------------------------------------------------------
// ConfigFileCommand — Rust ConfigFileCommand.
// ---------------------------------------------------------------------------

type ConfigFileCommand interface {
	Command
	isConfigFileCommand()
}

type configFileCmdBase struct{ cmdBase }

func (configFileCmdBase) isConfigFileCommand() {}

type ConfigFileCheckpoint struct {
	configFileCmdBase
	RootSeqNum types.SeqNum
	Checkpoint cstypes.Checkpoint
}

type ConfigFileValidatorSetData struct {
	configFileCmdBase
	ValidatorSetData ValidatorSetDataWithEpoch
}

// ValidatorSetDataWithEpoch — Rust validator_data::ValidatorSetDataWithEpoch.
type ValidatorSetDataWithEpoch struct {
	Epoch      types.Epoch
	Validators ValidatorSetData
}

// ValidatorSetData — Rust ValidatorSetData: ordered (nodeid, stake, certpk).
type ValidatorSetData struct {
	Validators []ValidatorData
}

// ValidatorData — Rust ValidatorData { node_id, stake, cert_pubkey }.
type ValidatorData struct {
	NodeId     types.NodeId
	Stake      types.Stake
	CertPubKey [48]byte // BLS pubkey, compressed
}

func (v ValidatorSetData) GetStakes() []ValidatorStake {
	out := make([]ValidatorStake, len(v.Validators))
	for i, vd := range v.Validators {
		out[i] = ValidatorStake{NodeId: vd.NodeId, Stake: vd.Stake}
	}
	return out
}

// ---------------------------------------------------------------------------
// ValSetCommand — Rust ValSetCommand.
// ---------------------------------------------------------------------------

type ValSetCommand interface {
	Command
	isValSetCommand()
}

type valSetCmdBase struct{ cmdBase }

func (valSetCmdBase) isValSetCommand() {}

// ValSetNotifyFinalized — NotifyFinalized(seq_num).
type ValSetNotifyFinalized struct {
	valSetCmdBase
	SeqNum types.SeqNum
}

// ---------------------------------------------------------------------------
// TimestampCommand — Rust TimestampCommand.
// ---------------------------------------------------------------------------

type TimestampCommand interface {
	Command
	isTimestampCommand()
}

type timestampCmdBase struct{ cmdBase }

func (timestampCmdBase) isTimestampCommand() {}

// TimestampAdjustDelta — AdjustDelta(TimestampAdjustment).
type TimestampAdjustDelta struct {
	timestampCmdBase
	Adj cstypes.TimestampAdjustment
}

// ---------------------------------------------------------------------------
// TxPoolCommand — Rust TxPoolCommand.
// ---------------------------------------------------------------------------

type TxPoolCommand interface {
	Command
	isTxPoolCommand()
}

type txPoolCmdBase struct{ cmdBase }

func (txPoolCmdBase) isTxPoolCommand() {}

// TxPoolBlockCommit — BlockCommit(validated blocks).
type TxPoolBlockCommit struct {
	txPoolCmdBase
	Blocks []*cstypes.ConsensusFullBlock
}

// TxPoolCreateProposal — CreateProposal{...}.
type TxPoolCreateProposal struct {
	txPoolCmdBase
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

// TxPoolInsertForwardedTxs — InsertForwardedTxs{sender, txs}.
type TxPoolInsertForwardedTxs struct {
	txPoolCmdBase
	Sender types.NodeId
	Txs    [][]byte
}

// TxPoolEnterRound — EnterRound{epoch, round, upcoming_leader_rounds}.
type TxPoolEnterRound struct {
	txPoolCmdBase
	Epoch                types.Epoch
	Round                types.Round
	UpcomingLeaderRounds []types.Round
}

// TxPoolReset — Reset{last_delay_committed_blocks}.
type TxPoolReset struct {
	txPoolCmdBase
	LastDelayCommittedBlocks []*cstypes.ConsensusFullBlock
}

// ---------------------------------------------------------------------------
// ControlPanelCommand — Rust ControlPanelCommand.
// ---------------------------------------------------------------------------

type ControlPanelCommand interface {
	Command
	isControlPanelCommand()
}

type controlPanelCmdBase struct{ cmdBase }

func (controlPanelCmdBase) isControlPanelCommand() {}

type ControlPanelRead struct {
	controlPanelCmdBase
	Cmd ReadCommand
}

type ControlPanelWrite struct {
	controlPanelCmdBase
	Cmd WriteCommand
}

// ---------------------------------------------------------------------------
// LoopbackCommand — Rust LoopbackCommand::Forward(event).
// ---------------------------------------------------------------------------

type LoopbackCommand interface {
	Command
	isLoopbackCommand()
}

type loopbackCmdBase struct{ cmdBase }

func (loopbackCmdBase) isLoopbackCommand() {}

// LoopbackForward — Forward(event): feed a MonadEvent back into MonadState.
type LoopbackForward struct {
	loopbackCmdBase
	Event MonadEvent
}

// ---------------------------------------------------------------------------
// StateSyncCommand — Rust StateSyncCommand.
// ---------------------------------------------------------------------------

type StateSyncCommand interface {
	Command
	isStateSyncCommand()
}

type stateSyncCmdBase struct{ cmdBase }

func (stateSyncCmdBase) isStateSyncCommand() {}

// StateSyncRequestSync — RequestSync(finalized_header).
type StateSyncRequestSync struct {
	stateSyncCmdBase
	Header exec.FinalizedHeader
}

// StateSyncMessage — Message((to, network_message)).
type StateSyncMessage struct {
	stateSyncCmdBase
	To      types.NodeId
	Message StateSyncNetworkMessage
}

// StateSyncStartExecution — StartExecution.
type StateSyncStartExecution struct {
	stateSyncCmdBase
}

// StateSyncExpandUpstreamPeers — ExpandUpstreamPeers(peers).
type StateSyncExpandUpstreamPeers struct {
	stateSyncCmdBase
	Peers []types.NodeId
}

// ---------------------------------------------------------------------------
// ConfigReloadCommand — Rust ConfigReloadCommand::ReloadConfig.
// ---------------------------------------------------------------------------

type ConfigReloadCommand interface {
	Command
	isConfigReloadCommand()
}

type configReloadCmdBase struct{ cmdBase }

func (configReloadCmdBase) isConfigReloadCommand() {}

type ConfigReloadReload struct{ configReloadCmdBase }

// ---------------------------------------------------------------------------
// Control-panel read/write command payloads.
// ---------------------------------------------------------------------------

// ReadCommand — Rust ReadCommand (control panel).
type ReadCommand struct {
	Kind      ReadCommandKind
	GetPeers  *GetPeers
	FullNodes *GetFullNodes
}

type ReadCommandKind uint8

const (
	ReadGetMetrics ReadCommandKind = iota + 1
	ReadClearMetrics
	ReadGetPeers
	ReadGetFullNodes
)

// WriteCommand — Rust WriteCommand.
type WriteCommand struct {
	Kind            WriteCommandKind
	ClearMetrics    bool   // ClearMetrics::Request
	UpdateLogFilter string // UpdateLogFilter(filter)
	ReloadConfig    bool   // ReloadConfig::Request
}

type WriteCommandKind uint8

const (
	WriteClearMetrics WriteCommandKind = iota + 1
	WriteUpdateLogFilter
	WriteReloadConfig
)

// GetPeers / GetFullNodes — control-panel peer queries (request/response).
type GetPeers struct {
	Request  bool
	Response []PeerEntry
}

type GetFullNodes struct {
	Request  bool
	Response []types.NodeId
}

// PeerEntry — Rust PeerEntry (discovered peer record). Kept minimal: only the
// fields the swarm/config paths need are carried.
type PeerEntry struct {
	Pubkey       types.NodeId
	RecordSeqNum uint64
	AuthPort     uint16
}

// ---------------------------------------------------------------------------
// SplitCommands — Rust Command::split_commands.
// ---------------------------------------------------------------------------

// CommandGroups — the per-executor grouping produced by SplitCommands.
type CommandGroups struct {
	Router       []RouterCommand
	Timer        []TimerCommand
	Ledger       []LedgerCommand
	ConfigFile   []ConfigFileCommand
	ValSet       []ValSetCommand
	Timestamp    []TimestampCommand
	TxPool       []TxPoolCommand
	ControlPanel []ControlPanelCommand
	Loopback     []LoopbackCommand
	StateSync    []StateSyncCommand
	ConfigReload []ConfigReloadCommand
}

// SplitCommands — Rust Command::split_commands.
func SplitCommands(cmds []Command) CommandGroups {
	var g CommandGroups
	for _, c := range cmds {
		switch c := c.(type) {
		case RouterCommand:
			g.Router = append(g.Router, c)
		case TimerCommand:
			g.Timer = append(g.Timer, c)
		case LedgerCommand:
			g.Ledger = append(g.Ledger, c)
		case ConfigFileCommand:
			g.ConfigFile = append(g.ConfigFile, c)
		case ValSetCommand:
			g.ValSet = append(g.ValSet, c)
		case TimestampCommand:
			g.Timestamp = append(g.Timestamp, c)
		case TxPoolCommand:
			g.TxPool = append(g.TxPool, c)
		case ControlPanelCommand:
			g.ControlPanel = append(g.ControlPanel, c)
		case LoopbackCommand:
			g.Loopback = append(g.Loopback, c)
		case StateSyncCommand:
			g.StateSync = append(g.StateSync, c)
		case ConfigReloadCommand:
			g.ConfigReload = append(g.ConfigReload, c)
		}
	}
	return g
}
