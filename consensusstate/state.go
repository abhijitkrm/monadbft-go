package consensusstate

import (
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/consensus"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// Bounds and lookahead constants — Rust lib.rs.
const (
	// futureVoteBound — bound on future rounds/NEs we buffer.
	futureVoteBound types.Round = 10

	numLeadersForwardTxs   = 3
	numLeadersSelfUpcoming = 3
)

// Config — Rust ConsensusConfig.
type Config struct {
	ExecutionDelay types.SeqNum
	// Delta approximates the upper bound of message delivery during a
	// broadcast; drives timeout lengths.
	Delta       time.Duration
	ChainConfig chaincfg.Config
	// If the node lags more than this many blocks behind, trigger statesync.
	LiveToStatesyncThreshold types.SeqNum
	// In statesync mode, go live within this many blocks of root. Must be <
	// LiveToStatesyncThreshold.
	StatesyncToLiveThreshold types.SeqNum
	// Start execution if a high_qc is within this threshold of root.
	StartExecutionThreshold types.SeqNum

	TimestampLatencyEstimateNs types.U128
}

// blockSyncRequestStatus — Rust BlockSyncRequestStatus.
type blockSyncRequestStatus struct {
	blockRange cstypes.BlockRange
	// once a block with round >= cancel_round is committed, the request is
	// canceled
	cancelRound types.Round
}

// OutgoingVoteStatusKind — Rust OutgoingVoteStatus.
type OutgoingVoteStatusKind uint8

const (
	VoteTimerFired OutgoingVoteStatusKind = iota
	VoteReady
)

// OutgoingVoteStatus — Rust OutgoingVoteStatus.
type OutgoingVoteStatus struct {
	Kind OutgoingVoteStatusKind
	Vote cstypes.Vote // valid iff Kind == VoteReady
}

// ConsensusState — Rust ConsensusState: the core consensus algorithm state.
// Pure state only — the environment deps live on State (the Wrapper).
type ConsensusState struct {
	// prospective blocks waiting to be committed
	PendingBlockTree *blocktree.BlockTree
	// votes collected for proposals
	VoteState *consensus.VoteState
	// no-endorsements collected for proposals
	NoEndorsementState *consensus.NoEndorsementState
	// outgoing prepared votes to send to next leader
	ScheduledVote *OutgoingVoteStatus

	Safety *consensus.Safety

	// tracks and updates the current round
	Pacemaker *consensus.Pacemaker

	BlockSyncRequests map[types.BlockId]blockSyncRequestStatus

	// last canonical coherent tip emitted
	CanonicalProposedTip *types.BlockId
	VoteDelayTimerStart  *VoteDelayTimerStart
	voteDelayMetrics     voteDelayMetricsWindow
}

// NewConsensusState — Rust ConsensusState::new.
func NewConsensusState(
	epochManager *validator.EpochManager,
	config *Config,
	root blocktree.RootInfo,
	highCertificate cstypes.RoundCertificate,
) *ConsensusState {
	pacemaker := consensus.NewPacemaker(
		config.Delta,
		config.ChainConfig,
		config.Delta, // TODO upstream: change to a different value later
		epochManager,
		highCertificate,
	)
	return &ConsensusState{
		PendingBlockTree:   blocktree.New(root),
		VoteState:          consensus.NewVoteState(pacemaker.GetCurrentRound()),
		NoEndorsementState: consensus.NewNoEndorsementState(pacemaker.GetCurrentRound()),
		Pacemaker:          pacemaker,
		Safety:             consensus.NewSafety(&highCertificate, nil),
		BlockSyncRequests:  make(map[types.BlockId]blockSyncRequestStatus),
	}
}

func (c *ConsensusState) RefreshVoteDelayMetrics(nowNs types.U128, m *metrics.Metrics) {
	c.voteDelayMetrics.refresh(nsToMs(nowNs), m)
}

func (c *ConsensusState) GetCurrentEpoch() types.Epoch { return c.Pacemaker.GetCurrentEpoch() }
func (c *ConsensusState) GetCurrentRound() types.Round { return c.Pacemaker.GetCurrentRound() }
func (c *ConsensusState) GetHighCertificate() *cstypes.RoundCertificate {
	return c.Pacemaker.HighCertificate()
}

// RequestBlocksIfMissingAncestor — Rust request_blocks_if_missing_ancestor:
// blocksync the gap between the blocktree root and the high_qc's block.
func (c *ConsensusState) RequestBlocksIfMissingAncestor() []Command {
	highQc := c.Pacemaker.HighCertificate().GetQC()
	blockRange := c.PendingBlockTree.MaybeFillPathToRoot(&highQc)
	if blockRange == nil {
		return nil
	}
	if blockRange.NumBlocks == 0 {
		panic("consensusstate: empty block range")
	}
	if _, exists := c.BlockSyncRequests[blockRange.LastBlockId]; exists {
		return nil
	}
	c.BlockSyncRequests[blockRange.LastBlockId] = blockSyncRequestStatus{
		blockRange: *blockRange,
		// the round of last_block_id would be more precise, but it doesn't
		// matter — only used for garbage collection
		cancelRound: highQc.GetRound(),
	}
	return []Command{CmdRequestSync{Range: *blockRange}}
}

// requestTipIfMissing — Rust request_tip_if_missing: when the high
// certificate is a TC carrying a Tip we don't have, blocksync just that tip.
func (c *ConsensusState) requestTipIfMissing() []Command {
	highCert := c.Pacemaker.HighCertificate()
	if highCert.IsQC || !highCert.TC.HighExtend.IsTip {
		return nil
	}
	tip := highCert.TC.HighExtend.Tip
	tipId := tip.BlockHeader.GetId()
	if c.PendingBlockTree.GetBlock(tipId) != nil {
		return nil
	}
	if _, exists := c.BlockSyncRequests[tipId]; exists {
		return nil
	}
	blockRange := cstypes.BlockRange{LastBlockId: tipId, NumBlocks: 1}
	c.BlockSyncRequests[tipId] = blockSyncRequestStatus{
		blockRange:  blockRange,
		cancelRound: tip.BlockHeader.BlockRound,
	}
	return []Command{CmdRequestSync{Range: blockRange}}
}

// State — Rust ConsensusStateWrapper: the consensus state machine bound to
// its environment (validators, election, block policy, keys, clock).
type State struct {
	Consensus *ConsensusState

	Metrics      *metrics.Metrics
	EpochManager *validator.EpochManager
	// policy for validating chain extension — mutable because the consensus
	// tip is updated
	BlockPolicy blocktree.BlockPolicy
	StateRead   blocktree.ExecutionStateRead

	ValEpochMap *validator.ValidatorsEpochMapping
	Election    validator.LeaderElection
	Version     uint32

	// policy for validating incoming proposals
	BlockValidator blocktree.BlockValidator
	// local timestamp + proposal timestamp validation
	BlockTimestamp *BlockTimestamp

	// destination address for proposal payments
	Beneficiary [20]byte
	// this node's public NodeId as seen in the validator set
	NodeId types.NodeId
	// consensus algorithm parameters
	Config *Config

	Keypair     *crypto.SecpKeyPair
	CertKeypair *crypto.BlsKeyPair
}

// HandleTimeoutExpiry — Rust handle_timeout_expiry: the local round timer
// fired.
func (s *State) HandleTimeoutExpiry(timeoutRound types.Round) []Command {
	var cmds []Command
	if timeoutRound < s.Consensus.Pacemaker.GetCurrentRound() {
		return cmds
	}
	s.Metrics.ConsensusEvents.LocalTimeout.Inc()
	timeoutRound = s.Consensus.Pacemaker.GetCurrentRound()
	for _, pc := range s.Consensus.Pacemaker.ProcessLocalTimeout(s.Consensus.Safety) {
		cmds = append(cmds, FromPacemakerCommand(s.Keypair, s.CertKeypair, s.Version, pc)...)
	}
	return cmds
}

// HasHandledProposal — Rust has_handled_proposal.
func (s *State) HasHandledProposal(round types.Round) bool {
	return !s.Consensus.Safety.IsSafeToHandleProposal(round)
}

// HandleProposalMessage — Rust handle_proposal_message. Proposals can
// include NULL blocks (0 transactions); NULL blocks skip payload validation.
func (s *State) HandleProposalMessage(
	author types.NodeId,
	p messages.ProposalMessage,
) []Command {
	s.Metrics.ConsensusEvents.HandleProposal.Inc()
	var cmds []Command

	if p.ProposalRound <= s.Consensus.PendingBlockTree.Root().Round {
		// old proposal, dropping
		return cmds
	}

	epoch, ok := s.EpochManager.GetEpoch(p.ProposalRound)
	if !ok {
		panic("consensusstate: epoch verified")
	}
	validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
	if !ok {
		panic("consensusstate: proposal message was verified")
	}

	// a valid proposal will advance the pacemaker round so process the
	// certificates first
	cmds = append(cmds, s.ProcessQC(&p.Tip.BlockHeader.QC)...)

	if p.LastRoundTC != nil {
		s.Metrics.ConsensusEvents.ProposalWithTC.Inc()
		cmds = append(cmds, s.ProcessTC(p.LastRoundTC)...)
	}

	// author, leader, round checks
	pacemakerRound := s.Consensus.Pacemaker.GetCurrentRound()
	proposalRound := p.ProposalRound
	expectedLeader := s.Election.GetLeader(proposalRound, validatorSet)
	if proposalRound > pacemakerRound || author != expectedLeader {
		s.Metrics.ConsensusEvents.InvalidProposalRoundLeader.Inc()
		return cmds
	}

	// TODO emit evidence if this is a *different* block for the same round
	if !s.Consensus.Safety.IsSafeToHandleProposal(proposalRound) {
		// dropping proposal, already received for this round
		return cmds
	}
	s.Consensus.Safety.HandleProposal(proposalRound)

	block := s.validateBlock(p.Tip.BlockHeader, p.BlockBody)
	if block == nil {
		return cmds
	}

	// at this point the block is valid and can be added to the blocktree
	cmds = append(cmds, s.tryAddAndCommitBlocktree(
		block, &pendingVote{
			proposalRound: p.ProposalRound,
			lastRoundTC:   p.LastRoundTC,
			tip:           p.Tip,
		})...)

	// out-of-order proposals are possible if some round R+1 proposal arrives
	// before R because of network conditions — still valid
	if proposalRound != pacemakerRound {
		s.Metrics.ConsensusEvents.OutOfOrderProposals.Inc()
	}

	return cmds
}

// validateBlock — Rust validate_block.
func (s *State) validateBlock(
	header cstypes.ConsensusBlockHeader,
	body cstypes.ConsensusBlockBody,
) *cstypes.ConsensusFullBlock {
	if validated := s.Consensus.PendingBlockTree.GetBlock(header.GetId()); validated != nil {
		// fast-path if we've already validated this block — can hit on
		// reproposal
		if validated.Body.GetId() != body.GetId() {
			// TODO: this is malicious behaviour?
			return nil
		}
		return validated
	}

	blockRound := header.BlockRound
	blockAuthor := header.Author

	epoch, ok := s.EpochManager.GetEpoch(blockRound)
	if !ok {
		panic("consensusstate: epoch verified")
	}
	validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
	if !ok {
		panic("consensusstate: proposal message was verified")
	}
	if blockAuthor != s.Election.GetLeader(blockRound, validatorSet) {
		return nil
	}

	mapping, ok := s.ValEpochMap.GetCertPubkeys(header.Epoch)
	if !ok {
		panic("consensusstate: proposal message was verified")
	}
	if !mapping.Has(blockAuthor) {
		panic("consensusstate: proposal author exists in validator_mapping")
	}
	authorPubkey := mapping.PubKey(blockAuthor)

	block, err := s.BlockValidator.Validate(header, body, &authorPubkey, s.Config.ChainConfig, s.Metrics)
	if err != nil {
		// dropping proposal, block validation failed
		return nil
	}
	return block
}

// HandleVoteMessage — Rust handle_vote_message: collect votes, form QC on
// supermajority.
func (s *State) HandleVoteMessage(
	author types.NodeId,
	voteMsg messages.VoteMessage,
) []Command {
	voteRound := voteMsg.Vote.Round
	current := s.Consensus.Pacemaker.GetCurrentRound()
	if voteRound < current {
		s.Metrics.ConsensusEvents.OldVoteReceived.Inc()
		return nil
	}
	if voteRound > current+futureVoteBound {
		s.Metrics.ConsensusEvents.FutureVoteReceived.Inc()
		return nil
	}
	s.Metrics.ConsensusEvents.VoteReceived.Inc()

	var cmds []Command
	epoch, ok := s.EpochManager.GetEpoch(voteRound)
	if !ok {
		panic("consensusstate: epoch verified")
	}
	validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
	if !ok {
		panic("consensusstate: vote message was verified")
	}
	validatorMapping, ok := s.ValEpochMap.GetCertPubkeys(epoch)
	if !ok {
		panic("consensusstate: vote message was verified")
	}
	maybeQc := s.Consensus.VoteState.ProcessVote(author, &voteMsg, validatorSet, validatorMapping)

	if maybeQc != nil {
		s.Metrics.ConsensusEvents.CreatedQC.Inc()
		cmds = append(cmds, s.ProcessQC(maybeQc)...)
		// this try_propose is superfluous — process_qc calls it internally
		cmds = append(cmds, s.tryPropose()...)

		voteRoundLeader := s.Election.GetLeader(voteRound, validatorSet)
		if s.NodeId == voteRoundLeader {
			// If we're also the leader of vote_round+1, we'll send QC(r) in
			// both AdvanceRound(QC(r)) and Proposal(r+1) — fine, AdvanceRound
			// propagates faster via direct broadcast.
			// Note: broadcasts to the (qc.round + 1) validator set.
			msg := messages.ConsensusMessage{
				Version: s.Version,
				Message: messages.ProtocolMessage{
					Kind: messages.PMAdvanceRound,
					AdvanceRound: &messages.AdvanceRoundMessage{
						LastRoundCertificate: *cstypes.RoundCertFromQC(*maybeQc),
					},
				},
			}
			cmds = append(cmds, CmdPublish{
				Target:  types.BroadcastTarget(s.Consensus.GetCurrentEpoch()),
				Message: messages.Sign(msg, s.Keypair),
			})
		}
	}
	return cmds
}

// HandleTimeoutMessage — Rust handle_timeout_message: remote timeout msgs.
func (s *State) HandleTimeoutMessage(
	author types.NodeId,
	timeoutMessage messages.TimeoutMessage,
) []Command {
	var cmds []Command
	timeout := &timeoutMessage.Timeout
	if timeout.TmInfo.Round < s.Consensus.Pacemaker.GetCurrentRound() {
		s.Metrics.ConsensusEvents.OldRemoteTimeout.Inc()
		return cmds
	}
	// Note: last_round_certificate may have been set to None by
	// TimeoutMessage::validate if timeout.round == current_round
	s.Metrics.ConsensusEvents.RemoteTimeoutMsg.Inc()

	epoch, ok := s.EpochManager.GetEpoch(timeout.TmInfo.Round)
	if !ok {
		panic("consensusstate: epoch verified")
	}
	validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
	if !ok {
		panic("consensusstate: timeout message was verified")
	}
	validatorMapping, ok := s.ValEpochMap.GetCertPubkeys(epoch)
	if !ok {
		panic("consensusstate: timeout message was verified")
	}

	heQc := timeout.HighExtend.GetQC()
	cmds = append(cmds, s.ProcessQC(&heQc)...)

	if timeout.HighExtend.IsTip && timeout.HighExtend.VoteSig != nil {
		tip := timeout.HighExtend.Tip
		cmds = append(cmds, s.HandleVoteMessage(author, messages.VoteMessage{
			Vote: cstypes.Vote{
				ID:    tip.BlockHeader.GetId(),
				Epoch: timeout.TmInfo.Epoch,
				Round: timeout.TmInfo.Round,
			},
			Sig: *timeout.HighExtend.VoteSig,
		})...)
	}

	currentRound := s.Consensus.Pacemaker.GetCurrentRound()
	switch lrc := timeout.LastRoundCertificate; {
	case lrc != nil && !lrc.IsQC && lrc.TC.Round == currentRound:
		s.Metrics.ConsensusEvents.RemoteTimeoutMsgWithTC.Inc()
		// broadcast Timeout message immediately if received TC to advance
		// round — helps other validators form their own TC
		cmds = append(cmds, s.HandleTimeoutExpiry(lrc.TC.Round)...)
		cmds = append(cmds, s.ProcessTC(lrc.TC)...)
	case lrc != nil && !lrc.IsQC && lrc.TC.Round > currentRound:
		s.Metrics.ConsensusEvents.RemoteTimeoutMsgWithFutureTC.Inc()
		// broadcast AdvanceRound message with the TC for the skipped round —
		// helps other validators advance their rounds. (Can't broadcast a
		// Timeout message: no round certificate for the skipped round.)
		cmds = append(cmds, s.BroadcastAdvanceRoundMessage(*lrc)...)
		cmds = append(cmds, s.ProcessTC(lrc.TC)...)
	case lrc != nil && !lrc.IsQC:
		// ignore TC from past rounds
	case lrc != nil && lrc.IsQC:
		cmds = append(cmds, s.ProcessQC(lrc.QC)...)
	default:
		// don't do anything — last_round_certificate may have been cleared
		// to nil by validate when timeout.round == current_round
	}

	for _, pc := range s.Consensus.Pacemaker.ProcessRemoteTimeout(
		s.EpochManager, validatorSet, validatorMapping,
		s.Consensus.Safety, author, timeoutMessage,
	) {
		cmds = append(cmds, FromPacemakerCommand(s.Keypair, s.CertKeypair, s.Version, pc)...)
	}

	// necessary: process_remote_timeout may internally construct a TC
	cmds = append(cmds, s.tryPropose()...)
	return cmds
}

// BroadcastAdvanceRoundMessage — Rust broadcast_advance_round_message.
func (s *State) BroadcastAdvanceRoundMessage(
	lastRoundCertificate cstypes.RoundCertificate,
) []Command {
	certRound := lastRoundCertificate.Round()
	epoch, ok := s.EpochManager.GetEpoch(certRound)
	if !ok {
		// cannot broadcast advance round message, epoch not found
		return nil
	}
	msg := messages.ConsensusMessage{
		Version: s.Version,
		Message: messages.ProtocolMessage{
			Kind: messages.PMAdvanceRound,
			AdvanceRound: &messages.AdvanceRoundMessage{
				LastRoundCertificate: lastRoundCertificate,
			},
		},
	}
	return []Command{CmdPublish{
		Target:  types.BroadcastTarget(epoch),
		Message: messages.Sign(msg, s.Keypair),
	}}
}

// HandleRoundRecoveryMessage — Rust handle_round_recovery_message: a leader
// missing its tip asks validators to endorse recovery (NoEndorsement).
func (s *State) HandleRoundRecoveryMessage(
	author types.NodeId,
	roundRecovery messages.RoundRecoveryMessage,
) []Command {
	s.Metrics.ConsensusEvents.HandleRoundRecovery.Inc()
	var cmds []Command

	epoch, ok := s.EpochManager.GetEpoch(roundRecovery.Round)
	if !ok {
		panic("consensusstate: epoch verified")
	}
	validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
	if !ok {
		panic("consensusstate: round recovery message was verified")
	}

	// a valid proposal would advance the pacemaker round — handle the
	// certificate first
	cmds = append(cmds, s.ProcessTC(&roundRecovery.TC)...)

	// author, leader, round checks
	pacemakerRound := s.Consensus.Pacemaker.GetCurrentRound()
	round := roundRecovery.Round
	expectedLeader := s.Election.GetLeader(pacemakerRound, validatorSet)
	if round != pacemakerRound || author != expectedLeader {
		s.Metrics.ConsensusEvents.InvalidRoundRecoveryLeader.Inc()
		return cmds
	}

	if !roundRecovery.TC.HighExtend.IsTip {
		// invariant broken: round_recovery.tc.high_extend is not a tip
		return cmds
	}
	tip := roundRecovery.TC.HighExtend.Tip

	if s.Consensus.PendingBlockTree.IsCoherent(tip.BlockHeader.GetId()) &&
		tip.BlockHeader.TimestampNs.Cmp(s.BlockTimestamp.GetCurrentTime()) < 0 {
		// ignoring round recovery for coherent tip
		return cmds
	}

	if s.Consensus.Safety.IsSafeToNoEndorse(roundRecovery.Round) {
		s.Consensus.Safety.NoEndorse(roundRecovery.Round, tip.BlockHeader.GetId())
		ne := messages.NewNoEndorsementMessage(cstypes.NoEndorsement{
			Epoch:      epoch,
			Round:      round,
			TipQcRound: tip.BlockHeader.QC.GetRound(),
		}, s.CertKeypair)
		msg := messages.ConsensusMessage{
			Version: s.Version,
			Message: messages.ProtocolMessage{
				Kind:          messages.PMNoEndorsement,
				NoEndorsement: &ne,
			},
		}
		cmds = append(cmds, CmdPublish{
			Target:  types.PointToPointTarget(author),
			Message: messages.Sign(msg, s.Keypair),
		})
	}
	return cmds
}

// HandleNoEndorsementMessage — Rust handle_no_endorsement_message.
func (s *State) HandleNoEndorsementMessage(
	author types.NodeId,
	noEndorsementMsg messages.NoEndorsementMessage,
) []Command {
	current := s.Consensus.Pacemaker.GetCurrentRound()
	if noEndorsementMsg.Msg.Round < current {
		s.Metrics.ConsensusEvents.OldNoEndorsementReceived.Inc()
		return nil
	}
	if noEndorsementMsg.Msg.Round > current {
		s.Metrics.ConsensusEvents.FutureNoEndorsementReceived.Inc()
		return nil
	}
	s.Metrics.ConsensusEvents.HandleNoEndorsement.Inc()

	var cmds []Command
	epoch, ok := s.EpochManager.GetEpoch(noEndorsementMsg.Msg.Round)
	if !ok {
		panic("consensusstate: epoch verified")
	}
	validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
	if !ok {
		panic("consensusstate: no_endorsement message was verified")
	}
	validatorMapping, ok := s.ValEpochMap.GetCertPubkeys(epoch)
	if !ok {
		panic("consensusstate: no_endorsement message was verified")
	}
	maybeNec := s.Consensus.NoEndorsementState.ProcessNoEndorsement(
		author, &noEndorsementMsg, validatorSet, validatorMapping)

	if maybeNec != nil {
		s.Metrics.ConsensusEvents.CreatedNEC.Inc()
		cmds = append(cmds, s.tryPropose()...)
	}
	return cmds
}

// HandleAdvanceRoundMessage — Rust handle_advance_round_message.
func (s *State) HandleAdvanceRoundMessage(
	author types.NodeId,
	advanceRoundMsg messages.AdvanceRoundMessage,
) []Command {
	s.Metrics.ConsensusEvents.HandleAdvanceRound.Inc()
	var cmds []Command

	cert := advanceRoundMsg.LastRoundCertificate
	if !cert.IsQC {
		cmds = append(cmds, s.ProcessTC(cert.TC)...)
		return cmds
	}
	qc := cert.QC
	// duplicated from process_qc: we also forward the AdvanceRound to the
	// next leader — this deduplicates forwarding within a round
	if qc.Info.Round < s.Consensus.Pacemaker.GetCurrentRound() {
		s.Metrics.ConsensusEvents.ProcessOldQC.Inc()
		return cmds
	}
	cmds = append(cmds, s.ProcessQC(qc)...)

	currentRound := s.Consensus.Pacemaker.GetCurrentRound()
	// TODO this grouping should be enforced by epoch_manager/val_epoch_map
	epoch, ok := s.EpochManager.GetEpoch(currentRound)
	if !ok {
		panic("consensusstate: looked up leader for invalid round")
	}
	validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
	if !ok {
		panic("consensusstate: looked up leader for invalid round")
	}
	leader := s.Election.GetLeader(currentRound, validatorSet)
	msg := messages.ConsensusMessage{
		Version: s.Version,
		Message: messages.ProtocolMessage{
			Kind: messages.PMAdvanceRound,
			AdvanceRound: &messages.AdvanceRoundMessage{
				LastRoundCertificate: *cstypes.RoundCertFromQC(*qc),
			},
		},
	}
	cmds = append(cmds, CmdPublish{
		Target:  types.PointToPointTarget(leader),
		Message: messages.Sign(msg, s.Keypair),
	})
	return cmds
}

// HandleBlockSync — Rust handle_block_sync.
//
// Invariant: must only be passed blocks that were previously requested.
// A requested block can fail to be added if the original proposal arrived
// first, or the request is no longer relevant after a prune.
func (s *State) HandleBlockSync(
	blockRange cstypes.BlockRange,
	fullBlocks []*cstypes.ConsensusFullBlock,
) []Command {
	var cmds []Command
	if _, ok := s.Consensus.BlockSyncRequests[blockRange.LastBlockId]; !ok {
		// can happen if the corresponding proposal was received before the
		// blocksync response
		return cmds
	}
	for _, fullBlock := range fullBlocks {
		header := fullBlock.Header
		body := fullBlock.Body
		if !s.Consensus.PendingBlockTree.IsValidToInsert(&header) {
			continue
		}
		block := s.validateBlock(header, body)
		if block == nil {
			// blocksynced block failed to validate — invalid tip?
			break
		}
		cmds = append(cmds, s.tryAddAndCommitBlocktree(block, nil)...)
	}
	delete(s.Consensus.BlockSyncRequests, blockRange.LastBlockId)
	return cmds
}

// HandleVoteTimer — Rust handle_vote_timer: the vote-pace timer fired.
func (s *State) HandleVoteTimer(voteTimerRound types.Round) []Command {
	sv := s.Consensus.ScheduledVote
	if sv == nil || sv.Kind != VoteReady {
		s.Consensus.ScheduledVote = &OutgoingVoteStatus{Kind: VoteTimerFired}
		return nil
	}
	return s.sendVoteAndResetTimer(sv.Vote)
}

func (s *State) maybeRecordVoteDelayMetrics(proposalRound, parentBlockRound types.Round) {
	timerStart := s.Consensus.VoteDelayTimerStart
	if timerStart == nil {
		return
	}
	if timerStart.Round != proposalRound || parentBlockRound+1 != proposalRound {
		return
	}
	nowMs := nsToMs(s.BlockTimestamp.GetCurrentTime())
	s.Consensus.voteDelayMetrics.recordReadyAfterTimerStart(
		nowMs, nowMs-minU64(nowMs, timerStart.StartedAtMs), s.Metrics)
}

// sendVoteAndResetTimer — Rust send_vote_and_reset_timer: sign the vote and
// publish it to the next (and current, if different) round leader.
func (s *State) sendVoteAndResetTimer(vote cstypes.Vote) []Command {
	round := vote.Round
	var cmds []Command
	voteMsg := messages.NewVoteMessage(vote, s.CertKeypair)
	msg := messages.Sign(messages.ConsensusMessage{
		Version: s.Version,
		Message: messages.ProtocolMessage{Kind: messages.PMVote, Vote: &voteMsg},
	}, s.Keypair)
	s.Metrics.ConsensusEvents.CreatedVote.Inc()

	getLeader := func(r types.Round) types.NodeId {
		epoch, ok := s.EpochManager.GetEpoch(r)
		if !ok {
			panic("consensusstate: looked up leader for invalid round")
		}
		validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
		if !ok {
			panic("consensusstate: looked up leader for invalid round")
		}
		return s.Election.GetLeader(r, validatorSet)
	}
	// leader for next round must be known
	nextLeader := getLeader(round + 1)
	cmds = append(cmds, CmdPublish{
		Target:  types.PointToPointTarget(nextLeader),
		Message: msg,
	})
	// leader for current round must be known
	currentLeader := getLeader(round)
	if currentLeader != nextLeader {
		cmds = append(cmds, CmdPublish{
			Target:  types.PointToPointTarget(currentLeader),
			Message: msg,
		})
	}

	// start the vote-timer for the next round
	nextRound := round + 1
	votePace := s.Config.ChainConfig.GetChainRevision(nextRound).ChainParams().VotePace
	cmds = append(cmds, CmdScheduleVote{Duration: votePace, Round: nextRound})
	s.Consensus.VoteDelayTimerStart = &VoteDelayTimerStart{
		Round:       nextRound,
		StartedAtMs: nsToMs(s.BlockTimestamp.GetCurrentTime()),
	}
	s.Consensus.ScheduledVote = nil
	return cmds
}

// ProcessQC — Rust process_qc: commit parent via the QC's commit hash if
// committable, update high_qc, advance the pacemaker.
func (s *State) ProcessQC(qc *cstypes.QuorumCertificate) []Command {
	if qc.Info.Round < s.Consensus.Pacemaker.GetCurrentRound() {
		s.Metrics.ConsensusEvents.ProcessOldQC.Inc()
		return nil
	}
	s.Metrics.ConsensusEvents.ProcessQC.Inc()

	var cmds []Command

	// emit Voted commit for the highest coherent block on the path to the
	// QC block
	if voted := s.Consensus.PendingBlockTree.GetHighestCoherentBlockOnPathFromRoot(qc.GetBlockId()); voted != nil {
		cmds = append(cmds, CmdCommitBlocks{Commit: OptimisticPolicyCommit{
			Kind:  CommitVoted,
			Block: voted,
		}})
	}

	cmds = append(cmds, s.tryCommit(qc)...)

	// cancel obsolete blocksync requests
	var toCancel []types.BlockId
	for blockId, status := range s.Consensus.BlockSyncRequests {
		if status.cancelRound <= s.Consensus.PendingBlockTree.Root().Round {
			toCancel = append(toCancel, blockId)
		}
	}
	for _, blockId := range toCancel {
		canceled := s.Consensus.BlockSyncRequests[blockId]
		delete(s.Consensus.BlockSyncRequests, blockId)
		cmds = append(cmds, CmdCancelSync{Range: canceled.blockRange})
	}

	// statesync if too far from tip
	cmds = append(cmds, s.maybeStatesync()...)

	for _, pc := range s.Consensus.Pacemaker.ProcessCertificate(
		s.EpochManager, s.Consensus.Safety,
		*cstypes.RoundCertFromQC(*qc),
	) {
		cmds = append(cmds, FromPacemakerCommand(s.Keypair, s.CertKeypair, s.Version, pc)...)
	}

	cmds = append(cmds, s.updateProposedHead()...)

	// retrieve missing blocks if processed QC is highest and points at an
	// unknown block
	cmds = append(cmds, s.Consensus.RequestBlocksIfMissingAncestor()...)

	// update vote_state round — ok if not leader; we never propose then
	round := s.Consensus.Pacemaker.GetCurrentRound()
	s.Consensus.VoteState.StartNewRound(round)
	s.Consensus.NoEndorsementState.StartNewRound(round)

	_ = s.lookupLeader(round)

	cmds = append(cmds, s.tryPropose()...)
	return cmds
}

// ProcessTC — Rust process_tc.
func (s *State) ProcessTC(tc *cstypes.TimeoutCertificate) []Command {
	if tc.Round < s.Consensus.Pacemaker.GetCurrentRound() {
		s.Metrics.ConsensusEvents.ProcessOldTC.Inc()
		return nil
	}
	s.Metrics.ConsensusEvents.ProcessTC.Inc()

	var cmds []Command
	for _, pc := range s.Consensus.Pacemaker.ProcessCertificate(
		s.EpochManager, s.Consensus.Safety,
		*cstypes.RoundCertFromTC(*tc),
	) {
		cmds = append(cmds, FromPacemakerCommand(s.Keypair, s.CertKeypair, s.Version, pc)...)
	}

	round := s.Consensus.Pacemaker.GetCurrentRound()
	_ = s.lookupLeader(round)

	cmds = append(cmds, s.tryPropose()...)
	return cmds
}

// Checkpoint — Rust checkpoint: a serializable recovery point.
func (s *State) Checkpoint() cstypes.Checkpoint {
	getLockedEpoch := func(epoch types.Epoch) *cstypes.LockedEpoch {
		// return early if validator set isn't locked
		if _, ok := s.ValEpochMap.GetValSet(epoch); !ok {
			return nil
		}
		// return early if next epoch isn't scheduled
		round, ok := s.EpochManager.GetEpochStart(epoch)
		if !ok {
			return nil
		}
		// epoch is scheduled and validator set is ready
		return &cstypes.LockedEpoch{Epoch: epoch, Round: round}
	}

	baseEpoch := s.Consensus.PendingBlockTree.Root().Epoch
	var locked []cstypes.LockedEpoch
	if le := getLockedEpoch(baseEpoch); le != nil {
		locked = append(locked, *le)
	} else {
		panic("consensusstate: checkpoint: no validator set populated for base_epoch")
	}
	if le := getLockedEpoch(baseEpoch + 1); le != nil {
		locked = append(locked, *le)
	}
	return cstypes.Checkpoint{
		Root:            s.Consensus.PendingBlockTree.Root().BlockId,
		HighCertificate: *s.Consensus.Pacemaker.HighCertificate(),
		ValidatorSets:   locked,
	}
}

// tryCommit — Rust try_commit: committing the boundary block can schedule
// the next epoch and bump the pacemaker epoch.
func (s *State) tryCommit(qc *cstypes.QuorumCertificate) []Command {
	var cmds []Command
	qcParent := s.Consensus.PendingBlockTree.GetBlock(qc.GetBlockId())
	if qcParent == nil {
		// the block the qc points to doesn't exist, or parent block is root
		return cmds
	}
	committableId := qc.GetCommittableId(qcParent)
	if committableId == nil {
		// qc is not committable (not consecutive rounds)
		return cmds
	}
	if !s.Consensus.PendingBlockTree.IsCoherent(*committableId) {
		// committable block not (yet) coherent — execution likely lagging
		return cmds
	}

	for _, block := range s.Consensus.PendingBlockTree.Prune(*committableId) {
		// when the epoch boundary block commits, epoch manager records update
		s.Metrics.ConsensusEvents.CommitBlock.Inc()
		s.BlockPolicy.UpdateCommittedBlock(block)
		s.EpochManager.ScheduleEpochStart(block.Header.SeqNum, block.GetBlockRound())
		cmds = append(cmds, CmdCommitBlocks{Commit: OptimisticPolicyCommit{
			Kind:  CommitFinalized,
			Block: block,
		}})
	}
	return cmds
}

// pendingVote — the try_vote argument: (proposal_round, last_round_tc, tip).
type pendingVote struct {
	proposalRound types.Round
	lastRoundTC   *cstypes.TimeoutCertificate
	tip           cstypes.ConsensusTip
}

// tryAddAndCommitBlocktree — Rust try_add_and_commit_blocktree.
func (s *State) tryAddAndCommitBlocktree(
	block *cstypes.ConsensusFullBlock,
	tryVote *pendingVote,
) []Command {
	var cmds []Command
	s.Consensus.PendingBlockTree.Add(block)

	cmds = append(cmds, s.tryUpdateCoherency(block.GetId())...)

	if tryVote != nil && tryVote.proposalRound == s.Consensus.Pacemaker.GetCurrentRound() {
		if tryVote.tip.BlockHeader.GetId() != block.GetId() {
			panic("consensusstate: tip block id mismatch")
		}
		cmds = append(cmds, s.tryVote(tryVote.lastRoundTC, tryVote.tip)...)
	}
	cmds = append(cmds, s.tryPropose()...)

	// statesync if too far from tip
	cmds = append(cmds, s.maybeStatesync()...)
	cmds = append(cmds, s.Consensus.RequestBlocksIfMissingAncestor()...)
	return cmds
}

// tryUpdateCoherency — Rust try_update_coherency: re-check coherence from
// the updated block, emit Proposed commits for newly-coherent blocks, and
// try to finalize via the high committable QC.
func (s *State) tryUpdateCoherency(updatedBlockId types.BlockId) []Command {
	var cmds []Command
	for _, coherent := range s.Consensus.PendingBlockTree.TryUpdateCoherency(
		updatedBlockId, s.BlockPolicy, s.StateRead, s.Config.ChainConfig,
	) {
		cmds = append(cmds, CmdCommitBlocks{Commit: OptimisticPolicyCommit{
			Kind:        CommitProposed,
			Block:       coherent,
			IsCanonical: false,
		}})
	}

	cmds = append(cmds, s.updateProposedHead()...)

	if qc := s.Consensus.PendingBlockTree.GetHighCommittableQc(); qc != nil {
		cmds = append(cmds, s.tryCommit(qc)...)
	}
	return cmds
}

// updateProposedHead — Rust update_proposed_head: emit a canonical Proposed
// commit when the canonical coherent tip changes.
func (s *State) updateProposedHead() []Command {
	highCertQc := s.Consensus.Pacemaker.HighCertificate().GetQC()
	canonicalTipId := s.Consensus.PendingBlockTree.GetCanonicalCoherentTip(&highCertQc)

	if s.Consensus.CanonicalProposedTip != nil && *s.Consensus.CanonicalProposedTip == canonicalTipId {
		return nil
	}
	block := s.Consensus.PendingBlockTree.GetBlock(canonicalTipId)
	if block == nil {
		return nil
	}
	s.Consensus.CanonicalProposedTip = &canonicalTipId
	return []Command{CmdCommitBlocks{Commit: OptimisticPolicyCommit{
		Kind:        CommitProposed,
		Block:       block,
		IsCanonical: true,
	}}}
}

// maybeStatesync — Rust maybe_statesync: panic if the high QC is too far
// ahead of the blocktree root (operator must restart + statesync).
func (s *State) maybeStatesync() []Command {
	highQc := s.Consensus.Pacemaker.HighCertificate().GetQC()
	highQcSeqNum, ok := s.Consensus.PendingBlockTree.GetSeqNumOfQc(&highQc)
	if !ok {
		return nil
	}
	if s.Consensus.PendingBlockTree.Root().SeqNum+s.Config.LiveToStatesyncThreshold > highQcSeqNum {
		return nil
	}
	panic("consensusstate: high qc too far ahead of block tree root, restart client and statesync")
}

// tryVote — Rust try_vote: timestamp + coherence + safety checks, then
// either send the vote or schedule it on the vote-pace timer.
func (s *State) tryVote(
	lastRoundTC *cstypes.TimeoutCertificate,
	tip cstypes.ConsensusTip,
) []Command {
	var cmds []Command
	proposalRound := s.Consensus.Pacemaker.GetCurrentRound()

	parentTimestamp, okTs := s.Consensus.PendingBlockTree.GetTimestampOfQc(&tip.BlockHeader.QC)
	parentBlockRound, okRound := s.Consensus.PendingBlockTree.GetBlockRoundOfQc(&tip.BlockHeader.QC)
	if !okTs || !okRound {
		// dropping proposal, no parent timestamp/block_round
		return cmds
	}

	isReproposal := proposalRound != tip.BlockHeader.BlockRound
	votePace := s.Config.ChainConfig.GetChainRevision(proposalRound).ChainParams().VotePace
	if s.BlockTimestamp.ValidBlockTimestamp(
		parentTimestamp, tip.BlockHeader.TimestampNs,
		types.U128FromUint64(uint64(votePace)), isReproposal,
	) == nil {
		s.Metrics.ConsensusEvents.FailedTSValidation.Inc()
		return cmds
	}

	if !s.Consensus.PendingBlockTree.IsCoherent(tip.BlockHeader.GetId()) {
		// not voting on proposal — not coherent
		return cmds
	}

	var lastRoundTcTip *types.BlockId
	if lastRoundTC != nil && lastRoundTC.HighExtend.IsTip {
		id := lastRoundTC.HighExtend.Tip.BlockHeader.GetId()
		lastRoundTcTip = &id
	}

	if !s.Consensus.Safety.IsSafeToVote(proposalRound, lastRoundTcTip) {
		// already voted or timed out this round, or already NE'd a
		// different TC
		return cmds
	}
	s.Consensus.Safety.Vote(proposalRound, lastRoundTcTip, tip)

	v := cstypes.Vote{
		ID:    tip.BlockHeader.GetId(),
		Round: proposalRound,
		Epoch: s.Consensus.Pacemaker.GetCurrentEpoch(),
	}
	s.maybeRecordVoteDelayMetrics(proposalRound, parentBlockRound)

	switch sv := s.Consensus.ScheduledVote; {
	case sv != nil && sv.Kind == VoteTimerFired:
		// timer already fired for this round — send vote immediately
		cmds = append(cmds, s.sendVoteAndResetTimer(v)...)
	case sv != nil && sv.Kind == VoteReady && sv.Vote.Round >= v.Round:
		panic("consensusstate: trying to schedule another vote in same round")
	default:
		// if this is the next round after a timeout, vote immediately —
		// otherwise schedule on the vote-pace timer
		if parentBlockRound+1 != proposalRound {
			cmds = append(cmds, s.sendVoteAndResetTimer(v)...)
		} else {
			s.Consensus.ScheduledVote = &OutgoingVoteStatus{Kind: VoteReady, Vote: v}
		}
	}
	return cmds
}

// tryPropose — Rust try_propose (idempotent): if we're the leader, emit a
// CreateProposal (QC extension) or a reproposal/round-recovery (Tip).
func (s *State) tryPropose() []Command {
	var cmds []Command

	round := s.Consensus.Pacemaker.GetCurrentRound()
	epoch, ok := s.EpochManager.GetEpoch(round)
	if !ok {
		panic("consensusstate: current epoch exists")
	}
	validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
	if !ok {
		panic("consensusstate: TODO handle non-existent validatorset for next round epoch")
	}
	leader := s.Election.GetLeader(round, validatorSet)

	if s.NodeId != leader {
		return cmds
	}

	cmds = append(cmds, s.Consensus.requestTipIfMissing()...)

	if !s.Consensus.Safety.IsSafeToPropose(round) {
		return cmds
	}

	var highExtend cstypes.HighExtend
	var freshProposalCert *cstypes.FreshProposalCertificate
	var lastRoundTC *cstypes.TimeoutCertificate
	switch hc := s.Consensus.Pacemaker.HighCertificate(); {
	case !hc.IsQC:
		tc := hc.TC
		lastRoundTC = tc
		if nec := s.Consensus.NoEndorsementState.GetNec(round); nec != nil {
			heQc := tc.HighExtend.GetQC()
			highExtend = cstypes.HighExtendQc(heQc)
			freshProposalCert = cstypes.FPCFromNec(*nec)
		} else if tc.HighExtend.IsTip {
			highExtend = cstypes.HighExtendTip(tc.HighExtend.Tip)
		} else {
			highExtend = cstypes.HighExtendQc(*tc.HighExtend.QC)
			freshProposalCert = cstypes.FPCFromNoTip(cstypes.NoTipCertificate{
				Epoch:     tc.Epoch,
				Round:     tc.Round,
				TipRounds: tc.TipRounds,
				HighQc:    *tc.HighExtend.QC,
			})
		}
	default:
		highExtend = cstypes.HighExtendQc(*hc.QC)
	}

	if highExtend.IsTip {
		tip := highExtend.Tip
		cmds = append(cmds, s.tryUpdateCoherency(tip.BlockHeader.GetId())...)
		isCoherent := s.Consensus.PendingBlockTree.IsCoherent(tip.BlockHeader.GetId())
		// TODO roll this into coherency, remove from try_vote — error-prone
		isVotableTs := tip.BlockHeader.TimestampNs.Cmp(s.BlockTimestamp.GetCurrentTime()) < 0
		if !isCoherent || !isVotableTs {
			if !s.Consensus.Safety.IsSafeToRecoveryRequest(round) {
				return cmds
			}
			s.Consensus.Safety.RecoveryRequest(round)
			// tip.block_id not coherent — request recovery instead of
			// reproposing
			rrMsg := messages.ConsensusMessage{
				Version: s.Version,
				Message: messages.ProtocolMessage{
					Kind: messages.PMRoundRecovery,
					RoundRecovery: &messages.RoundRecoveryMessage{
						Round: s.Consensus.Pacemaker.GetCurrentRound(),
						Epoch: s.Consensus.Pacemaker.GetCurrentEpoch(),
						TC:    *lastRoundTC, // high_extend is tip → tc exists
					},
				},
			}
			cmds = append(cmds, CmdPublish{
				Target:  types.BroadcastTarget(s.Consensus.Pacemaker.GetCurrentEpoch()),
				Message: messages.Sign(rrMsg, s.Keypair),
			})
			return cmds
		}

		// make sure we haven't voted or timed out this round
		s.Consensus.Safety.Propose(round)
		block := s.Consensus.PendingBlockTree.GetBlock(tip.BlockHeader.GetId())
		if block == nil {
			panic("consensusstate: tip is coherent")
		}
		propMsg := messages.ConsensusMessage{
			Version: s.Version,
			Message: messages.ProtocolMessage{
				Kind: messages.PMProposal,
				Proposal: &messages.ProposalMessage{
					ProposalRound: s.Consensus.Pacemaker.GetCurrentRound(),
					ProposalEpoch: s.Consensus.Pacemaker.GetCurrentEpoch(),
					Tip:           *tip,
					BlockBody:     block.Body,
					LastRoundTC:   lastRoundTC,
				},
			},
		}
		cmds = append(cmds, CmdPublish{
			Target: types.RaptorcastTarget(
				s.Consensus.Pacemaker.GetCurrentRound(),
				s.Consensus.Pacemaker.GetCurrentEpoch()),
			Message: messages.Sign(propMsg, s.Keypair),
		})
		return cmds
	}

	// HighExtend::Qc — check path to root and coherence
	qc := highExtend.QC
	cmds = append(cmds, s.tryUpdateCoherency(qc.GetBlockId())...)
	if !s.Consensus.PendingBlockTree.IsCoherent(qc.GetBlockId()) {
		// qc.block_id not coherent — can't propose
		return cmds
	}

	roundSignature := cstypes.NewRoundSignature(round, s.CertKeypair)

	// propose when there's a path to root
	pendingBlocks := s.Consensus.PendingBlockTree.GetBlocksOnPathFromRoot(qc.GetBlockId())
	if pendingBlocks == nil {
		panic("consensusstate: there should be a path to root")
	}

	// build a proposal off the pending branch, or against the blocktree root
	// if there is no branch
	var tryProposeSeqNum types.SeqNum
	var timestampNs types.U128
	if len(pendingBlocks) > 0 {
		extending := pendingBlocks[len(pendingBlocks)-1]
		tryProposeSeqNum = extending.GetSeqNum() + 1
		timestampNs = s.BlockTimestamp.GetValidBlockTimestamp(extending.Header.TimestampNs)
	} else {
		tryProposeSeqNum = s.Consensus.PendingBlockTree.Root().SeqNum + 1
		timestampNs = s.BlockTimestamp.GetValidBlockTimestamp(
			s.Consensus.PendingBlockTree.Root().TimestampNs)
	}

	delayedResults, err := s.BlockPolicy.GetExpectedExecutionResults(
		tryProposeSeqNum, pendingBlocks, s.StateRead)
	if err != nil {
		// no execution result found, can't propose — execution lagging
		s.Metrics.ConsensusEvents.RxExecutionLagging.Inc()
		return cmds
	}

	s.Consensus.Safety.Propose(round)

	params := s.Config.ChainConfig.GetChainRevision(round).ChainParams()
	cmds = append(cmds, CmdCreateProposal{
		NodeId:                   s.NodeId,
		Epoch:                    epoch,
		Round:                    round,
		SeqNum:                   tryProposeSeqNum,
		HighQC:                   *qc,
		RoundSignature:           roundSignature,
		LastRoundTC:              lastRoundTC,
		FreshProposalCertificate: freshProposalCert,
		TxLimit:                  params.TxLimit,
		ProposalGasLimit:         params.ProposalGasLimit,
		ProposalByteLimit:        params.ProposalByteLimit,
		Beneficiary:              s.Beneficiary,
		TimestampNs:              timestampNs,
		ExtendingBlocks:          pendingBlocks,
		DelayedExecutionResults:  delayedResults,
	})
	return cmds
}

// upcomingLeaderRoundPairs — Rust compute_upcoming_leader_round_pairs.
func (s *State) upcomingLeaderRoundPairs(includeCurrent bool, numRounds int) []struct {
	NodeId types.NodeId
	Round  types.Round
} {
	start := s.Consensus.GetCurrentRound()
	if !includeCurrent {
		start++
	}
	out := make([]struct {
		NodeId types.NodeId
		Round  types.Round
	}, 0, numRounds)
	for i := 0; i < numRounds; i++ {
		round := start + types.Round(i)
		epoch, ok := s.EpochManager.GetEpoch(round)
		if !ok {
			panic("consensusstate: epoch exists")
		}
		validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
		if !ok {
			panic("consensusstate: TODO handle non-existent validatorset for next k round epoch")
		}
		out = append(out, struct {
			NodeId types.NodeId
			Round  types.Round
		}{s.Election.GetLeader(round, validatorSet), round})
	}
	return out
}

// IterUpcomingSelfLeaderRounds — Rust iter_upcoming_self_leader_rounds.
func (s *State) IterUpcomingSelfLeaderRounds() []types.Round {
	var out []types.Round
	for _, p := range s.upcomingLeaderRoundPairs(true, numLeadersSelfUpcoming) {
		if p.NodeId == s.NodeId {
			out = append(out, p.Round)
		}
	}
	return out
}

// IterFutureOtherLeaders — Rust iter_future_other_leaders (unique leaders
// over the lookahead window, first-occurrence order).
func (s *State) IterFutureOtherLeaders() []types.NodeId {
	var out []types.NodeId
	seen := make(map[types.NodeId]struct{})
	for _, p := range s.upcomingLeaderRoundPairs(false, numLeadersForwardTxs) {
		if p.NodeId == s.NodeId {
			continue
		}
		if _, ok := seen[p.NodeId]; ok {
			continue
		}
		seen[p.NodeId] = struct{}{}
		out = append(out, p.NodeId)
	}
	return out
}

func (s *State) lookupLeader(round types.Round) *types.NodeId {
	epoch, ok := s.EpochManager.GetEpoch(round)
	if !ok {
		return nil
	}
	validatorSet, ok := s.ValEpochMap.GetValSet(epoch)
	if !ok {
		return nil
	}
	leader := s.Election.GetLeader(round, validatorSet)
	return &leader
}
