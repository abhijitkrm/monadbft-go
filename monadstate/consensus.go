package monadstate

import (
	"github.com/abhijitkrm/monadbft-go/blocksync"
	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validation"
)

// wrappedConsensusCommand — Rust WrappedConsensusCommand: a ConsensusCommand
// plus the upcoming self-leader rounds snapshot taken when it was emitted.
type wrappedConsensusCommand struct {
	upcomingLeaderRounds []types.Round
	command              consensusstate.Command
}

// updateConsensus — Rust ConsensusChildState::update.
func (m *MonadState) updateConsensus(ev glue.ConsensusEvent) []wrappedConsensusCommand {
	if !m.consensus.isLive() {
		// Sync mode: buffer proposals, maybe re-target statesync.
		var cmds []wrappedConsensusCommand
		if msg, ok := ev.(glue.EvConsensusMessage); ok {
			validated, ok := m.verifyAndValidate(
				m.consensus.blockBuffer.RootInfo(),
				m.consensus.highCertificate.Round()+1,
				msg.Sender, msg.UnverifiedMessage)
			if ok {
				pm := validated.Verified.Message.Obj.Message
				if pm.Kind == messages.PMProposal {
					if newRoot, newHighQC := m.consensus.blockBuffer.HandleProposal(validated.Verified.Author, *pm.Proposal); newRoot != nil {
						if !m.consensus.updatingTarget {
							m.consensus.updatingTarget = true
							m.metrics.ConsensusEvents.TriggerStateSync.Inc()
							cmds = append(cmds, wrappedConsensusCommand{
								command: consensusstate.CmdRequestStateSync{Root: *newRoot, HighQC: *newHighQC},
							})
						}
					}
				}
			}
		}
		return cmds
	}

	live := m.consensus.live

	var consensusCmds []consensusstate.Command
	switch e := ev.(type) {
	case glue.EvConsensusMessage:
		root := live.Consensus.PendingBlockTree.Root()
		validated, ok := m.verifyAndValidate(
			&root,
			live.Consensus.GetCurrentRound(),
			e.Sender, e.UnverifiedMessage)
		if !ok {
			return nil
		}
		pm := validated.Verified.Message.Obj.Message
		author := validated.Verified.Author
		switch pm.Kind {
		case messages.PMProposal:
			proposalRound := pm.Proposal.ProposalRound
			proposalEpoch := pm.Proposal.ProposalEpoch
			firstProposal := !live.HasHandledProposal(proposalRound)
			proposalCmds := live.HandleProposalMessage(author, *pm.Proposal)
			if firstProposal && live.HasHandledProposal(proposalRound) {
				proposalCmds = append(proposalCmds, consensusstate.CmdPublishToFullNodes{
					Epoch:         proposalEpoch,
					Round:         proposalRound,
					BroadcastMode: types.SecondaryRaptorcast,
					Message:       validated,
				})
			}
			consensusCmds = proposalCmds
		case messages.PMVote:
			consensusCmds = live.HandleVoteMessage(author, *pm.Vote)
		case messages.PMTimeout:
			consensusCmds = live.HandleTimeoutMessage(author, *pm.Timeout)
		case messages.PMRoundRecovery:
			consensusCmds = live.HandleRoundRecoveryMessage(author, *pm.RoundRecovery)
		case messages.PMNoEndorsement:
			consensusCmds = live.HandleNoEndorsementMessage(author, *pm.NoEndorsement)
		case messages.PMAdvanceRound:
			consensusCmds = live.HandleAdvanceRoundMessage(author, *pm.AdvanceRound)
		}
	case glue.EvConsensusTimeout:
		consensusCmds = live.HandleTimeoutExpiry(e.Round)
	case glue.EvConsensusBlockSync:
		fullBlocks := make([]*cstypes.ConsensusFullBlock, len(e.FullBlocks))
		for i := range e.FullBlocks {
			fullBlocks[i] = &e.FullBlocks[i]
		}
		consensusCmds = live.HandleBlockSync(e.BlockRange, fullBlocks)
	case glue.EvConsensusSendVote:
		consensusCmds = live.HandleVoteTimer(e.Round)
	}

	filtered := m.filterConsensusCmds(consensusCmds)
	out := make([]wrappedConsensusCommand, 0, len(filtered))
	for _, c := range filtered {
		out = append(out, wrappedConsensusCommand{
			upcomingLeaderRounds: live.IterUpcomingSelfLeaderRounds(),
			command:              c,
		})
	}
	return out
}

// verifyAndValidate — Rust ConsensusChildState::verify_and_validate_consensus_message:
// verify sig/author, prefilter, then structural/certificate validation.
// On failure the offending command evidence is recorded as metrics and the
// message is dropped (Rust returns an empty command Vec as evidence).
func (m *MonadState) verifyAndValidate(
	rootInfo *blocktree.RootInfo,
	currentRound types.Round,
	sender types.NodeId,
	msg messages.Unverified,
) (messages.Validated, bool) {
	verified, err := validation.Verify(msg, m.epochManager, m.valEpochMap)
	if err != nil {
		m.recordValidationError(err)
		return messages.Validated{}, false
	}
	if err := validation.Prefilter(&verified.Message, rootInfo, currentRound); err != nil {
		m.recordPrefilterError(err)
		return messages.Validated{}, false
	}
	validated, err := validation.Validate(
		verified, m.certificateCache, m.epochManager, m.valEpochMap,
		m.leaderElection, m.version.ProtocolVersion, currentRound)
	if err != nil {
		m.recordValidationError(err)
		return messages.Validated{}, false
	}
	return validated, true
}

// filterConsensusCmds — Rust ConsensusChildState::filter_cmds: full nodes
// never publish votes/timeouts nor create proposals.
func (m *MonadState) filterConsensusCmds(cmds []consensusstate.Command) []consensusstate.Command {
	if m.GetRole() == RoleValidator {
		return cmds
	}
	out := cmds[:0]
	for _, c := range cmds {
		switch c.(type) {
		case consensusstate.CmdPublish:
			continue
		case consensusstate.CmdCreateProposal:
			continue
		case consensusstate.CmdPublishToFullNodes:
			continue
		}
		out = append(out, c)
	}
	return out
}

// handleMempoolEvent — Rust ConsensusChildState::handle_mempool_event.
func (m *MonadState) handleMempoolEvent(ev glue.MempoolEvent) []glue.Command {
	if !m.consensus.isLive() {
		switch ev.(type) {
		case glue.EvMempoolProposal:
			panic("monadstate: txpool emitted proposal while not live")
		default:
			return nil
		}
	}
	live := m.consensus.live

	switch e := ev.(type) {
	case glue.EvMempoolProposal:
		m.metrics.ConsensusEvents.CreatingProposal.Inc()
		blockBody := cstypes.ConsensusBlockBody{Inner: cstypes.ConsensusBlockBodyInner{ExecutionBody: e.ProposedExecutionInputs.Body}}
		header := cstypes.NewConsensusBlockHeader(
			m.nodeid, e.Epoch, e.Round,
			e.DelayedExecutionResults, e.ProposedExecutionInputs.Header,
			blockBody.GetId(), e.HighQC, e.SeqNum, e.TimestampNs,
			e.RoundSignature, e.BaseFee, e.BaseFeeTrend, e.BaseFeeMoment,
		)
		tip := cstypes.NewConsensusTip(m.keypair, header, e.FreshProposalCertificate)
		p := messages.ProposalMessage{
			ProposalEpoch: e.Epoch,
			ProposalRound: e.Round,
			Tip:           tip,
			BlockBody:     blockBody,
			LastRoundTC:   e.LastRoundTC,
		}
		msg := messages.Sign(messages.ConsensusMessage{
			Version: m.version.ProtocolVersion,
			Message: messages.ProtocolMessage{Kind: messages.PMProposal, Proposal: &p},
		}, m.keypair)
		return []glue.Command{glue.RouterPublish{
			Target:  types.RaptorcastTarget(e.Round, e.Epoch),
			Message: glue.VerifiedFromConsensus(msg),
		}}

	case glue.EvMempoolForwardedTxs:
		return []glue.Command{glue.TxPoolInsertForwardedTxs{Sender: e.Sender, Txs: e.Txs}}

	case glue.EvMempoolForwardTxs:
		var cmds []glue.Command
		for _, target := range live.IterFutureOtherLeaders() {
			cmds = append(cmds, glue.RouterPublishWithPriority{
				Target:   types.RouterTarget{Kind: types.RouterDirectPointToPoint, To: target},
				Message:  &glue.VerifiedMonadMessage{Kind: 4, ForwardedTx: e.Txs},
				Priority: glue.UdpPriorityRegular,
			})
		}
		return cmds
	}
	return nil
}

// handleValidatedProposal — Rust ConsensusChildState::handle_validated_proposal
// (used to inject buffered proposals when transitioning Sync -> Live).
func (m *MonadState) handleValidatedProposal(
	author types.NodeId,
	proposal messages.ProposalMessage,
) []glue.Command {
	if !m.consensus.isLive() {
		panic("monadstate: handle_validated_proposal when not live")
	}
	live := m.consensus.live
	consensusCmds := live.HandleProposalMessage(author, proposal)
	var cmds []glue.Command
	for _, c := range m.filterConsensusCmds(consensusCmds) {
		cmds = append(cmds, m.fromConsensusCommand(wrappedConsensusCommand{
			upcomingLeaderRounds: live.IterUpcomingSelfLeaderRounds(),
			command:              c,
		})...)
	}
	return cmds
}

// checkpoint — Rust ConsensusChildState::checkpoint.
func (m *MonadState) checkpoint() glue.Command {
	if !m.consensus.isLive() {
		return nil
	}
	cp := m.consensus.live.Checkpoint()
	rootSeqNum := m.consensus.live.Consensus.PendingBlockTree.Root().SeqNum
	return glue.ConfigFileCheckpoint{RootSeqNum: rootSeqNum, Checkpoint: cp}
}

// recordValidationError — Rust handle_validation_error.
func (m *MonadState) recordValidationError(err error) {
	ve := &m.metrics.ValidationErrors
	switch err {
	case validation.ErrInvalidAuthor:
		ve.InvalidAuthor.Inc()
	case validation.ErrNotWellFormed:
		ve.NotWellFormedSig.Inc()
	case validation.ErrInvalidSignature:
		ve.InvalidSignature.Inc()
	case validation.ErrInvalidTcRound:
		ve.InvalidTcRound.Inc()
	case validation.ErrDuplicateTcTipRound:
		ve.DuplicateTcTipRound.Inc()
	case validation.ErrEmptySignersTcTipRound:
		ve.EmptySignersTcTipRound.Inc()
	case validation.ErrTooManyTcTipRound:
		ve.TooManyTcTipRound.Inc()
	case validation.ErrInsufficientStake:
		ve.InsufficientStake.Inc()
	case validation.ErrValidatorSetDataUnavailable:
		ve.ValDataUnavailable.Inc()
	case validation.ErrSignaturesDuplicateNode:
		ve.SignaturesDuplicateNode.Inc()
	case validation.ErrInvalidVote:
		ve.InvalidVoteMessage.Inc()
	case validation.ErrInvalidVersion:
		ve.InvalidVersion.Inc()
	case validation.ErrInvalidEpoch:
		ve.InvalidEpoch.Inc()
	}
}

// recordPrefilterError — Rust record_prefilter_error.
func (m *MonadState) recordPrefilterError(err error) {
	switch err {
	case validation.OutdatedVote:
		m.metrics.ConsensusEvents.OldVoteReceived.Inc()
	case validation.OutdatedTimeout:
		m.metrics.ConsensusEvents.OldRemoteTimeout.Inc()
	case validation.OutdatedNoEndorsement:
		m.metrics.ConsensusEvents.OldNoEndorsementReceived.Inc()
	case validation.OutdatedAdvanceRoundQc:
		m.metrics.ConsensusEvents.ProcessOldQC.Inc()
	case validation.OutdatedAdvanceRoundTc:
		m.metrics.ConsensusEvents.ProcessOldTC.Inc()
	}
}

// fromConsensusCommand — Rust From<WrappedConsensusCommand> for Vec<Command>:
// translates a ConsensusCommand into executor-facing Commands.
func (m *MonadState) fromConsensusCommand(w wrappedConsensusCommand) []glue.Command {
	switch c := w.command.(type) {
	case consensusstate.CmdEnterRound:
		return []glue.Command{
			glue.RouterUpdateCurrentRound{Epoch: c.Epoch, Round: c.Round},
			glue.TxPoolEnterRound{Epoch: c.Epoch, Round: c.Round, UpcomingLeaderRounds: w.upcomingLeaderRounds},
		}
	case consensusstate.CmdPublish:
		return []glue.Command{glue.RouterPublishWithPriority{
			Target:   c.Target,
			Message:  glue.VerifiedFromConsensus(c.Message),
			Priority: glue.UdpPriorityHigh,
		}}
	case consensusstate.CmdPublishToFullNodes:
		return []glue.Command{glue.RouterPublishToFullNodes{
			Epoch:         c.Epoch,
			Round:         c.Round,
			BroadcastMode: c.BroadcastMode,
			Message:       glue.VerifiedFromConsensus(c.Message),
		}}
	case consensusstate.CmdSchedule:
		return []glue.Command{glue.TimerSchedule{
			Duration:  c.Duration,
			Variant:   glue.TimeoutVariantPacemaker,
			OnTimeout: glue.EvConsensusTimeout{Round: c.Round},
		}}
	case consensusstate.CmdScheduleReset:
		return []glue.Command{glue.TimerScheduleReset{Variant: glue.TimeoutVariantPacemaker}}
	case consensusstate.CmdCreateProposal:
		return []glue.Command{glue.TxPoolCreateProposal{
			NodeId: c.NodeId, Epoch: c.Epoch, Round: c.Round, SeqNum: c.SeqNum,
			HighQC: c.HighQC, RoundSignature: c.RoundSignature,
			LastRoundTC: c.LastRoundTC, FreshProposalCertificate: c.FreshProposalCertificate,
			TxLimit: c.TxLimit, ProposalGasLimit: c.ProposalGasLimit, ProposalByteLimit: c.ProposalByteLimit,
			Beneficiary: c.Beneficiary, TimestampNs: c.TimestampNs,
			ExtendingBlocks: c.ExtendingBlocks, DelayedExecutionResults: c.DelayedExecutionResults,
		}}
	case consensusstate.CmdCommitBlocks:
		commit := c.Commit
		cmds := []glue.Command{glue.LedgerCommit{Commit: glue.OptimisticCommit{
			Kind:        glue.CommitKind(commit.Kind),
			Block:       commit.Block,
			IsCanonical: commit.IsCanonical,
		}}}
		if commit.Kind == consensusstate.CommitFinalized {
			cmds = append(cmds,
				glue.TxPoolBlockCommit{Blocks: []*cstypes.ConsensusFullBlock{commit.Block}},
				glue.ValSetNotifyFinalized{SeqNum: commit.Block.GetSeqNum()},
			)
		}
		return cmds
	case consensusstate.CmdRequestSync:
		return []glue.Command{glue.LoopbackForward{Event: glue.EvBlockSyncSelfRequest{
			Requester:  blocksync.SelfRequesterConsensus,
			BlockRange: c.Range,
		}}}
	case consensusstate.CmdCancelSync:
		return []glue.Command{glue.LoopbackForward{Event: glue.EvBlockSyncSelfCancelRequest{
			Requester:  blocksync.SelfRequesterConsensus,
			BlockRange: c.Range,
		}}}
	case consensusstate.CmdRequestStateSync:
		return []glue.Command{glue.LoopbackForward{Event: glue.EvStateSyncRequestSync{
			Root:   c.Root,
			HighQC: c.HighQC,
		}}}
	case consensusstate.CmdTimestampUpdate:
		return []glue.Command{glue.TimestampAdjustDelta{Adj: c.Adj}}
	case consensusstate.CmdScheduleVote:
		return []glue.Command{glue.TimerSchedule{
			Duration:  c.Duration,
			Variant:   glue.TimeoutVariantSendVote,
			OnTimeout: glue.EvConsensusSendVote{Round: c.Round},
		}}
	}
	return nil
}
