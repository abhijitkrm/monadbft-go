package consensus

import (
	"time"

	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// PhaseHonest — Rust PhaseHonest: tracks whether we've seen evidence of an
// honest timeout this round.
type phaseHonest int

const (
	phaseZero phaseHonest = iota
	phaseOne
)

// PacemakerCommand — Rust PacemakerCommand.
type PacemakerCommand interface{ isPacemakerCmd() }

// EnterRound — emitted whenever round changes (drives router epoch/round).
type CmdEnterRound struct {
	Epoch    types.Epoch
	Round    types.Round
	HighCert cstypes.RoundCertificate
}

// PrepareTimeout — create+sign a TimeoutMessage and broadcast it.
type CmdPrepareTimeout struct {
	Timeout    cstypes.TimeoutInfo
	HighExtend cstypes.HighExtend
	SafeToVote bool
	LastRC     *cstypes.RoundCertificate
}

// CmdSchedule — schedule a local round timeout after Duration.
type CmdSchedule struct {
	Round    types.Round
	Duration time.Duration
}

// CmdScheduleReset — cancel the current local round timeout.
type CmdScheduleReset struct{}

func (CmdEnterRound) isPacemakerCmd()     {}
func (CmdPrepareTimeout) isPacemakerCmd() {}
func (CmdSchedule) isPacemakerCmd()       {}
func (CmdScheduleReset) isPacemakerCmd()  {}

// Pacemaker ports Rust pacemaker::Pacemaker.
type Pacemaker struct {
	delta           time.Duration
	chainConfig     chaincfg.Config
	localProcessing time.Duration

	currentEpoch types.Epoch

	// certificate that advanced us to current round
	highCertificate cstypes.RoundCertificate

	pendingTimeouts       map[[33]byte]pendingTimeout // nodeid -> timeout msg
	invalidTimeoutSenders map[[33]byte]struct{}

	phase phaseHonest
}

type pendingTimeout struct {
	nodeId types.NodeId
	msg    messages.TimeoutMessage
}

// NewPacemaker — Rust Pacemaker::new.
func NewPacemaker(
	delta time.Duration,
	chainConfig chaincfg.Config,
	localProcessing time.Duration,
	epochManager *validator.EpochManager,
	highCertificate cstypes.RoundCertificate,
) *Pacemaker {
	currentRound := highCertificate.Round() + 1
	epoch, ok := epochManager.GetEpoch(currentRound)
	if !ok {
		panic("pacemaker: init round must exist in epoch manager")
	}
	return &Pacemaker{
		delta:                 delta,
		chainConfig:           chainConfig,
		localProcessing:       localProcessing,
		currentEpoch:          epoch,
		highCertificate:       highCertificate,
		pendingTimeouts:       make(map[[33]byte]pendingTimeout),
		invalidTimeoutSenders: make(map[[33]byte]struct{}),
		phase:                 phaseZero,
	}
}

func (p *Pacemaker) GetCurrentRound() types.Round {
	return p.highCertificate.Round() + 1
}

func (p *Pacemaker) GetCurrentEpoch() types.Epoch { return p.currentEpoch }

func (p *Pacemaker) HighCertificate() *cstypes.RoundCertificate {
	return &p.highCertificate
}

// getRoundTimer = delta*3 + vote_pace + local_processing.
func (p *Pacemaker) getRoundTimer(round types.Round) time.Duration {
	voteDelay := p.chainConfig.GetChainRevision(round).ChainParams().VotePace
	return p.delta*3 + voteDelay + p.localProcessing
}

// ProcessCertificate — Rust process_certificate: advance round on QC/TC.
func (p *Pacemaker) ProcessCertificate(
	epochManager *validator.EpochManager,
	safety *Safety,
	certificate cstypes.RoundCertificate,
) []PacemakerCommand {
	if certificate.Round() <= p.highCertificate.Round() {
		return nil
	}
	safety.ProcessCertificate(&certificate)
	p.highCertificate = certificate
	epoch, ok := epochManager.GetEpoch(p.GetCurrentRound())
	if !ok {
		panic("pacemaker: epoch must exist for higher round")
	}
	p.currentEpoch = epoch
	p.phase = phaseZero
	p.pendingTimeouts = make(map[[33]byte]pendingTimeout)
	p.invalidTimeoutSenders = make(map[[33]byte]struct{})

	return []PacemakerCommand{
		CmdEnterRound{
			Epoch:    p.currentEpoch,
			Round:    p.GetCurrentRound(),
			HighCert: p.highCertificate,
		},
		CmdSchedule{
			Round:    p.GetCurrentRound(),
			Duration: p.getRoundTimer(p.GetCurrentRound()),
		},
	}
}

// localTimeoutRound — Rust local_timeout_round.
func (p *Pacemaker) localTimeoutRound(safety *Safety) []PacemakerCommand {
	currentRound := p.GetCurrentRound()
	safeToIncludeVote := safety.Timeout(currentRound)

	var highExtend cstypes.HighExtend
	if tip := safety.MaybeHighTip(); tip != nil {
		highExtend = cstypes.HighExtendTip(tip)
	} else {
		qc := p.highCertificate.GetQC()
		highExtend = cstypes.HighExtendQc(qc)
	}

	var highTipRound, highExtendQcRound types.Round
	if highExtend.IsTip {
		highTipRound = highExtend.Tip.BlockHeader.BlockRound
		highExtendQcRound = highExtend.Tip.BlockHeader.QC.GetRound()
	} else {
		highTipRound = types.GENESIS_ROUND
		highExtendQcRound = highExtend.QC.GetRound()
	}

	tinfo := cstypes.TimeoutInfo{
		Epoch:        p.currentEpoch,
		Round:        currentRound,
		HighTipRound: highTipRound,
		HighQcRound:  highExtendQcRound,
	}

	var lastRC *cstypes.RoundCertificate
	if highExtendQcRound+1 != currentRound {
		rc := p.highCertificate
		lastRC = &rc
	}

	return []PacemakerCommand{
		CmdScheduleReset{},
		CmdPrepareTimeout{
			Timeout:    tinfo,
			HighExtend: highExtend,
			SafeToVote: safeToIncludeVote,
			LastRC:     lastRC,
		},
		CmdSchedule{Round: currentRound, Duration: p.getRoundTimer(currentRound)},
	}
}

// ProcessLocalTimeout — Rust process_local_timeout.
func (p *Pacemaker) ProcessLocalTimeout(safety *Safety) []PacemakerCommand {
	p.phase = phaseOne
	return p.localTimeoutRound(safety)
}

// ProcessRemoteTimeout — Rust process_remote_timeout.
func (p *Pacemaker) ProcessRemoteTimeout(
	epochManager *validator.EpochManager,
	validators *validator.ValidatorSet,
	validatorMapping *validator.ValidatorMapping,
	safety *Safety,
	author types.NodeId,
	timeoutMsg messages.TimeoutMessage,
) []PacemakerCommand {
	var cmds []PacemakerCommand
	tmInfo := timeoutMsg.Timeout.TmInfo
	if tmInfo.Round < p.GetCurrentRound() {
		return nil
	}
	// caller guarantees: tm round == current round (the embedded QC/TC was
	// processed before this call)
	if tmInfo.Round != p.GetCurrentRound() {
		panic("pacemaker: timeout round != current round")
	}
	authorKey := [33]byte(author.PubKey)
	if _, bad := p.invalidTimeoutSenders[authorKey]; bad {
		return nil
	}
	p.pendingTimeouts[authorKey] = pendingTimeout{nodeId: author, msg: timeoutMsg}

	timeouts := p.pendingNodeIds()

	if p.phase == phaseZero {
		ok, err := validators.HasHonestVote(timeouts)
		if err != nil {
			panic("pacemaker: has_honest_vote")
		}
		if ok {
			cmds = append(cmds, p.localTimeoutRound(safety)...)
			p.phase = phaseOne
		}
	}

	for p.phase == phaseOne {
		ok, err := validators.HasSuperMajorityVotes(timeouts)
		if err != nil {
			panic("pacemaker: has_super_majority_votes")
		}
		if !ok {
			break
		}
		// build TC from all pending timeouts
		tms := make([]struct {
			NodeId  types.NodeId
			Timeout cstypes.Timeout
		}, 0, len(p.pendingTimeouts))
		for _, pt := range p.pendingTimeouts {
			tms = append(tms, struct {
				NodeId  types.NodeId
				Timeout cstypes.Timeout
			}{pt.nodeId, pt.msg.Timeout})
		}
		tc, err := cstypes.NewTimeoutCertificate(tmInfo.Epoch, tmInfo.Round, tms, validatorMapping)
		if err == nil {
			cmds = append(cmds, p.ProcessCertificate(epochManager, safety,
				*cstypes.RoundCertFromTC(*tc))...)
			if p.phase != phaseZero {
				panic("pacemaker: phase must reset after certificate")
			}
			break
		}
		// InvalidSignaturesCreate → drop the bad senders and retry
		if bad, ok := invalidSigVoters(err); ok {
			for _, n := range bad {
				p.invalidTimeoutSenders[[33]byte(n.PubKey)] = struct{}{}
				delete(p.pendingTimeouts, [33]byte(n.PubKey))
			}
			timeouts = p.pendingNodeIds()
			continue
		}
		panic("pacemaker: unexpected TC creation error: " + err.Error())
	}
	return cmds
}

func (p *Pacemaker) pendingNodeIds() []types.NodeId {
	out := make([]types.NodeId, 0, len(p.pendingTimeouts))
	for _, pt := range p.pendingTimeouts {
		out = append(out, pt.nodeId)
	}
	return out
}
