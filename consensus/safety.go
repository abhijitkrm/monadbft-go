// Package consensus ports monad-consensus: pacemaker, vote/no-endorsement
// state, safety, and the message validation pipeline.
package consensus

import (
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/types"
)

// handledProposalCacheSize — Rust HANDLED_PROPOSAL_CACHE_SIZE.
const handledProposalCacheSize = 100

// Safety ports Rust validation::safety::Safety — all stateful safety checks
// preventing double-vote / double-propose / conflicting NE+vote.
type Safety struct {
	maybeHighTip           *cstypes.ConsensusTip
	highCertificateQcRound types.Round
	highestVote            types.Round
	highestNoEndorse       highNoEndorse
	highestPropose         types.Round
	highestRecoveryRequest types.Round
	handledProposals       map[types.Round]struct{}
	handledProposalsOrder  []types.Round // insertion order for eviction
}

type highNoEndorse struct {
	round types.Round
	tip   types.BlockId
}

// NewSafety — Rust Safety::new(high_certificate, maybe_high_tip).
func NewSafety(highCertificate *cstypes.RoundCertificate, maybeHighTip *cstypes.ConsensusTip) *Safety {
	currentRound := highCertificate.Round() + 1
	return &Safety{
		maybeHighTip:           maybeHighTip,
		highCertificateQcRound: highCertificate.GetQC().GetRound(),
		// we never vote/ne/propose the current round
		highestVote:            currentRound,
		highestNoEndorse:       highNoEndorse{round: currentRound, tip: types.GENESIS_BLOCK_ID},
		highestPropose:         currentRound,
		highestRecoveryRequest: currentRound,
		handledProposals:       make(map[types.Round]struct{}),
	}
}

// DefaultSafety — Rust Safety::default (all genesis).
func DefaultSafety() *Safety {
	return &Safety{
		highCertificateQcRound: types.GENESIS_ROUND,
		highestVote:            types.GENESIS_ROUND,
		highestNoEndorse:       highNoEndorse{round: types.GENESIS_ROUND, tip: types.GENESIS_BLOCK_ID},
		highestPropose:         types.GENESIS_ROUND,
		highestRecoveryRequest: types.GENESIS_ROUND,
		handledProposals:       make(map[types.Round]struct{}),
	}
}

func (s *Safety) MaybeHighTip() *cstypes.ConsensusTip { return s.maybeHighTip }

// ProcessCertificate — Rust process_certificate: bump high qc round,
// clear stale high tip.
func (s *Safety) ProcessCertificate(cert *cstypes.RoundCertificate) {
	if r := cert.GetQC().GetRound(); r > s.highCertificateQcRound {
		s.highCertificateQcRound = r
	}
	if s.maybeHighTip != nil &&
		s.maybeHighTip.BlockHeader.BlockRound <= s.highCertificateQcRound {
		s.maybeHighTip = nil
	}
}

// IsSafeToVote — Rust is_safe_to_vote.
func (s *Safety) IsSafeToVote(round types.Round, lastRoundTcTip *types.BlockId) bool {
	if round == s.highestNoEndorse.round &&
		(lastRoundTcTip == nil || *lastRoundTcTip != s.highestNoEndorse.tip) {
		// once a TC is NE'd, we must only vote on proposals including that TC
		return false
	}
	return round > s.highestVote
}

// Vote — Rust vote(): asserts safety, records highest vote + maybe high tip.
func (s *Safety) Vote(round types.Round, lastRoundTcTip *types.BlockId, tip cstypes.ConsensusTip) {
	if !s.IsSafeToVote(round, lastRoundTcTip) {
		panic("safety: unsafe vote")
	}
	s.highestVote = round
	if tip.BlockHeader.BlockRound > s.highCertificateQcRound {
		s.maybeHighTip = &tip
	} else {
		s.maybeHighTip = nil
	}
}

func (s *Safety) IsSafeToNoEndorse(round types.Round) bool {
	m := s.highestNoEndorse.round
	if s.highestVote > m {
		m = s.highestVote
	}
	return round > m
}

func (s *Safety) NoEndorse(round types.Round, tip types.BlockId) {
	if !s.IsSafeToNoEndorse(round) {
		panic("safety: unsafe no-endorse")
	}
	s.highestNoEndorse = highNoEndorse{round: round, tip: tip}
}

// Timeout — returns true if safe to include a vote for high_tip in Timeout(r).
func (s *Safety) Timeout(round types.Round) bool {
	if round < s.highestVote {
		panic("safety: timeout round < highest_vote")
	}
	s.highestVote = round
	return s.highestNoEndorse.round < round ||
		(s.maybeHighTip != nil && s.maybeHighTip.BlockHeader.BlockRound == round)
}

func (s *Safety) IsSafeToPropose(round types.Round) bool {
	m := s.highestPropose
	if s.highestVote > m {
		m = s.highestVote
	}
	return round > m
}

func (s *Safety) Propose(round types.Round) {
	if !s.IsSafeToPropose(round) {
		panic("safety: unsafe propose")
	}
	s.highestPropose = round
}

func (s *Safety) IsSafeToRecoveryRequest(round types.Round) bool {
	return round > s.highestRecoveryRequest
}

func (s *Safety) RecoveryRequest(round types.Round) {
	if !s.IsSafeToRecoveryRequest(round) {
		panic("safety: unsafe recovery request")
	}
	s.highestRecoveryRequest = round
}

func (s *Safety) IsSafeToHandleProposal(round types.Round) bool {
	_, ok := s.handledProposals[round]
	return !ok
}

func (s *Safety) HandleProposal(round types.Round) {
	if !s.IsSafeToHandleProposal(round) {
		panic("safety: proposal already handled")
	}
	s.handledProposals[round] = struct{}{}
	s.handledProposalsOrder = append(s.handledProposalsOrder, round)
	for len(s.handledProposals) > handledProposalCacheSize {
		delete(s.handledProposals, s.handledProposalsOrder[0])
		s.handledProposalsOrder = s.handledProposalsOrder[1:]
	}
}
