// Package messages ports monad-consensus/src/messages: protocol message
// types, the ConsensusMessage envelope, and the Verified/Unverified
// signature wrappers. All RLP byte-identical to the Rust impl.
package messages

import (
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// VoteMessage — Rust { vote, sig(BLS) }. Sig = cert-key sign over
// domain Vote || rlp(vote).
type VoteMessage struct {
	Vote cstypes.Vote
	Sig  crypto.BlsSignature
}

func NewVoteMessage(vote cstypes.Vote, key *crypto.BlsKeyPair) VoteMessage {
	return VoteMessage{Vote: vote, Sig: key.Sign(crypto.DomainVote, vote.EncodeRLP(nil))}
}

func (m VoteMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = m.Vote.EncodeRLP(p)
		p = rlp.AppendString(p, m.Sig.Compress())
		return p
	})
}

func (m *VoteMessage) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := m.Vote.DecodeRLP(l); err != nil {
		return err
	}
	b, err := l.FixedBytes(crypto.BlsSignatureCompressdLen)
	if err != nil {
		return err
	}
	sig, err := crypto.BlsSignatureUncompress(b)
	if err != nil {
		return err
	}
	m.Sig = sig
	return l.Done()
}

// TimeoutMessage — transparent RLP wrapper over cstypes.Timeout.
type TimeoutMessage struct {
	Timeout cstypes.Timeout
}

func NewTimeoutMessage(certKey *crypto.BlsKeyPair, tinfo cstypes.TimeoutInfo,
	highExtend cstypes.HighExtend, safeToVote bool, lastRoundCert *cstypes.RoundCertificate) TimeoutMessage {
	return TimeoutMessage{Timeout: cstypes.NewTimeout(certKey, tinfo, highExtend, safeToVote, lastRoundCert)}
}

func (m TimeoutMessage) EncodeRLP(dst []byte) []byte { return m.Timeout.EncodeRLP(dst) }
func (m *TimeoutMessage) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	return m.Timeout.DecodeRLP(s, ep)
}

// ProposalMessage — Rust { proposal_round, proposal_epoch, tip, block_body,
// last_round_tc(trailing) }.
type ProposalMessage struct {
	ProposalRound types.Round
	ProposalEpoch types.Epoch
	Tip           cstypes.ConsensusTip
	BlockBody     cstypes.ConsensusBlockBody
	LastRoundTC   *cstypes.TimeoutCertificate // trailing optional
}

func (m ProposalMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = m.ProposalRound.EncodeRLP(p)
		p = m.ProposalEpoch.EncodeRLP(p)
		p = m.Tip.EncodeRLP(p)
		p = m.BlockBody.EncodeRLP(p)
		if m.LastRoundTC != nil {
			p = m.LastRoundTC.EncodeRLP(p)
		}
		return p
	})
}

func (m *ProposalMessage) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := m.ProposalRound.DecodeRLP(l); err != nil {
		return err
	}
	if err := m.ProposalEpoch.DecodeRLP(l); err != nil {
		return err
	}
	if err := m.Tip.DecodeRLP(l, ep); err != nil {
		return err
	}
	if err := m.BlockBody.DecodeRLP(l, ep); err != nil {
		return err
	}
	if l.Remaining() > 0 {
		var tc cstypes.TimeoutCertificate
		if err := tc.DecodeRLP(l, ep); err != nil {
			return err
		}
		m.LastRoundTC = &tc
	}
	return l.Done()
}

// AdvanceRoundMessage — Rust { last_round_certificate }.
type AdvanceRoundMessage struct {
	LastRoundCertificate cstypes.RoundCertificate
}

func (m AdvanceRoundMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		return m.LastRoundCertificate.EncodeRLP(p)
	})
}

func (m *AdvanceRoundMessage) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := m.LastRoundCertificate.DecodeRLP(l, ep); err != nil {
		return err
	}
	return l.Done()
}

// RoundRecoveryMessage — Rust { round, epoch, tc }.
type RoundRecoveryMessage struct {
	Round types.Round
	Epoch types.Epoch
	TC    cstypes.TimeoutCertificate
}

func (m RoundRecoveryMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = m.Round.EncodeRLP(p)
		p = m.Epoch.EncodeRLP(p)
		p = m.TC.EncodeRLP(p)
		return p
	})
}

func (m *RoundRecoveryMessage) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := m.Round.DecodeRLP(l); err != nil {
		return err
	}
	if err := m.Epoch.DecodeRLP(l); err != nil {
		return err
	}
	if err := m.TC.DecodeRLP(l, ep); err != nil {
		return err
	}
	return l.Done()
}

// NoEndorsementMessage — Rust { msg, signature }.
type NoEndorsementMessage struct {
	Msg       cstypes.NoEndorsement
	Signature crypto.BlsSignature
}

func NewNoEndorsementMessage(ne cstypes.NoEndorsement, key *crypto.BlsKeyPair) NoEndorsementMessage {
	return NoEndorsementMessage{
		Msg:       ne,
		Signature: key.Sign(crypto.DomainNoEndorsement, ne.EncodeRLP(nil)),
	}
}

func (m NoEndorsementMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = m.Msg.EncodeRLP(p)
		p = rlp.AppendString(p, m.Signature.Compress())
		return p
	})
}

func (m *NoEndorsementMessage) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := m.Msg.DecodeRLP(l); err != nil {
		return err
	}
	b, err := l.FixedBytes(crypto.BlsSignatureCompressdLen)
	if err != nil {
		return err
	}
	sig, err := crypto.BlsSignatureUncompress(b)
	if err != nil {
		return err
	}
	m.Signature = sig
	return l.Done()
}
