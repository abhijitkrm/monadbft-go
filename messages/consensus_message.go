package messages

import (
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

const protocolMessageName = "ProtocolMessage"

// ProtocolMessage — Rust enum, encodes as ["ProtocolMessage", tag, inner]:
//   1 Proposal, 2 Vote, 3 Timeout, 4 RoundRecovery, 5 NoEndorsement, 6 AdvanceRound.
type ProtocolMessage struct {
	Kind          ProtocolMessageKind
	Proposal      *ProposalMessage
	Vote          *VoteMessage
	Timeout       *TimeoutMessage
	RoundRecovery *RoundRecoveryMessage
	NoEndorsement *NoEndorsementMessage
	AdvanceRound  *AdvanceRoundMessage
}

type ProtocolMessageKind uint8

const (
	PMProposal ProtocolMessageKind = iota + 1
	PMVote
	PMTimeout
	PMRoundRecovery
	PMNoEndorsement
	PMAdvanceRound
)

func (m ProtocolMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendString(p, []byte(protocolMessageName))
		p = rlp.AppendUint8(p, uint8(m.Kind))
		switch m.Kind {
		case PMProposal:
			p = m.Proposal.EncodeRLP(p)
		case PMVote:
			p = m.Vote.EncodeRLP(p)
		case PMTimeout:
			p = m.Timeout.EncodeRLP(p)
		case PMRoundRecovery:
			p = m.RoundRecovery.EncodeRLP(p)
		case PMNoEndorsement:
			p = m.NoEndorsement.EncodeRLP(p)
		case PMAdvanceRound:
			p = m.AdvanceRound.EncodeRLP(p)
		}
		return p
	})
}

func (m *ProtocolMessage) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	name, err := l.Bytes()
	if err != nil {
		return err
	}
	if string(name) != protocolMessageName {
		return rlp.ErrCustom
	}
	tag, err := l.Uint64()
	if err != nil {
		return err
	}
	switch tag {
	case 1:
		m.Kind, m.Proposal = PMProposal, &ProposalMessage{}
		err = m.Proposal.DecodeRLP(l, ep)
	case 2:
		m.Kind, m.Vote = PMVote, &VoteMessage{}
		err = m.Vote.DecodeRLP(l)
	case 3:
		m.Kind, m.Timeout = PMTimeout, &TimeoutMessage{}
		err = m.Timeout.DecodeRLP(l, ep)
	case 4:
		m.Kind, m.RoundRecovery = PMRoundRecovery, &RoundRecoveryMessage{}
		err = m.RoundRecovery.DecodeRLP(l, ep)
	case 5:
		m.Kind, m.NoEndorsement = PMNoEndorsement, &NoEndorsementMessage{}
		err = m.NoEndorsement.DecodeRLP(l)
	case 6:
		m.Kind, m.AdvanceRound = PMAdvanceRound, &AdvanceRoundMessage{}
		err = m.AdvanceRound.DecodeRLP(l, ep)
	default:
		return rlp.ErrCustom
	}
	if err != nil {
		return err
	}
	return l.Done()
}

func (m ProtocolMessage) GetRound() types.Round {
	switch m.Kind {
	case PMProposal:
		return m.Proposal.ProposalRound
	case PMVote:
		return m.Vote.Vote.Round
	case PMTimeout:
		return m.Timeout.Timeout.TmInfo.Round
	case PMRoundRecovery:
		return m.RoundRecovery.Round
	case PMNoEndorsement:
		return m.NoEndorsement.Msg.Round
	case PMAdvanceRound:
		return m.AdvanceRound.LastRoundCertificate.Round()
	}
	return 0
}

// ConsensusMessage — Rust { version u32, message: ProtocolMessage }.
type ConsensusMessage struct {
	Version uint32
	Message ProtocolMessage
}

func (m ConsensusMessage) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendUint32(p, m.Version)
		p = m.Message.EncodeRLP(p)
		return p
	})
}

func (m *ConsensusMessage) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	v, err := l.Uint64()
	if err != nil {
		return err
	}
	m.Version = uint32(v)
	if err := m.Message.DecodeRLP(l, ep); err != nil {
		return err
	}
	return l.Done()
}

func (m ConsensusMessage) GetRound() types.Round { return m.Message.GetRound() }

// Unverified — Rust Unverified<ST, Unvalidated<M>> = [obj, author_signature].
// On the wire this is what gets deserialized first; the secp sig recovers
// the author NodeId over domain ConsensusMessage || rlp(obj).
type Unverified struct {
	Obj              ConsensusMessage
	AuthorSignature  crypto.SecpSignature
}

func (u Unverified) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = u.Obj.EncodeRLP(p)
		p = rlp.AppendString(p, u.AuthorSignature[:])
		return p
	})
}

func (u *Unverified) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := u.Obj.DecodeRLP(l, ep); err != nil {
		return err
	}
	sigB, err := l.FixedBytes(crypto.SecpSignatureSize)
	if err != nil {
		return err
	}
	sig, err := crypto.SecpSignatureFromBytes(sigB)
	if err != nil {
		return err
	}
	u.AuthorSignature = sig
	return l.Done()
}

// Verify recovers the author and produces a Verified message.
// Rust: Unverified::verify (ecrecover, errors on invalid sig).
func (u Unverified) Verify() (Verified, error) {
	pk, err := u.AuthorSignature.RecoverPubKey(crypto.DomainConsensusMessage, u.Obj.EncodeRLP(nil))
	if err != nil {
		return Verified{}, err
	}
	return Verified{Author: types.NewNodeId(pk), Message: u}, nil
}

// Verified — Rust Verified<ST, Validated<M>>: author + the Unverified.
type Verified struct {
	Author  types.NodeId
	Message Unverified
}

// Sign produces the Verified message (Rust: ConsensusMessage::sign →
// Verified::new over the validated consensus message).
func Sign(msg ConsensusMessage, kp *crypto.SecpKeyPair) Verified {
	sig := kp.Sign(crypto.DomainConsensusMessage, msg.EncodeRLP(nil))
	return Verified{
		Author:  types.NewNodeId(kp.PubKey()),
		Message: Unverified{Obj: msg, AuthorSignature: sig},
	}
}

func (v Verified) Obj() *ConsensusMessage { return &v.Message.Obj }
