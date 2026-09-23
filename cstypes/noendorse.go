package cstypes

import (
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/sigcol"
	"github.com/abhijitkrm/monadbft-go/types"
)

// NoEndorsement — Rust { epoch, round, tip_qc_round }.
type NoEndorsement struct {
	Epoch      types.Epoch
	Round      types.Round
	TipQcRound types.Round
}

func (n NoEndorsement) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = n.Epoch.EncodeRLP(p)
		p = n.Round.EncodeRLP(p)
		p = n.TipQcRound.EncodeRLP(p)
		return p
	})
}

func (n *NoEndorsement) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := n.Epoch.DecodeRLP(l); err != nil {
		return err
	}
	if err := n.Round.DecodeRLP(l); err != nil {
		return err
	}
	if err := n.TipQcRound.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

// NoEndorsementCertificate — Rust { msg, signatures }.
type NoEndorsementCertificate struct {
	Msg        NoEndorsement
	Signatures sigcol.BlsSignatureCollection
}

func (n NoEndorsementCertificate) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = n.Msg.EncodeRLP(p)
		p = n.Signatures.EncodeRLP(p)
		return p
	})
}

func (n *NoEndorsementCertificate) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := n.Msg.DecodeRLP(l); err != nil {
		return err
	}
	if err := n.Signatures.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

// FreshProposalCertificate — Rust enum: Nec(tag 1) | NoTip(tag 2).
type FreshProposalCertificate struct {
	IsNec  bool
	Nec    *NoEndorsementCertificate
	NoTip  *NoTipCertificate
}

func FPCFromNec(nec NoEndorsementCertificate) *FreshProposalCertificate {
	return &FreshProposalCertificate{IsNec: true, Nec: &nec}
}
func FPCFromNoTip(nt NoTipCertificate) *FreshProposalCertificate {
	return &FreshProposalCertificate{NoTip: &nt}
}

func (f FreshProposalCertificate) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		if f.IsNec {
			p = rlp.AppendUint8(p, 1)
			p = f.Nec.EncodeRLP(p)
		} else {
			p = rlp.AppendUint8(p, 2)
			p = f.NoTip.EncodeRLP(p)
		}
		return p
	})
}

func (f *FreshProposalCertificate) DecodeRLP(s *rlp.Stream, ep decodeCtx) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	tag, err := l.Uint64()
	if err != nil {
		return err
	}
	switch tag {
	case 1:
		var nec NoEndorsementCertificate
		if err := nec.DecodeRLP(l); err != nil {
			return err
		}
		f.IsNec, f.Nec = true, &nec
	case 2:
		var nt NoTipCertificate
		l2, err := l.List()
		if err != nil {
			return err
		}
		if err := nt.Epoch.DecodeRLP(l2); err != nil {
			return err
		}
		if err := nt.Round.DecodeRLP(l2); err != nil {
			return err
		}
		trs, err := l2.List()
		if err != nil {
			return err
		}
		for trs.Remaining() > 0 {
			var tr HighTipRoundSigColTuple
			if err := tr.DecodeRLP(trs); err != nil {
				return err
			}
			nt.TipRounds = append(nt.TipRounds, tr)
		}
		if err := nt.HighQc.DecodeRLP(l2); err != nil {
			return err
		}
		if err := l2.Done(); err != nil {
			return err
		}
		f.IsNec, f.NoTip = false, &nt
	default:
		return rlp.ErrCustom
	}
	return l.Done()
}
