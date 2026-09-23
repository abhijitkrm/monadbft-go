package cstypes

import (
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// RoundCertificate — Rust enum: Qc(tag 1) | Tc(tag 2).
type RoundCertificate struct {
	IsQC bool
	QC   *QuorumCertificate
	TC   *TimeoutCertificate
}

func RoundCertFromQC(qc QuorumCertificate) *RoundCertificate {
	return &RoundCertificate{IsQC: true, QC: &qc}
}
func RoundCertFromTC(tc TimeoutCertificate) *RoundCertificate {
	return &RoundCertificate{TC: &tc}
}

func (r RoundCertificate) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		if r.IsQC {
			p = rlp.AppendUint8(p, 1)
			p = r.QC.EncodeRLP(p)
		} else {
			p = rlp.AppendUint8(p, 2)
			p = r.TC.EncodeRLP(p)
		}
		return p
	})
}

func (r *RoundCertificate) DecodeRLP(s *rlp.Stream, ep decodeCtx) error {
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
		var qc QuorumCertificate
		if err := qc.DecodeRLP(l); err != nil {
			return err
		}
		r.IsQC, r.QC = true, &qc
	case 2:
		var tc TimeoutCertificate
		if err := tc.DecodeRLP(l, ep); err != nil {
			return err
		}
		r.IsQC, r.TC = false, &tc
	default:
		return rlp.ErrCustom
	}
	return l.Done()
}

func (r RoundCertificate) Round() types.Round {
	if r.IsQC {
		return r.QC.Info.Round
	}
	return r.TC.Round
}

func (r RoundCertificate) GetTC() *TimeoutCertificate { return r.TC }

// QC returns the QC for Qc variant, or the TC's high_extend QC.
func (r RoundCertificate) GetQC() QuorumCertificate {
	if r.IsQC {
		return *r.QC
	}
	return r.TC.HighExtend.GetQC()
}
