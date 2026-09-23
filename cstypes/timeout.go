package cstypes

import (
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/sigcol"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// decodeCtx is the execution-protocol factory needed to decode
// EPT-parameterized fields (headers, tips, bodies).
type decodeCtx = *exec.Protocol

// TimeoutInfo — Rust timeout::TimeoutInfo { epoch, round, high_qc_round, high_tip_round }.
type TimeoutInfo struct {
	Epoch        types.Epoch
	Round        types.Round
	HighQcRound  types.Round
	HighTipRound types.Round
}

func (t TimeoutInfo) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = t.Epoch.EncodeRLP(p)
		p = t.Round.EncodeRLP(p)
		p = t.HighQcRound.EncodeRLP(p)
		p = t.HighTipRound.EncodeRLP(p)
		return p
	})
}

func (t *TimeoutInfo) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := t.Epoch.DecodeRLP(l); err != nil {
		return err
	}
	if err := t.Round.DecodeRLP(l); err != nil {
		return err
	}
	if err := t.HighQcRound.DecodeRLP(l); err != nil {
		return err
	}
	if err := t.HighTipRound.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

// Rank — Rust TimeoutInfo::rank.
func (t TimeoutInfo) Rank() HighExtendRank {
	if t.HighTipRound == types.GENESIS_ROUND {
		return HighExtendRank{QcRound: t.HighQcRound, IsTip: false}
	}
	return HighExtendRank{IsTip: true, TipRound: t.HighTipRound, QcRound: t.HighQcRound}
}

// HighExtendRank — Rust HighExtendRank ordering: QC vs Tip compared by
// (tip_round wins ties... QC takes precedence when qc_round == tip_round).
type HighExtendRank struct {
	IsTip    bool
	TipRound types.Round // valid iff IsTip
	QcRound  types.Round
}

// Cmp — Rust Ord for HighExtendRank.
func (a HighExtendRank) Cmp(b HighExtendRank) int {
	cmpR := func(x, y types.Round) int {
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
		return 0
	}
	switch {
	case !a.IsTip && !b.IsTip:
		return cmpR(a.QcRound, b.QcRound)
	case a.IsTip && b.IsTip:
		if a.TipRound != b.TipRound {
			return cmpR(a.TipRound, b.TipRound)
		}
		return cmpR(a.QcRound, b.QcRound)
	case !a.IsTip && b.IsTip:
		if a.QcRound == b.TipRound {
			return 1 // QC takes precedence
		}
		return cmpR(a.QcRound, b.TipRound)
	default: // a tip, b qc
		if a.TipRound == b.QcRound {
			return -1
		}
		return cmpR(a.TipRound, b.QcRound)
	}
}

// HighExtend — Rust enum HighExtend: Tip(tag 1) | Qc(tag 2).
type HighExtend struct {
	IsTip bool
	Tip   *ConsensusTip // set iff IsTip
	QC    *QuorumCertificate
}

func HighExtendQc(qc QuorumCertificate) HighExtend { return HighExtend{QC: &qc} }
func HighExtendTip(t *ConsensusTip) HighExtend     { return HighExtend{IsTip: true, Tip: t} }

func (h HighExtend) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		if h.IsTip {
			p = rlp.AppendUint8(p, 1)
			p = h.Tip.EncodeRLP(p)
		} else {
			p = rlp.AppendUint8(p, 2)
			p = h.QC.EncodeRLP(p)
		}
		return p
	})
}

func (h *HighExtend) DecodeRLP(s *rlp.Stream, ep decodeCtx) error {
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
		var tip ConsensusTip
		if err := tip.DecodeRLP(l, ep); err != nil {
			return err
		}
		h.IsTip, h.Tip = true, &tip
	case 2:
		var qc QuorumCertificate
		if err := qc.DecodeRLP(l); err != nil {
			return err
		}
		h.IsTip, h.QC = false, &qc
	default:
		return rlp.ErrCustom
	}
	return l.Done()
}

func (h HighExtend) Rank() HighExtendRank {
	if h.IsTip {
		return HighExtendRank{
			IsTip:    true,
			TipRound: h.Tip.BlockHeader.BlockRound,
			QcRound:  h.Tip.BlockHeader.QC.GetRound(),
		}
	}
	return HighExtendRank{QcRound: h.QC.GetRound()}
}

func (h HighExtend) GetQC() QuorumCertificate {
	if h.IsTip {
		return h.Tip.BlockHeader.QC
	}
	return *h.QC
}

// HighExtendVote — Rust enum: Tip(tip, Option<sig>) tag 1 | Qc tag 2.
type HighExtendVote struct {
	IsTip   bool
	Tip     *ConsensusTip
	VoteSig *crypto.BlsSignature // optional, only with Tip
	QC      *QuorumCertificate
}

func (h HighExtendVote) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		if h.IsTip {
			p = rlp.AppendUint8(p, 1)
			p = h.Tip.EncodeRLP(p)
			if h.VoteSig != nil {
				p = rlp.AppendString(p, h.VoteSig.Compress())
			}
		} else {
			p = rlp.AppendUint8(p, 2)
			p = h.QC.EncodeRLP(p)
		}
		return p
	})
}

func (h *HighExtendVote) DecodeRLP(s *rlp.Stream, ep decodeCtx) error {
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
		var tip ConsensusTip
		if err := tip.DecodeRLP(l, ep); err != nil {
			return err
		}
		h.IsTip, h.Tip = true, &tip
		if l.Remaining() > 0 {
			b, err := l.FixedBytes(crypto.BlsSignatureCompressdLen)
			if err != nil {
				return err
			}
			sig, err := crypto.BlsSignatureUncompress(b)
			if err != nil {
				return err
			}
			h.VoteSig = &sig
		}
	case 2:
		var qc QuorumCertificate
		if err := qc.DecodeRLP(l); err != nil {
			return err
		}
		h.IsTip, h.QC = false, &qc
	default:
		return rlp.ErrCustom
	}
	return l.Done()
}

func (h HighExtendVote) Rank() HighExtendRank {
	return h.asHighExtend().Rank()
}

func (h HighExtendVote) GetQC() QuorumCertificate { return h.asHighExtend().GetQC() }

func (h HighExtendVote) asHighExtend() HighExtend {
	return HighExtend{IsTip: h.IsTip, Tip: h.Tip, QC: h.QC}
}

// Timeout — Rust timeout::Timeout { tminfo, timeout_signature, high_extend,
// last_round_certificate(trailing) }.
type Timeout struct {
	TmInfo               TimeoutInfo
	TimeoutSignature     crypto.BlsSignature
	HighExtend           HighExtendVote
	LastRoundCertificate *RoundCertificate // trailing optional
}

// NewTimeout — Rust Timeout::new: signature over Timeout domain of
// rlp(tminfo); Tip variant may carry an embedded vote signature.
func NewTimeout(
	certKey *crypto.BlsKeyPair,
	tinfo TimeoutInfo,
	highExtend HighExtend,
	safeToVote bool,
	lastRoundCert *RoundCertificate,
) Timeout {
	tmSig := certKey.Sign(crypto.DomainTimeout, tinfo.EncodeRLP(nil))
	hev := HighExtendVote{}
	if highExtend.IsTip {
		var voteSig *crypto.BlsSignature
		if safeToVote {
			vote := Vote{
				Round: tinfo.Round,
				Epoch: tinfo.Epoch,
				ID:    highExtend.Tip.BlockHeader.GetId(),
			}
			s := certKey.Sign(crypto.DomainVote, vote.EncodeRLP(nil))
			voteSig = &s
		}
		hev = HighExtendVote{IsTip: true, Tip: highExtend.Tip, VoteSig: voteSig}
	} else {
		hev = HighExtendVote{QC: highExtend.QC}
	}
	return Timeout{
		TmInfo:               tinfo,
		TimeoutSignature:     tmSig,
		HighExtend:           hev,
		LastRoundCertificate: lastRoundCert,
	}
}

func (t Timeout) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = t.TmInfo.EncodeRLP(p)
		p = rlp.AppendString(p, t.TimeoutSignature.Compress())
		p = t.HighExtend.EncodeRLP(p)
		if t.LastRoundCertificate != nil {
			p = t.LastRoundCertificate.EncodeRLP(p)
		}
		return p
	})
}

func (t *Timeout) DecodeRLP(s *rlp.Stream, ep decodeCtx) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := t.TmInfo.DecodeRLP(l); err != nil {
		return err
	}
	sigB, err := l.FixedBytes(crypto.BlsSignatureCompressdLen)
	if err != nil {
		return err
	}
	sig, err := crypto.BlsSignatureUncompress(sigB)
	if err != nil {
		return err
	}
	t.TimeoutSignature = sig
	if err := t.HighExtend.DecodeRLP(l, ep); err != nil {
		return err
	}
	// trailing optional
	if l.Remaining() > 0 {
		var rc RoundCertificate
		if err := rc.DecodeRLP(l, ep); err != nil {
			return err
		}
		t.LastRoundCertificate = &rc
	}
	return l.Done()
}

// HighTipRoundSigColTuple — Rust { high_qc_round, high_tip_round, sigs }.
type HighTipRoundSigColTuple struct {
	HighQcRound  types.Round
	HighTipRound types.Round
	Sigs         sigcol.BlsSignatureCollection
}

func (t HighTipRoundSigColTuple) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = t.HighQcRound.EncodeRLP(p)
		p = t.HighTipRound.EncodeRLP(p)
		p = t.Sigs.EncodeRLP(p)
		return p
	})
}

func (t *HighTipRoundSigColTuple) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := t.HighQcRound.DecodeRLP(l); err != nil {
		return err
	}
	if err := t.HighTipRound.DecodeRLP(l); err != nil {
		return err
	}
	if err := t.Sigs.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

func (t HighTipRoundSigColTuple) Rank() HighExtendRank {
	if t.HighTipRound == types.GENESIS_ROUND {
		return HighExtendRank{QcRound: t.HighQcRound}
	}
	return HighExtendRank{IsTip: true, TipRound: t.HighTipRound, QcRound: t.HighQcRound}
}

// TimeoutCertificate — Rust { epoch, round, tip_rounds, high_extend }.
type TimeoutCertificate struct {
	Epoch      types.Epoch
	Round      types.Round
	TipRounds  []HighTipRoundSigColTuple // LimitedVec<_, MAX_VALIDATOR_SET_SIZE>
	HighExtend HighExtend
}

func (t TimeoutCertificate) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = t.Epoch.EncodeRLP(p)
		p = t.Round.EncodeRLP(p)
		p = rlp.AppendList(p, func(q []byte) []byte {
			for _, tr := range t.TipRounds {
				q = tr.EncodeRLP(q)
			}
			return q
		})
		p = t.HighExtend.EncodeRLP(p)
		return p
	})
}

func (t *TimeoutCertificate) DecodeRLP(s *rlp.Stream, ep decodeCtx) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := t.Epoch.DecodeRLP(l); err != nil {
		return err
	}
	if err := t.Round.DecodeRLP(l); err != nil {
		return err
	}
	trs, err := l.List()
	if err != nil {
		return err
	}
	t.TipRounds = nil
	for trs.Remaining() > 0 {
		var tr HighTipRoundSigColTuple
		if err := tr.DecodeRLP(trs); err != nil {
			return err
		}
		t.TipRounds = append(t.TipRounds, tr)
	}
	if len(t.TipRounds) > validator.MaxValidatorSetSize {
		return rlp.ErrUnexpectedLength
	}
	if err := t.HighExtend.DecodeRLP(l, ep); err != nil {
		return err
	}
	return l.Done()
}

// NewTimeoutCertificate — Rust TimeoutCertificate::new: group sigs by
// tminfo, aggregate per group, track highest high_extend.
func NewTimeoutCertificate(
	epoch types.Epoch,
	round types.Round,
	timeouts []struct {
		NodeId  types.NodeId
		Timeout Timeout
	},
	mapping *validator.ValidatorMapping,
) (*TimeoutCertificate, error) {
	highest := HighExtendQc(GenesisQC())
	// group by tminfo (preserving insertion order for deterministic output)
	groups := make(map[TimeoutInfo][]sigcol.NodeSig)
	var order []TimeoutInfo
	for _, tm := range timeouts {
		key := tm.Timeout.TmInfo
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], sigcol.NodeSig{NodeId: tm.NodeId, Sig: tm.Timeout.TimeoutSignature})
		if he := tm.Timeout.HighExtend.asHighExtend(); he.Rank().Cmp(highest.Rank()) > 0 {
			highest = he
		}
	}
	var tipRounds []HighTipRoundSigColTuple
	for _, ti := range order {
		digest := ti.EncodeRLP(nil)
		sc, err := sigcol.New(crypto.DomainTimeout, groups[ti], mapping, digest)
		if err != nil {
			return nil, err
		}
		tipRounds = append(tipRounds, HighTipRoundSigColTuple{
			HighQcRound:  ti.HighQcRound,
			HighTipRound: ti.HighTipRound,
			Sigs:         *sc,
		})
	}
	return &TimeoutCertificate{
		Epoch:      epoch,
		Round:      round,
		TipRounds:  tipRounds,
		HighExtend: highest,
	}, nil
}

// NoTipCertificate — Rust { epoch, round, tip_rounds, high_qc }.
type NoTipCertificate struct {
	Epoch     types.Epoch
	Round     types.Round
	TipRounds []HighTipRoundSigColTuple
	HighQc    QuorumCertificate
}

func (t NoTipCertificate) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = t.Epoch.EncodeRLP(p)
		p = t.Round.EncodeRLP(p)
		p = rlp.AppendList(p, func(q []byte) []byte {
			for _, tr := range t.TipRounds {
				q = tr.EncodeRLP(q)
			}
			return q
		})
		p = t.HighQc.EncodeRLP(p)
		return p
	})
}
