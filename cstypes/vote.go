// Package cstypes ports monad-consensus-types: votes, certificates, tips,
// timeouts and block headers — all byte-identical to the Rust RLP encodings.
package cstypes

import (
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/sigcol"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Vote — Rust voting::Vote { id, round, epoch }.
type Vote struct {
	ID    types.BlockId
	Round types.Round
	Epoch types.Epoch
}

func (v Vote) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = v.ID.EncodeRLP(p)
		p = v.Round.EncodeRLP(p)
		p = v.Epoch.EncodeRLP(p)
		return p
	})
}

func (v *Vote) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := v.ID.DecodeRLP(l); err != nil {
		return err
	}
	if err := v.Round.DecodeRLP(l); err != nil {
		return err
	}
	if err := v.Epoch.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

// QuorumCertificate — Rust QuorumCertificate<SCT> { info: Vote, signatures: SCT }.
type QuorumCertificate struct {
	Info       Vote
	Signatures sigcol.BlsSignatureCollection
}

func GenesisQC() QuorumCertificate {
	return QuorumCertificate{
		Info: Vote{
			ID:    types.GENESIS_BLOCK_ID,
			Epoch: types.GENESIS_EPOCH,
			Round: types.GENESIS_ROUND,
		},
		Signatures: *sigcol.Empty(),
	}
}

func (q QuorumCertificate) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = q.Info.EncodeRLP(p)
		p = q.Signatures.EncodeRLP(p)
		return p
	})
}

func (q *QuorumCertificate) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := q.Info.DecodeRLP(l); err != nil {
		return err
	}
	if err := q.Signatures.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

func (q QuorumCertificate) GetRound() types.Round     { return q.Info.Round }
func (q QuorumCertificate) GetEpoch() types.Epoch     { return q.Info.Epoch }
func (q QuorumCertificate) GetBlockId() types.BlockId { return q.Info.ID }

// GetCommittableId — Rust QuorumCertificate::get_committable_id: if the QC's
// round is consecutive to the parent block's QC round, the parent's parent
// (qc_parent.qc.block_id) becomes committable — the pipelined 2-chain rule.
func (q QuorumCertificate) GetCommittableId(qcParent *ConsensusFullBlock) *types.BlockId {
	if q.GetBlockId() != qcParent.GetId() {
		panic("cstypes: qc doesn't point to parent block")
	}
	if q.Info.Round == qcParent.Header.QC.Info.Round+1 {
		id := qcParent.Header.QC.GetBlockId()
		return &id
	}
	return nil
}

// Rank — Rust quorum_certificate::Rank: compare by vote round only.
func (q QuorumCertificate) RankCmp(o QuorumCertificate) int {
	if q.Info.Round < o.Info.Round {
		return -1
	}
	if q.Info.Round > o.Info.Round {
		return 1
	}
	return 0
}

// TimestampAdjustmentDirection — Rust enum { Forward, Backward }.
type TimestampAdjustmentDirection uint8

const (
	TimestampAdjustForward TimestampAdjustmentDirection = iota
	TimestampAdjustBackward
)

// TimestampAdjustment — Rust quorum_certificate::TimestampAdjustment.
type TimestampAdjustment struct {
	Delta     types.U128
	Direction TimestampAdjustmentDirection
}

func (t TimestampAdjustment) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = t.Delta.EncodeRLP(p)
		p = rlp.AppendUint8(p, uint8(t.Direction))
		return p
	})
}
