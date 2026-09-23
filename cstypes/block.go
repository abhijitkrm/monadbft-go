package cstypes

import (
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/zeebo/blake3"
)

const MaxDelayedResults = 4

// ConsensusBlockBodyId — Rust payload::ConsensusBlockBodyId(Hash).
type ConsensusBlockBodyId = types.Hash

// RoundSignature — Rust payload::RoundSignature<CST>: BLS sig over
// domain RoundSignature || rlp(round).
type RoundSignature = crypto.BlsSignature

func NewRoundSignature(round types.Round, kp *crypto.BlsKeyPair) RoundSignature {
	return kp.Sign(crypto.DomainRoundSignature, round.EncodeRLP(nil))
}

func VerifyRoundSignature(sig RoundSignature, round types.Round, pk crypto.BlsPubKey) bool {
	return sig.Verify(crypto.DomainRoundSignature, round.EncodeRLP(nil), pk)
}

// ConsensusBlockHeader — Rust ConsensusBlockHeader<ST,SCT,EPT>.
// RLP field order: block_round, epoch, qc, author, seq_num, timestamp_ns,
// round_signature, delayed_execution_results, execution_inputs,
// block_body_id, base_fee, base_fee_trend, base_fee_moment.
type ConsensusBlockHeader struct {
	BlockRound              types.Round
	Epoch                   types.Epoch
	QC                      QuorumCertificate
	Author                  types.NodeId
	SeqNum                  types.SeqNum
	TimestampNs             types.U128
	RoundSignature          RoundSignature
	DelayedExecutionResults []exec.FinalizedHeader // LimitedVec<_,4>
	ExecutionInputs         exec.ProposedHeader
	BlockBodyId             ConsensusBlockBodyId
	BaseFee                 uint64
	BaseFeeTrend            uint64
	BaseFeeMoment           uint64
}

// NewConsensusBlockHeader — Rust ConsensusBlockHeader::new (arg order preserved).
func NewConsensusBlockHeader(
	author types.NodeId,
	epoch types.Epoch,
	blockRound types.Round,
	delayedExecutionResults []exec.FinalizedHeader,
	executionInputs exec.ProposedHeader,
	blockBodyId ConsensusBlockBodyId,
	qc QuorumCertificate,
	seqNum types.SeqNum,
	timestampNs types.U128,
	roundSignature RoundSignature,
	baseFee, baseFeeTrend, baseFeeMoment uint64,
) ConsensusBlockHeader {
	return ConsensusBlockHeader{
		Author:                  author,
		Epoch:                   epoch,
		BlockRound:              blockRound,
		DelayedExecutionResults: delayedExecutionResults,
		ExecutionInputs:         executionInputs,
		BlockBodyId:             blockBodyId,
		QC:                      qc,
		SeqNum:                  seqNum,
		TimestampNs:             timestampNs,
		RoundSignature:          roundSignature,
		BaseFee:                 baseFee,
		BaseFeeTrend:            baseFeeTrend,
		BaseFeeMoment:           baseFeeMoment,
	}
}

func (h ConsensusBlockHeader) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = h.BlockRound.EncodeRLP(p)
		p = h.Epoch.EncodeRLP(p)
		p = h.QC.EncodeRLP(p)
		p = h.Author.EncodeRLP(p)
		p = h.SeqNum.EncodeRLP(p)
		p = h.TimestampNs.EncodeRLP(p)
		p = rlp.AppendString(p, h.RoundSignature.Compress())
		p = rlp.AppendList(p, func(q []byte) []byte {
			for _, fh := range h.DelayedExecutionResults {
				q = fh.EncodeRLP(q)
			}
			return q
		})
		p = h.ExecutionInputs.EncodeRLP(p)
		p = rlp.AppendString(p, h.BlockBodyId[:])
		p = rlp.AppendUint64(p, h.BaseFee)
		p = rlp.AppendUint64(p, h.BaseFeeTrend)
		p = rlp.AppendUint64(p, h.BaseFeeMoment)
		return p
	})
}

// DecodeRLP — needs the protocol factory for EPT-typed fields.
func (h *ConsensusBlockHeader) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := h.BlockRound.DecodeRLP(l); err != nil {
		return err
	}
	if err := h.Epoch.DecodeRLP(l); err != nil {
		return err
	}
	if err := h.QC.DecodeRLP(l); err != nil {
		return err
	}
	if err := h.Author.DecodeRLP(l); err != nil {
		return err
	}
	if err := h.SeqNum.DecodeRLP(l); err != nil {
		return err
	}
	if err := h.TimestampNs.DecodeRLP(l); err != nil {
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
	h.RoundSignature = sig

	resList, err := l.List()
	if err != nil {
		return err
	}
	h.DelayedExecutionResults = nil
	for resList.Remaining() > 0 {
		fh := ep.NewFinalizedHeader()
		if err := fh.DecodeRLP(resList); err != nil {
			return err
		}
		h.DelayedExecutionResults = append(h.DelayedExecutionResults, fh)
	}
	if len(h.DelayedExecutionResults) > MaxDelayedResults {
		return rlp.ErrUnexpectedLength
	}

	h.ExecutionInputs = ep.NewProposedHeader()
	if err := h.ExecutionInputs.DecodeRLP(l); err != nil {
		return err
	}
	bid, err := l.FixedBytes(32)
	if err != nil {
		return err
	}
	copy(h.BlockBodyId[:], bid)
	if h.BaseFee, err = l.Uint64(); err != nil {
		return err
	}
	if h.BaseFeeTrend, err = l.Uint64(); err != nil {
		return err
	}
	if h.BaseFeeMoment, err = l.Uint64(); err != nil {
		return err
	}
	return l.Done()
}

// GetId = blake3(rlp(header)). Rust: ConsensusBlockHeader::get_id.
func (h ConsensusBlockHeader) GetId() types.BlockId {
	return types.BlockId(blake3.Sum256(h.EncodeRLP(nil)))
}

func (h ConsensusBlockHeader) GetParentId() types.BlockId { return h.QC.GetBlockId() }

// ConsensusBlockBodyInner — Rust ConsensusBlockBodyInner { execution_body }.
type ConsensusBlockBodyInner struct {
	ExecutionBody exec.Body
}

func (b ConsensusBlockBodyInner) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		return b.ExecutionBody.EncodeRLP(p)
	})
}

// ConsensusBlockBody — transparent RLP wrapper over the inner struct.
type ConsensusBlockBody struct {
	Inner ConsensusBlockBodyInner
}

func (b ConsensusBlockBody) EncodeRLP(dst []byte) []byte { return b.Inner.EncodeRLP(dst) }

func (b *ConsensusBlockBody) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	b.Inner.ExecutionBody = ep.NewBody()
	if err := b.Inner.ExecutionBody.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}

func (b ConsensusBlockBody) GetId() ConsensusBlockBodyId {
	return blake3.Sum256(b.EncodeRLP(nil))
}

// ConsensusFullBlock — Rust ConsensusFullBlock { header, body }.
type ConsensusFullBlock struct {
	Header ConsensusBlockHeader
	Body   ConsensusBlockBody
}

func NewFullBlock(h ConsensusBlockHeader, b ConsensusBlockBody) (ConsensusFullBlock, error) {
	if b.GetId() != h.BlockBodyId {
		return ConsensusFullBlock{}, errHeaderPayloadMismatch
	}
	return ConsensusFullBlock{Header: h, Body: b}, nil
}

var errHeaderPayloadMismatch = errStr("header payload mismatch")

type errStr string

func (e errStr) Error() string { return string(e) }

func (b ConsensusFullBlock) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = b.Header.EncodeRLP(p)
		p = b.Body.EncodeRLP(p)
		return p
	})
}

func (b ConsensusFullBlock) GetId() types.BlockId       { return b.Header.GetId() }
func (b ConsensusFullBlock) GetParentId() types.BlockId { return b.Header.GetParentId() }
func (b ConsensusFullBlock) GetSeqNum() types.SeqNum    { return b.Header.SeqNum }
func (b ConsensusFullBlock) GetBlockRound() types.Round { return b.Header.BlockRound }
func (b ConsensusFullBlock) GetEpoch() types.Epoch      { return b.Header.Epoch }
func (b ConsensusFullBlock) GetTimestamp() types.U128   { return b.Header.TimestampNs }
func (b ConsensusFullBlock) GetBodyId() ConsensusBlockBodyId {
	return b.Body.GetId()
}
func (b ConsensusFullBlock) GetExecutionResults() []exec.FinalizedHeader {
	return b.Header.DelayedExecutionResults
}

// BlockRange — Rust BlockRange { last_block_id, num_blocks }.
type BlockRange struct {
	LastBlockId types.BlockId
	NumBlocks   types.SeqNum
}

func (r BlockRange) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = r.LastBlockId.EncodeRLP(p)
		p = r.NumBlocks.EncodeRLP(p)
		return p
	})
}

func (r *BlockRange) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := r.LastBlockId.DecodeRLP(l); err != nil {
		return err
	}
	if err := r.NumBlocks.DecodeRLP(l); err != nil {
		return err
	}
	return l.Done()
}
