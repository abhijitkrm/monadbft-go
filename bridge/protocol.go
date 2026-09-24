// Package bridge wires MonadBFT to a Cosmos SDK ABCI application (evmd).
//
// The bridge replaces the swarm's mock executors with ABCI-backed ones:
// LedgerCommit{Finalized} drives app.FinalizeBlock+Commit, proposal creation
// drives app.ReapTxs+PrepareProposal, tx submission drives CheckTx+InsertTx,
// and epoch boundaries consume the app's ValidatorUpdates. The consensus
// core, wire formats, and deterministic scheduler are unchanged — only the
// executor seam is swapped.
//
// Execution is synchronous: a block's txs execute when consensus finalizes
// it (the 2-chain commit rule), and the resulting app hash is bound into
// consensus via EvmFinalizedHeader delayed-execution-results.
package bridge

import (
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Evm — the exec.Protocol for the ABCI/EVM lane.
var Evm = &exec.Protocol{
	NewProposedHeader:  func() exec.ProposedHeader { return &EvmProposedHeader{} },
	NewBody:            func() exec.Body { return &EvmBody{} },
	NewFinalizedHeader: func() exec.FinalizedHeader { return &EvmFinalizedHeader{} },
}

// EvmProposedHeader — minimal: the consensus header already carries the
// seqnum/timestamp/author that RequestFinalizeBlock needs; nothing extra is
// required on the execution lane.
type EvmProposedHeader struct{}

func (EvmProposedHeader) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte { return p })
}
func (*EvmProposedHeader) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	return l.Done()
}

// EvmBody — the block body is a tx list (SDK-encoded tx bytes), mirroring
// EthBlockBody's `transactions` shape: RLP list of byte strings.
type EvmBody struct {
	Txs [][]byte
}

func (b EvmBody) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		for _, tx := range b.Txs {
			p = rlp.AppendString(p, tx)
		}
		return p
	})
}

func (b *EvmBody) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	for l.Remaining() > 0 {
		tx, err := l.Bytes()
		if err != nil {
			return err
		}
		b.Txs = append(b.Txs, append([]byte(nil), tx...))
	}
	return l.Done()
}

// EvmFinalizedHeader — the delayed execution result bound into later headers:
// the app hash the application committed at seq_num.
type EvmFinalizedHeader struct {
	Number  types.SeqNum
	AppHash []byte
}

func (h EvmFinalizedHeader) SeqNum() types.SeqNum { return h.Number }

func (h EvmFinalizedHeader) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = h.Number.EncodeRLP(p)
		return rlp.AppendString(p, h.AppHash)
	})
}

func (h *EvmFinalizedHeader) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := h.Number.DecodeRLP(l); err != nil {
		return err
	}
	ah, err := l.Bytes()
	if err != nil {
		return err
	}
	h.AppHash = append([]byte(nil), ah...)
	return l.Done()
}
