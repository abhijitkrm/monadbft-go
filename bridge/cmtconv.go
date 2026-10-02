package bridge

import (
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtversion "github.com/cometbft/cometbft/proto/tendermint/version"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cometbft/cometbft/version"

	"github.com/abhijitkrm/monadbft-go/cstypes"
)

// cmtconv — synthesizes CometBFT wire types from committed bridge state.
// These are the transitional protocol the engine seam speaks: consumers
// (json-rpc backend, indexer, mempool, gRPC services) all read
// coretypes/cmttypes today, so a monadbft node fabricates them from its
// committed blocks + result index.

// synthHeader — comet-shaped block header for a committed consensus block.
// Merkle hashes are computed over the real data (txs, valsets, results) so
// block.Hash() is self-consistent for the chain.
func (a *App) synthHeader(b *cstypes.ConsensusFullBlock) cmttypes.Header {
	h := b.Header
	seq := int64(h.SeqNum.Uint64())

	var appHash []byte
	var lastResultsHash []byte
	if e, _, _, _, _, _, ok := a.CommittedEntry(seq); ok && e != nil {
		appHash = e.AppHash
	}
	if seq > 1 {
		if _, _, _, txRes, _, _, ok := a.CommittedEntry(seq - 1); ok {
			lastResultsHash = cmttypes.NewResults(txRes).Hash()
		}
	}

	var dataHash []byte
	if body, ok := b.Body.Inner.ExecutionBody.(*EvmBody); ok && len(body.Txs) > 0 {
		dataHash = toCmtTxs(body.Txs).Hash()
	}

	var valHash, nextValHash, consHash []byte
	if vs := a.ValSetAt(seq); vs != nil {
		valHash = vs.Hash()
	}
	if vs := a.valSetAfter(seq); vs != nil {
		nextValHash = vs.Hash()
	}
	if a.consParams != nil {
		consHash = cmttypes.ConsensusParamsFromProto(*a.consParams).Hash()
	}

	parentID := h.GetParentId()
	return cmttypes.Header{
		Version: cmtversion.Consensus{Block: version.BlockProtocol, App: 0},
		ChainID: a.chainID,
		Height:  seq,
		Time:    time.Unix(0, int64(h.TimestampNs.Uint64())).UTC(),
		LastBlockID: cmttypes.BlockID{
			Hash:          parentID[:],
			PartSetHeader: cmttypes.PartSetHeader{Total: 1, Hash: parentID[:]},
		},
		LastCommitHash:     qcHash(h.QC),
		DataHash:           dataHash,
		ValidatorsHash:     valHash,
		NextValidatorsHash: nextValHash,
		ConsensusHash:      consHash,
		AppHash:            appHash,
		LastResultsHash:    lastResultsHash,
		ProposerAddress:    a.ConsAddr(h.Author),
	}
}

// synthCommit — the commit cert embedded in block b for its parent (b's QC).
// Signer bitmap is QC-aggregated — per-validator signatures don't exist in
// the BLS aggregate, so Commit-flagged entries carry an empty signature.
func (a *App) synthCommit(b *cstypes.ConsensusFullBlock) *cmttypes.Commit {
	h := b.Header
	parentSeq := int64(h.SeqNum.Uint64()) - 1
	commit := &cmttypes.Commit{
		Height: parentSeq,
		Round:  int32(h.QC.Info.Round.Uint64()),
	}
	parentID := h.GetParentId()
	commit.BlockID = cmttypes.BlockID{
		Hash:          parentID[:],
		PartSetHeader: cmttypes.PartSetHeader{Total: 1, Hash: parentID[:]},
	}
	vs := a.ValSetAt(parentSeq)
	if vs == nil {
		return commit
	}
	commit.Signatures = make([]cmttypes.CommitSig, len(vs.Validators))
	ts := time.Unix(0, int64(h.TimestampNs.Uint64())).UTC()
	for i, v := range vs.Validators {
		sig := cmttypes.CommitSig{
			BlockIDFlag:      cmttypes.BlockIDFlagAbsent,
			ValidatorAddress: v.Address,
			Timestamp:        ts,
		}
		if mi, ok := a.byCons[string(v.Address)]; ok &&
			mi < h.QC.Signatures.Signers.Len() && h.QC.Signatures.Signers.Bits[mi] {
			sig.BlockIDFlag = cmttypes.BlockIDFlagCommit
		}
		commit.Signatures[i] = sig
	}
	return commit
}

// SynthBlock — a full comet-shaped block for a committed consensus block.
func (a *App) SynthBlock(b *cstypes.ConsensusFullBlock) *cmttypes.Block {
	blk := &cmttypes.Block{
		Header:   a.synthHeader(b),
		Data:     cmttypes.Data{},
		Evidence: cmttypes.EvidenceData{},
	}
	if body, ok := b.Body.Inner.ExecutionBody.(*EvmBody); ok {
		blk.Data.Txs = toCmtTxs(body.Txs)
	}
	if blk.Header.Height > 1 {
		blk.LastCommit = a.synthCommit(b)
	} else {
		blk.LastCommit = &cmttypes.Commit{}
	}
	return blk
}

// SynthBlockResults — ResultBlockResults-equivalent fields for a height.
func (a *App) SynthBlockResults(seq int64) (txRes []*abcitypes.ExecTxResult,
	events []abcitypes.Event, updates []abcitypes.ValidatorUpdate, ok bool) {
	_, _, _, txRes, events, updates, ok = a.CommittedEntry(seq)
	return
}

// valSetAfter — the canonical set after seq's updates (validates seq+1).
func (a *App) valSetAfter(h int64) *cmttypes.ValidatorSet {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vs, ok := a.valSets[h]; ok {
		return vs
	}
	return a.lastValSet
}

// qcHash — a deterministic stand-in for LastCommitHash: comet hashes the
// commit's signature set; the QC's RLP encoding plays the same role here.
func qcHash(qc cstypes.QuorumCertificate) []byte {
	enc := qc.EncodeRLP(nil)
	if len(enc) == 0 {
		return nil
	}
	return tmhash.Sum(enc)
}

// toCmtTxs — raw tx bytes → comet Tx slice (shared backing; no copy).
func toCmtTxs(txs [][]byte) cmttypes.Txs {
	out := make(cmttypes.Txs, len(txs))
	for i, tx := range txs {
		out[i] = cmttypes.Tx(tx)
	}
	return out
}
