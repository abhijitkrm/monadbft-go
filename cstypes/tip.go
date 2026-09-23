package cstypes

import (
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// ConsensusTip — Rust tip::ConsensusTip { block_header, signature,
// fresh_certificate(trailing) }. `signature` is the proposer's secp256k1
// signature over domain Tip || rlp(block_header).
type ConsensusTip struct {
	BlockHeader      ConsensusBlockHeader
	Signature        crypto.SecpSignature
	FreshCertificate *FreshProposalCertificate // trailing optional
}

func NewConsensusTip(keypair *crypto.SecpKeyPair, header ConsensusBlockHeader, freshCert *FreshProposalCertificate) ConsensusTip {
	sig := keypair.Sign(crypto.DomainTip, header.EncodeRLP(nil))
	return ConsensusTip{BlockHeader: header, Signature: sig, FreshCertificate: freshCert}
}

// SignatureAuthor recovers the proposer pubkey. Rust: signature_author.
func (t ConsensusTip) SignatureAuthor() (crypto.SecpPubKey, error) {
	return t.Signature.RecoverPubKey(crypto.DomainTip, t.BlockHeader.EncodeRLP(nil))
}

func (t ConsensusTip) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = t.BlockHeader.EncodeRLP(p)
		p = rlp.AppendString(p, t.Signature[:])
		if t.FreshCertificate != nil {
			p = t.FreshCertificate.EncodeRLP(p)
		}
		return p
	})
}

func (t *ConsensusTip) DecodeRLP(s *rlp.Stream, ep decodeCtx) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := t.BlockHeader.DecodeRLP(l, ep); err != nil {
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
	t.Signature = sig
	if l.Remaining() > 0 {
		var fc FreshProposalCertificate
		if err := fc.DecodeRLP(l, ep); err != nil {
			return err
		}
		t.FreshCertificate = &fc
	}
	return l.Done()
}

// GetRound — tip round = block_round of its header.
func (t ConsensusTip) GetRound() types.Round { return t.BlockHeader.BlockRound }
