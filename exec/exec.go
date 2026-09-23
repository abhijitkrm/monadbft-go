// Package exec defines the ExecutionProtocol seam ported from monad-types.
// Consensus headers embed three protocol-owned types; in Go we express
// them as interfaces plus a Protocol factory used by decoders.
package exec

import (
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// ProposedHeader is the protocol's per-proposal header payload.
type ProposedHeader interface {
	rlp.Encodable
	DecodeRLP(*rlp.Stream) error
}

// Body is the protocol's block-body payload.
type Body interface {
	rlp.Encodable
	DecodeRLP(*rlp.Stream) error
}

// FinalizedHeader is a committed execution result embedded in later headers.
type FinalizedHeader interface {
	rlp.Encodable
	DecodeRLP(*rlp.Stream) error
	SeqNum() types.SeqNum
}

// Protocol supplies fresh zero values for decoding — the Go equivalent of
// Rust's EPT type parameter.
type Protocol struct {
	NewProposedHeader  func() ProposedHeader
	NewBody            func() Body
	NewFinalizedHeader func() FinalizedHeader
}
