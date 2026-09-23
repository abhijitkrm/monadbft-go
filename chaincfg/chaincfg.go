// Package chaincfg ports monad-chain-config: chain parameters and the
// revision schedule keyed by round.
package chaincfg

import (
	"time"

	"github.com/abhijitkrm/monadbft-go/types"
)

// Params — Rust ChainParams.
type Params struct {
	TxLimit           uint64
	ProposalGasLimit  uint64
	ProposalByteLimit uint64
	MaxReserveBalance [32]byte // U256
	VotePace          time.Duration
}

// Revision supplies the params in effect for a round. Rust ChainRevision.
type Revision interface {
	ChainParams() *Params
}

// Config resolves revisions by round. Rust ChainConfig.
type Config interface {
	GetChainRevision(round types.Round) Revision
}

// StaticConfig is a single-revision config — the common case pre-upgrade.
type StaticConfig struct {
	P Params
}

func (c StaticConfig) GetChainRevision(types.Round) Revision {
	return staticRevision{p: &c.P}
}

type staticRevision struct{ p *Params }

func (r staticRevision) ChainParams() *Params { return r.p }
