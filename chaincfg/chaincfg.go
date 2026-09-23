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
	// Epoch parameters — Rust ChainConfig::{get_epoch_length,
	// get_epoch_start_delay, get_staking_activation}.
	GetEpochLength() types.SeqNum
	GetEpochStartDelay() types.Round
	GetStakingActivation() types.Epoch
}

// StaticConfig is a single-revision config — the common case pre-upgrade.
// Mirrors Rust MockChainConfig (epoch_length/epoch_start_delay default to
// their MAX values; staking_activation to Epoch::MAX).
type StaticConfig struct {
	P Params

	EpochLength       types.SeqNum
	EpochStartDelay   types.Round
	StakingActivation types.Epoch
}

func (c StaticConfig) GetChainRevision(types.Round) Revision {
	return staticRevision{p: &c.P}
}

func (c StaticConfig) GetEpochLength() types.SeqNum      { return c.EpochLength }
func (c StaticConfig) GetEpochStartDelay() types.Round   { return c.EpochStartDelay }
func (c StaticConfig) GetStakingActivation() types.Epoch { return c.StakingActivation }

type staticRevision struct{ p *Params }

func (r staticRevision) ChainParams() *Params { return r.p }
