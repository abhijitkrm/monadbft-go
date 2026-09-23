package monadstate

import (
	"errors"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validation"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// DbSyncStatus — Rust monad-state::DbSyncStatus.
type DbSyncStatus int

const (
	DbSyncWaiting DbSyncStatus = iota
	DbSyncStarted
	DbSyncDone
)

// STATESYNC_BLOCK_THRESHOLD — Rust monad_state::STATESYNC_BLOCK_THRESHOLD.
const statesyncBlockThreshold = types.SeqNum(30_000)

// Forkpoint — Rust monad-state::Forkpoint: a Checkpoint that consensus
// restarts from.
type Forkpoint struct {
	Checkpoint cstypes.Checkpoint
}

// ForkpointGenesis — Rust Forkpoint::genesis.
func ForkpointGenesis() Forkpoint {
	qc := cstypes.GenesisQC()
	return Forkpoint{Checkpoint: cstypes.Checkpoint{
		Root:            types.GENESIS_BLOCK_ID,
		HighCertificate: cstypes.RoundCertificate{QC: &qc, IsQC: true},
		ValidatorSets:   []cstypes.LockedEpoch{{Epoch: types.Epoch(1), Round: types.GENESIS_ROUND}},
	}}
}

// GetEpochStarts — Rust Forkpoint::get_epoch_starts.
func (f Forkpoint) GetEpochStarts() map[types.Epoch]types.Round {
	out := make(map[types.Epoch]types.Round, len(f.Checkpoint.ValidatorSets))
	for _, le := range f.Checkpoint.ValidatorSets {
		out[le.Epoch] = le.Round
	}
	return out
}

// ForkpointValidationError — Rust ForkpointValidationError.
type ForkpointValidationError int

const (
	FpErrTooFewValidatorSets ForkpointValidationError = iota + 1
	FpErrTooManyValidatorSets
	FpErrValidatorSetsNotConsecutive
	FpErrInvalidValidatorSetStartEpoch
	FpErrInvalidQC
	FpErrInvalidHighCertificate
)

func (e ForkpointValidationError) Error() string {
	return [...]string{
		"too few validator sets", "too many validator sets",
		"validator sets not consecutive", "invalid validator set start epoch",
		"invalid qc", "invalid high certificate",
	}[e-1]
}

// Validate — Rust Forkpoint::validate.
//  1. 1 <= validator_sets.len() <= 2
//  2. validator_sets consecutive epochs, increasing start rounds
//  3. high_certificate verifies against the matching epoch's validator set
func (f Forkpoint) Validate(
	lockedValidatorSets []glue.ValidatorSetDataWithEpoch,
	election validator.LeaderElection,
) error {
	vsets := f.Checkpoint.ValidatorSets
	if len(vsets) == 0 {
		return FpErrTooFewValidatorSets
	}
	if len(vsets) > 2 {
		return FpErrTooManyValidatorSets
	}
	if len(vsets) != len(lockedValidatorSets) {
		panic("monadstate: locked_validator_sets must correspond 1:1 with checkpoint validator_sets")
	}
	for i := 0; i+1 < len(vsets); i++ {
		if !(vsets[i].Epoch+1 == vsets[i+1].Epoch && vsets[i].Round < vsets[i+1].Round) {
			return FpErrValidatorSetsNotConsecutive
		}
	}
	for i, locked := range lockedValidatorSets {
		if locked.Epoch != vsets[i].Epoch {
			panic("monadstate: locked epoch does not match forkpoint epoch")
		}
	}

	// epoch -> (vset, vmap)
	validators := make(map[types.Epoch]struct {
		vset *validator.ValidatorSet
		vmap *validator.ValidatorMapping
	})
	for _, locked := range lockedValidatorSets {
		var valData []validator.ValidatorData
		var mapEntries []struct {
			NodeId     types.NodeId
			CertPubKey crypto.BlsPubKey
		}
		for _, vd := range locked.Validators.Validators {
			pk, err := crypto.BlsPubKeyUncompress(vd.CertPubKey[:])
			if err != nil {
				return err
			}
			valData = append(valData, validator.ValidatorData{
				NodeId: vd.NodeId, Stake: vd.Stake, CertPubKey: pk,
			})
			mapEntries = append(mapEntries, struct {
				NodeId     types.NodeId
				CertPubKey crypto.BlsPubKey
			}{vd.NodeId, pk})
		}
		vset, err := validator.NewValidatorSet(valData)
		if err != nil {
			return err
		}
		validators[locked.Epoch] = struct {
			vset *validator.ValidatorSet
			vmap *validator.ValidatorMapping
		}{vset, validator.NewValidatorMapping(mapEntries)}
	}

	e2v := func(epoch types.Epoch, round types.Round) (*validator.ValidatorSet, *validator.ValidatorMapping, types.NodeId, error) {
		v, ok := validators[epoch]
		if !ok {
			return nil, nil, types.NodeId{}, validation.ErrValidatorSetDataUnavailable
		}
		return v.vset, v.vmap, election.GetLeader(round, v.vset), nil
	}

	certCache := validation.NewCertificateCache()
	hc := f.Checkpoint.HighCertificate
	if hc.IsQC {
		if err := validation.VerifyQC(certCache, e2v, hc.QC); err != nil {
			return FpErrInvalidQC
		}
	} else {
		if err := validation.VerifyTC(certCache, e2v, hc.TC); err != nil {
			return FpErrInvalidHighCertificate
		}
	}
	return nil
}

var _ = errors.New // silence unused if errors not otherwise needed
