package swarm

import (
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// MockValSetUpdaterNop — port of monad-updaters::val_set::MockValSetUpdaterNop.
//
// Emits ValidatorEvent::UpdateValidators carrying the genesis validator set at
// every epoch boundary — the "nop" updater: membership never actually changes.
//
// Rust keeps a single next_val_data slot and overwrites (with an error log)
// when boundary notifications batch — losing intermediate epoch updates. That
// can happen on restart buffer-fill commits; here we queue them so no locked
// epoch's validator set is ever dropped.
type MockValSetUpdaterNop struct {
	genesisValidatorData glue.ValidatorSetData
	pending              []glue.ValidatorSetDataWithEpoch
	epochLength          types.SeqNum
	enableUpdates        bool
}

var _ EventSource = (*MockValSetUpdaterNop)(nil)

func NewMockValSetUpdaterNop(genesisValidatorData glue.ValidatorSetData, epochLength types.SeqNum) *MockValSetUpdaterNop {
	return &MockValSetUpdaterNop{
		genesisValidatorData: genesisValidatorData,
		epochLength:          epochLength,
		enableUpdates:        true,
	}
}

// WithUpdatesEnabled — Rust with_updates_enabled.
func (v *MockValSetUpdaterNop) WithUpdatesEnabled(on bool) *MockValSetUpdaterNop {
	v.enableUpdates = on
	return v
}

// jankUpdateValset — Rust jank_update_valset: at a boundary block, queue the
// genesis set for the newly-locked epoch.
func (v *MockValSetUpdaterNop) jankUpdateValset(seqNum types.SeqNum) {
	if !seqNum.IsBoundaryBlock(v.epochLength) {
		return
	}
	lockedEpoch := seqNum.GetLockedEpoch(v.epochLength)
	v.pending = append(v.pending, glue.ValidatorSetDataWithEpoch{
		Epoch:      lockedEpoch,
		Validators: v.genesisValidatorData,
	})
}

// Exec — Rust Executor::exec(ValSetCommand).
func (v *MockValSetUpdaterNop) Exec(cmds []glue.ValSetCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.ValSetNotifyFinalized:
			v.jankUpdateValset(c.SeqNum)
		}
	}
}

// Ready — Rust MockableValSetUpdater::ready.
func (v *MockValSetUpdaterNop) Ready() bool {
	return v.enableUpdates && len(v.pending) > 0
}

// GetValidatorSetData — Rust get_validator_set_data (always genesis set).
func (v *MockValSetUpdaterNop) GetValidatorSetData(_ types.Epoch) glue.ValidatorSetData {
	return v.genesisValidatorData
}

// Next — Rust Stream::next → MonadEvent::ValidatorEvent(UpdateValidators).
func (v *MockValSetUpdaterNop) Next() glue.MonadEvent {
	if !v.enableUpdates || len(v.pending) == 0 {
		return nil
	}
	data := v.pending[0]
	v.pending = v.pending[1:]
	return glue.EvUpdateValidators{ValidatorSetDataWithEpoch: data}
}
