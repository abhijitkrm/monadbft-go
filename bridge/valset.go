package bridge

import (
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/swarm"
	"github.com/abhijitkrm/monadbft-go/types"
)

// ValSet — swarm.ValSetUpdater fed by the app's validator set: at each epoch
// boundary commit it snapshots the app's canonical set (genesis + applied
// ValidatorUpdates) into an EvUpdateValidators for the newly-locked epoch.
type ValSet struct {
	app         *App
	epochLength types.SeqNum

	pending []glue.ValidatorSetDataWithEpoch
	byEpoch map[types.Epoch]glue.ValidatorSetData // history for GetValidatorSetData
}

var _ swarm.ValSetUpdater = (*ValSet)(nil)

func NewValSet(app *App, epochLength types.SeqNum) (*ValSet, error) {
	v := &ValSet{app: app, epochLength: epochLength, byEpoch: map[types.Epoch]glue.ValidatorSetData{}}
	// seed genesis epochs with the initial set (same set until updates apply)
	data, err := app.ValidatorSetData()
	if err != nil {
		return nil, err
	}
	v.byEpoch[types.Epoch(1)] = data
	v.byEpoch[types.Epoch(2)] = data
	return v, nil
}

// Exec — ValSetCommand dispatch.
func (v *ValSet) Exec(cmds []glue.ValSetCommand) {
	for _, cmd := range cmds {
		if c, ok := cmd.(glue.ValSetNotifyFinalized); ok {
			v.notifyFinalized(c.SeqNum)
		}
	}
}

// notifyFinalized — at a boundary block the app set snapshot becomes the
// validator data for the newly-locked epoch (GetLockedEpoch semantics).
func (v *ValSet) notifyFinalized(seqNum types.SeqNum) {
	if !seqNum.IsBoundaryBlock(v.epochLength) {
		return
	}
	lockedEpoch := seqNum.GetLockedEpoch(v.epochLength)
	data, err := v.app.ValidatorSetData()
	if err != nil {
		panic(err)
	}
	v.byEpoch[lockedEpoch] = data
	v.pending = append(v.pending, glue.ValidatorSetDataWithEpoch{
		Epoch:      lockedEpoch,
		Validators: data,
	})
}

// GetValidatorSetData — serve the recorded set for an epoch (falls back to
// the app's current set for epochs not yet locked).
func (v *ValSet) GetValidatorSetData(epoch types.Epoch) glue.ValidatorSetData {
	if d, ok := v.byEpoch[epoch]; ok {
		return d
	}
	d, err := v.app.ValidatorSetData()
	if err != nil {
		return glue.ValidatorSetData{}
	}
	return d
}

func (v *ValSet) Ready() bool { return len(v.pending) > 0 }

func (v *ValSet) Next() glue.MonadEvent {
	if len(v.pending) == 0 {
		return nil
	}
	ev := v.pending[0]
	v.pending = v.pending[1:]
	return glue.EvUpdateValidators{ValidatorSetDataWithEpoch: ev}
}
