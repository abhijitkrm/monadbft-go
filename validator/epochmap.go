package validator

import (
	"github.com/abhijitkrm/monadbft-go/types"
)

// ValidatorsEpochMapping — Rust validators_epoch_mapping::ValidatorsEpochMapping:
// epoch -> (ValidatorSet, ValidatorMapping).
type ValidatorsEpochMapping struct {
	validatorMap map[types.Epoch]epochEntry
}

type epochEntry struct {
	valSet      *ValidatorSet
	certPubkeys *ValidatorMapping
}

func NewValidatorsEpochMapping() *ValidatorsEpochMapping {
	return &ValidatorsEpochMapping{validatorMap: make(map[types.Epoch]epochEntry)}
}

func (m *ValidatorsEpochMapping) GetValSet(epoch types.Epoch) (*ValidatorSet, bool) {
	e, ok := m.validatorMap[epoch]
	if !ok {
		return nil, false
	}
	return e.valSet, true
}

func (m *ValidatorsEpochMapping) GetCertPubkeys(epoch types.Epoch) (*ValidatorMapping, bool) {
	e, ok := m.validatorMap[epoch]
	if !ok {
		return nil, false
	}
	return e.certPubkeys, true
}

// Insert — Rust insert: on restart the same set may be inserted twice;
// asserts equality if the entry exists.
func (m *ValidatorsEpochMapping) Insert(
	epoch types.Epoch,
	valData []ValidatorData,
	certPubkeys *ValidatorMapping,
) {
	vs, err := NewValidatorSet(valData)
	if err != nil {
		panic("validator: ValidatorSetData has duplicates or invalid entries: " + err.Error())
	}
	if e, ok := m.validatorMap[epoch]; ok {
		if !equalMembers(e.valSet.members, vs.members) {
			panic("validator: validator set mismatch on re-insert")
		}
		if !equalMappings(e.certPubkeys, certPubkeys) {
			panic("validator: validator mapping mismatch on re-insert")
		}
		return
	}
	m.validatorMap[epoch] = epochEntry{valSet: vs, certPubkeys: certPubkeys}
}

func equalMembers(a, b []types.NodeId) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Cmp(b[i]) != 0 {
			return false
		}
	}
	return true
}

func equalMappings(a, b *ValidatorMapping) bool {
	return equalMembers(a.nodeIds, b.nodeIds)
}
