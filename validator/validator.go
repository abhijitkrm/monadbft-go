// Package validator ports monad-validator: ValidatorSet (stake-weighted
// membership), ValidatorMapping (NodeId -> cert pubkey, sorted by NodeId),
// EpochManager, and the ChaCha20-seeded weighted round-robin leader election.
package validator

import (
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/types"
)

const MaxValidatorSetSize = 300

var (
	ErrEmptyValidatorSet  = errors.New("validator: empty validator set")
	ErrZeroStakeValidator = errors.New("validator: zero-stake validator")
	ErrDuplicateValidator = errors.New("validator: duplicate node id")
	ErrNotMember          = errors.New("validator: not a member")
)

// ValidatorSet mirrors Rust ValidatorSet<PT>: BTreeMap<NodeId, Stake> + total.
// Members are kept sorted by NodeId (compressed-pubkey order).
type ValidatorSet struct {
	members    []types.NodeId // sorted
	stakes     map[[33]byte]types.Stake
	totalStake types.Stake
}

// NewValidatorSet — Rust ValidatorSetFactory::create.
func NewValidatorSet(vals []ValidatorData) (*ValidatorSet, error) {
	if len(vals) == 0 {
		return nil, ErrEmptyValidatorSet
	}
	vs := &ValidatorSet{stakes: make(map[[33]byte]types.Stake)}
	var total types.Stake
	for _, v := range vals {
		if v.Stake.IsZero() {
			return nil, fmt.Errorf("%w: %s", ErrZeroStakeValidator, v.NodeId)
		}
		k := [33]byte(v.NodeId.PubKey)
		if _, dup := vs.stakes[k]; dup {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateValidator, v.NodeId)
		}
		vs.stakes[k] = v.Stake
		total = total.Add(v.Stake)
		vs.members = append(vs.members, v.NodeId)
	}
	sort.Slice(vs.members, func(i, j int) bool { return vs.members[i].Cmp(vs.members[j]) < 0 })
	vs.totalStake = total
	return vs, nil
}

// ValidatorData is a single validator entry (mirrors Rust ValidatorData).
type ValidatorData struct {
	NodeId     types.NodeId
	Stake      types.Stake
	CertPubKey crypto.BlsPubKey
}

func (v *ValidatorSet) Members() []types.NodeId { return v.members }
func (v *ValidatorSet) Len() int                { return len(v.members) }
func (v *ValidatorSet) TotalStake() types.Stake { return v.totalStake }

func (v *ValidatorSet) IsMember(id types.NodeId) bool {
	_, ok := v.stakes[[33]byte(id.PubKey)]
	return ok
}

// index returns the sorted position of id, or -1.
func (v *ValidatorSet) Index(id types.NodeId) int {
	i := sort.Search(len(v.members), func(i int) bool {
		return v.members[i].Cmp(id) >= 0
	})
	if i < len(v.members) && v.members[i].Cmp(id) == 0 {
		return i
	}
	return -1
}

// CalculateCurrentStake — Rust calculate_current_stake: errors on duplicate
// addrs, silently ignores non-members.
func (v *ValidatorSet) CalculateCurrentStake(addrs []types.NodeId) (types.Stake, error) {
	seen := make(map[[33]byte]struct{})
	var sum types.Stake
	for _, a := range addrs {
		k := [33]byte(a.PubKey)
		if _, dup := seen[k]; dup {
			return types.Stake{}, fmt.Errorf("%w: %s", ErrDuplicateValidator, a)
		}
		seen[k] = struct{}{}
		if s, ok := v.stakes[k]; ok {
			sum = sum.Add(s)
		}
	}
	return sum, nil
}

// HasSuperMajorityVotes: stake >= floor(2*total/3) + 1
func (v *ValidatorSet) HasSuperMajorityVotes(addrs []types.NodeId) (bool, error) {
	threshold := threshold(v.totalStake, 2, 3, true)
	return v.hasThresholdVotes(addrs, threshold)
}

// HasHonestVote: stake >= floor(total/3) + 1
func (v *ValidatorSet) HasHonestVote(addrs []types.NodeId) (bool, error) {
	threshold := threshold(v.totalStake, 1, 3, true)
	return v.hasThresholdVotes(addrs, threshold)
}

// threshold computes floor(total*num/den) + (1 if plusOne).
func threshold(total types.Stake, num, den int64, plusOne bool) types.Stake {
	t := total.Big()
	t.Mul(t, big.NewInt(num))
	t.Div(t, big.NewInt(den))
	if plusOne {
		t.Add(t, big.NewInt(1))
	}
	return types.StakeFromBig(t)
}

func (v *ValidatorSet) hasThresholdVotes(addrs []types.NodeId, thr types.Stake) (bool, error) {
	sum, err := v.CalculateCurrentStake(addrs)
	if err != nil {
		return false, err
	}
	return sum.Cmp(thr) >= 0, nil
}

// StakeOf returns the member's stake.
func (v *ValidatorSet) StakeOf(id types.NodeId) (types.Stake, bool) {
	s, ok := v.stakes[[33]byte(id.PubKey)]
	return s, ok
}

// ValidatorMapping mirrors Rust ValidatorMapping: BTreeMap<NodeId, cert_pubkey>
// — sorted iteration order is compressed-pubkey order of NodeId.
type ValidatorMapping struct {
	nodeIds []types.NodeId // sorted
	pubs    map[[33]byte]crypto.BlsPubKey
}

func NewValidatorMapping(entries []struct {
	NodeId     types.NodeId
	CertPubKey crypto.BlsPubKey
}) *ValidatorMapping {
	m := &ValidatorMapping{pubs: make(map[[33]byte]crypto.BlsPubKey)}
	for _, e := range entries {
		m.pubs[[33]byte(e.NodeId.PubKey)] = e.CertPubKey
		m.nodeIds = append(m.nodeIds, e.NodeId)
	}
	sort.Slice(m.nodeIds, func(i, j int) bool { return m.nodeIds[i].Cmp(m.nodeIds[j]) < 0 })
	return m
}

func (m *ValidatorMapping) Len() int { return len(m.nodeIds) }
func (m *ValidatorMapping) Has(id types.NodeId) bool {
	_, ok := m.pubs[[33]byte(id.PubKey)]
	return ok
}
func (m *ValidatorMapping) Index(id types.NodeId) int {
	i := sort.Search(len(m.nodeIds), func(i int) bool { return m.nodeIds[i].Cmp(id) >= 0 })
	if i < len(m.nodeIds) && m.nodeIds[i].Cmp(id) == 0 {
		return i
	}
	return -1
}
func (m *ValidatorMapping) PubKey(id types.NodeId) crypto.BlsPubKey {
	return m.pubs[[33]byte(id.PubKey)]
}
func (m *ValidatorMapping) At(i int) (types.NodeId, crypto.BlsPubKey) {
	n := m.nodeIds[i]
	return n, m.pubs[[33]byte(n.PubKey)]
}
func (m *ValidatorMapping) Entries() []types.NodeId { return m.nodeIds }
