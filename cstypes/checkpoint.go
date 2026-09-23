package cstypes

import (
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// LockedEpoch — Rust checkpoint::LockedEpoch { epoch, round }.
type LockedEpoch struct {
	Epoch types.Epoch
	Round types.Round
}

func (l LockedEpoch) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = l.Epoch.EncodeRLP(p)
		p = l.Round.EncodeRLP(p)
		return p
	})
}

func (l *LockedEpoch) DecodeRLP(s *rlp.Stream) error {
	list, err := s.List()
	if err != nil {
		return err
	}
	if err := l.Epoch.DecodeRLP(list); err != nil {
		return err
	}
	if err := l.Round.DecodeRLP(list); err != nil {
		return err
	}
	return list.Done()
}

// MaxValidatorSets — Rust MAX_VALIDATOR_SETS.
const MaxValidatorSets = 4

// Checkpoint — Rust checkpoint::Checkpoint { root, high_certificate,
// validator_sets (LimitedVec<_, 4>) }.
type Checkpoint struct {
	Root            types.BlockId
	HighCertificate RoundCertificate
	ValidatorSets   []LockedEpoch
}

func (c Checkpoint) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = c.Root.EncodeRLP(p)
		p = c.HighCertificate.EncodeRLP(p)
		p = rlp.AppendList(p, func(q []byte) []byte {
			for _, le := range c.ValidatorSets {
				q = le.EncodeRLP(q)
			}
			return q
		})
		return p
	})
}

func (c *Checkpoint) DecodeRLP(s *rlp.Stream, ep *exec.Protocol) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	if err := c.Root.DecodeRLP(l); err != nil {
		return err
	}
	if err := c.HighCertificate.DecodeRLP(l, ep); err != nil {
		return err
	}
	les, err := l.List()
	if err != nil {
		return err
	}
	c.ValidatorSets = nil
	for les.Remaining() > 0 {
		var le LockedEpoch
		if err := le.DecodeRLP(les); err != nil {
			return err
		}
		c.ValidatorSets = append(c.ValidatorSets, le)
	}
	if len(c.ValidatorSets) > MaxValidatorSets {
		return rlp.ErrUnexpectedLength
	}
	return l.Done()
}
