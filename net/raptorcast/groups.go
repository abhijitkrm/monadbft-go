package raptorcast

import (
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// Broadcast groups — ports monad-raptorcast util.rs group views and
// rebroadcast contexts (primary path only; secondary groups arrive with B5).

// validatorGroupMap — Rust ValidatorGroupMap: epoch → validator set.
type validatorGroupMap map[types.Epoch]*validator.ValidatorSet

// primaryBroadcastGroup — Rust PrimaryBroadcastGroup.
type primaryBroadcastGroup struct {
	epoch  types.Epoch
	author types.NodeId
	group  *validator.ValidatorSet
}

// primaryGroupOfEpoch — Rust PrimaryBroadcastGroup::of_epoch.
func primaryGroupOfEpoch(epoch types.Epoch, author types.NodeId, groups validatorGroupMap) (*primaryBroadcastGroup, error) {
	vs := groups[epoch]
	if vs == nil {
		return nil, ErrGroupNotFound
	}
	if !vs.IsMember(author) {
		return nil, ErrInvalidAuthor
	}
	return &primaryBroadcastGroup{epoch: epoch, author: author, group: vs}, nil
}

func (g *primaryBroadcastGroup) groupID() GroupId { return PrimaryGroup(g.epoch) }

func (g *primaryBroadcastGroup) isMember(id types.NodeId) bool {
	return g.group.IsMember(id)
}

// isSenderValid — Rust PrimaryBroadcastGroup::is_sender_valid: any group
// member may send.
func (g *primaryBroadcastGroup) isSenderValid(sender types.NodeId) bool {
	return g.isMember(sender)
}

// view exposes the send-side group view for chunk assignment.
func (g *primaryBroadcastGroup) view() *validatorGroupView {
	vs := g.group
	return &validatorGroupView{
		epoch:   g.epoch,
		author:  g.author,
		members: vs.Members(),
		stakeOf: func(id types.NodeId) types.Stake {
			s, _ := vs.StakeOf(id)
			return s
		},
	}
}

// tryRebroadcast — Rust PrimaryBroadcastGroup::try_rebroadcast: only a
// first-hop recipient member rebroadcasts, to all members except self and
// the author.
func (g *primaryBroadcastGroup) tryRebroadcast(selfID types.NodeId, isFirstHopRecipient bool) []types.NodeId {
	if !g.group.IsMember(selfID) || !isFirstHopRecipient {
		return nil
	}
	out := make([]types.NodeId, 0, g.group.Len())
	for _, m := range g.group.Members() {
		if m == selfID || m == g.author {
			continue
		}
		out = append(out, m)
	}
	return out
}
