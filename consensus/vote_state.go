package consensus

import (
	"errors"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/sigcol"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// RoundVoteState — Rust RoundVoteState<PT, ST>.
type roundVoteState struct {
	// pending votes keyed by Vote value; a node may appear in multiple
	// buckets (equivocation)
	pendingVotes  map[cstypes.Vote]map[[33]byte]voteEntry
	nodeVotes     map[[33]byte]map[[96]byte]struct{} // nodeid -> set of sigs
	invalidVoters map[[33]byte]struct{}
}

type voteEntry struct {
	nodeId types.NodeId
	sig    crypto.BlsSignature
}

func newRoundVoteState() *roundVoteState {
	return &roundVoteState{
		pendingVotes:  make(map[cstypes.Vote]map[[33]byte]voteEntry),
		nodeVotes:     make(map[[33]byte]map[[96]byte]struct{}),
		invalidVoters: make(map[[33]byte]struct{}),
	}
}

// VoteState ports Rust VoteState<SCT>: accumulates votes per round, forms a
// QC on the first supermajority.
type VoteState struct {
	pendingVotes  map[types.Round]*roundVoteState
	earliestRound types.Round
}

func NewVoteState(round types.Round) *VoteState {
	return &VoteState{
		earliestRound: round,
		pendingVotes:  make(map[types.Round]*roundVoteState),
	}
}

func (v *VoteState) EarliestRound() types.Round { return v.earliestRound }

// ProcessVote — Rust process_vote. Returns a QC when one is formed.
// (Commands omitted — Rust's are empty TODO placeholders.)
func (v *VoteState) ProcessVote(
	author types.NodeId,
	voteMsg *messages.VoteMessage,
	validators *validator.ValidatorSet,
	validatorMapping *validator.ValidatorMapping,
) *cstypes.QuorumCertificate {
	vote := voteMsg.Vote
	round := vote.Round

	if round < v.earliestRound {
		return nil
	}

	rs, ok := v.pendingVotes[round]
	if !ok {
		rs = newRoundVoteState()
		v.pendingVotes[round] = rs
	}
	authorKey := [33]byte(author.PubKey)

	nv := rs.nodeVotes[authorKey]
	if nv == nil {
		nv = make(map[[96]byte]struct{})
		rs.nodeVotes[authorKey] = nv
	}
	var sigKey [96]byte
	copy(sigKey[:], voteMsg.Sig.Compress())
	nv[sigKey] = struct{}{}
	// len(nv) > 1 => equivocation; TODO evidence

	rpv := rs.pendingVotes[vote]
	if rpv == nil {
		rpv = make(map[[33]byte]voteEntry)
		rs.pendingVotes[vote] = rpv
	}
	if _, bad := rs.invalidVoters[authorKey]; bad {
		return nil
	}
	rpv[authorKey] = voteEntry{nodeId: author, sig: voteMsg.Sig}

	for {
		addrs := make([]types.NodeId, 0, len(rpv))
		for _, e := range rpv {
			addrs = append(addrs, e.nodeId)
		}
		ok, err := validators.HasSuperMajorityVotes(addrs)
		if err != nil || !ok {
			break
		}
		voteEnc := vote.EncodeRLP(nil)
		var sigs []sigcol.NodeSig
		for _, e := range rpv {
			sigs = append(sigs, sigcol.NodeSig{NodeId: e.nodeId, Sig: e.sig})
		}
		sc, err := sigcol.New(crypto.DomainVote, sigs, validatorMapping, voteEnc)
		if err == nil {
			qc := cstypes.QuorumCertificate{Info: vote, Signatures: *sc}
			v.earliestRound = round + 1
			return &qc
		}
		// InvalidSignaturesCreate: drop the offending voters and retry
		if bad, ok := invalidSigVoters(err); ok {
			for _, n := range bad {
				rs.invalidVoters[[33]byte(n.PubKey)] = struct{}{}
				delete(rpv, [33]byte(n.PubKey))
			}
			continue
		}
		return nil
	}
	return nil
}

// invalidSigVoters extracts the offending NodeIds from a sigcol error.
func invalidSigVoters(err error) ([]types.NodeId, bool) {
	var isc *sigcol.InvalidSignaturesCreateError
	if errors.As(err, &isc) {
		return isc.NodeIds(), true
	}
	return nil, false
}

// StartNewRound — Rust start_new_round.
func (v *VoteState) StartNewRound(newRound types.Round) {
	v.earliestRound = newRound
	for r := range v.pendingVotes {
		if r < newRound {
			delete(v.pendingVotes, r)
		}
	}
}
