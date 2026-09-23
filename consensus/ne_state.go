package consensus

import (
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/sigcol"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// roundNoEndorsementState — Rust RoundNoEndorsementState.
type roundNEState struct {
	// NEs keyed by tip_qc_round
	qcRoundNEs     map[types.Round]map[[33]byte]neEntry
	nodeNEs        map[[33]byte]map[[96]byte]struct{}
	invalidSenders map[[33]byte]struct{}
	certificate    *cstypes.NoEndorsementCertificate
}

type neEntry struct {
	nodeId types.NodeId
	sig    crypto.BlsSignature
}

func newRoundNEState() *roundNEState {
	return &roundNEState{
		qcRoundNEs:     make(map[types.Round]map[[33]byte]neEntry),
		nodeNEs:        make(map[[33]byte]map[[96]byte]struct{}),
		invalidSenders: make(map[[33]byte]struct{}),
	}
}

// NoEndorsementState — Rust NoEndorsementState<SCT>.
type NoEndorsementState struct {
	pending       map[types.Round]*roundNEState
	earliestRound types.Round
}

func NewNoEndorsementState(round types.Round) *NoEndorsementState {
	return &NoEndorsementState{
		earliestRound: round,
		pending:       make(map[types.Round]*roundNEState),
	}
}

// ProcessNoEndorsement — Rust process_no_endorsement. Caller must ensure
// NE.round == current_round. Returns the NEC when formed.
func (n *NoEndorsementState) ProcessNoEndorsement(
	author types.NodeId,
	msg *messages.NoEndorsementMessage,
	validators *validator.ValidatorSet,
	validatorMapping *validator.ValidatorMapping,
) *cstypes.NoEndorsementCertificate {
	ne := msg.Msg
	round := ne.Round

	if round < n.earliestRound {
		return nil
	}

	rs, ok := n.pending[round]
	if !ok {
		rs = newRoundNEState()
		n.pending[round] = rs
	}
	authorKey := [33]byte(author.PubKey)

	nv := rs.nodeNEs[authorKey]
	if nv == nil {
		nv = make(map[[96]byte]struct{})
		rs.nodeNEs[authorKey] = nv
	}
	var sigKey [96]byte
	copy(sigKey[:], msg.Signature.Compress())
	nv[sigKey] = struct{}{}

	rp := rs.qcRoundNEs[ne.TipQcRound]
	if rp == nil {
		rp = make(map[[33]byte]neEntry)
		rs.qcRoundNEs[ne.TipQcRound] = rp
	}
	if _, bad := rs.invalidSenders[authorKey]; bad {
		return nil
	}
	rp[authorKey] = neEntry{nodeId: author, sig: msg.Signature}

	for {
		addrs := make([]types.NodeId, 0, len(rp))
		for _, e := range rp {
			addrs = append(addrs, e.nodeId)
		}
		ok, err := validators.HasSuperMajorityVotes(addrs)
		if err != nil || !ok {
			break
		}
		neEnc := ne.EncodeRLP(nil)
		var sigs []sigcol.NodeSig
		for _, e := range rp {
			sigs = append(sigs, sigcol.NodeSig{NodeId: e.nodeId, Sig: e.sig})
		}
		sc, err := sigcol.New(crypto.DomainNoEndorsement, sigs, validatorMapping, neEnc)
		if err == nil {
			nec := &cstypes.NoEndorsementCertificate{Msg: ne, Signatures: *sc}
			n.earliestRound = round + 1
			rs.certificate = nec
			return nec
		}
		if bad, ok := invalidSigVoters(err); ok {
			for _, id := range bad {
				rs.invalidSenders[[33]byte(id.PubKey)] = struct{}{}
				delete(rp, [33]byte(id.PubKey))
			}
			continue
		}
		return nil
	}
	return nil
}

// StartNewRound — Rust start_new_round (earliest_round is monotone).
func (n *NoEndorsementState) StartNewRound(newRound types.Round) {
	if newRound > n.earliestRound {
		n.earliestRound = newRound
	}
	for r := range n.pending {
		if r < newRound {
			delete(n.pending, r)
		}
	}
}

func (n *NoEndorsementState) GetNec(round types.Round) *cstypes.NoEndorsementCertificate {
	rs, ok := n.pending[round]
	if !ok {
		return nil
	}
	return rs.certificate
}
