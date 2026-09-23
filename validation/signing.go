// Package validation ports monad-consensus/src/validation: the signature +
// structural validation pipeline for inbound consensus messages
// (verify → author check → version → prefilter → validate) and the
// QC/TC/NEC/tip certificate verifiers with their caches.
package validation

import (
	"bytes"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// Error — Rust monad_consensus_types::validation::Error.
type Error int

const (
	// signed by an author not in the validator set
	ErrInvalidAuthor Error = iota + 1
	// improper QC or TC values
	ErrNotWellFormed
	// bad signature
	ErrInvalidSignature
	// high qc rounds larger than the TC round
	ErrInvalidTcRound
	// duplicate (tip_round, high_qc_round) in the TC
	ErrDuplicateTcTipRound
	// empty signers for a (tip_round, high_qc_round) in the TC
	ErrEmptySignersTcTipRound
	// too many (tip_round, high_qc_round) in the TC
	ErrTooManyTcTipRound
	// signature collection lacks supermajority stake
	ErrInsufficientStake
	// required validator set / cert pubkeys not in the epoch mapping
	ErrValidatorSetDataUnavailable
	// signatures contain duplicate node id
	ErrSignaturesDuplicateNode
	// vote lacks a valid commit condition
	ErrInvalidVote
	// consensus message version mismatch
	ErrInvalidVersion
	// epoch number doesn't match local records
	ErrInvalidEpoch
)

func (e Error) Error() string {
	switch e {
	case ErrInvalidAuthor:
		return "InvalidAuthor"
	case ErrNotWellFormed:
		return "NotWellFormed"
	case ErrInvalidSignature:
		return "InvalidSignature"
	case ErrInvalidTcRound:
		return "InvalidTcRound"
	case ErrDuplicateTcTipRound:
		return "DuplicateTcTipRound"
	case ErrEmptySignersTcTipRound:
		return "EmptySignersTcTipRound"
	case ErrTooManyTcTipRound:
		return "TooManyTcTipRound"
	case ErrInsufficientStake:
		return "InsufficientStake"
	case ErrValidatorSetDataUnavailable:
		return "ValidatorSetDataUnavailable"
	case ErrSignaturesDuplicateNode:
		return "SignaturesDuplicateNode"
	case ErrInvalidVote:
		return "InvalidVote"
	case ErrInvalidVersion:
		return "InvalidVersion"
	case ErrInvalidEpoch:
		return "InvalidEpoch"
	}
	return "validation error"
}

// PrefilterError — Rust PrefilterError.
type PrefilterError int

const (
	PrefilterNone PrefilterError = iota
	OutdatedProposal
	OutdatedVote
	OutdatedTimeout
	OutdatedRoundRecovery
	OutdatedNoEndorsement
	OutdatedAdvanceRoundQc
	OutdatedAdvanceRoundTc
)

func (e PrefilterError) Error() string {
	switch e {
	case OutdatedProposal:
		return "OutdatedProposal"
	case OutdatedVote:
		return "OutdatedVote"
	case OutdatedTimeout:
		return "OutdatedTimeout"
	case OutdatedRoundRecovery:
		return "OutdatedRoundRecovery"
	case OutdatedNoEndorsement:
		return "OutdatedNoEndorsement"
	case OutdatedAdvanceRoundQc:
		return "OutdatedAdvanceRoundQc"
	case OutdatedAdvanceRoundTc:
		return "OutdatedAdvanceRoundTc"
	}
	return "prefilter error"
}

// ---------------------------------------------------------------------------
// Prefilter — Rust Unverified::prefilter / ConsensusMessage::prefilter.
// Cheap obsolete-message drop run before signature verification.
// ---------------------------------------------------------------------------

func Prefilter(u *messages.Unverified, rootInfo *blocktree.RootInfo, currentRound types.Round) error {
	m := u.Obj.Message // ProtocolMessage
	switch m.Kind {
	case messages.PMProposal:
		// proposals compared against root to permit out-of-order proposals
		if rootInfo != nil && m.Proposal.ProposalRound <= rootInfo.Round {
			return OutdatedProposal
		}
	case messages.PMVote:
		if m.Vote.Vote.Round < currentRound {
			return OutdatedVote
		}
	case messages.PMTimeout:
		if m.Timeout.Timeout.TmInfo.Round < currentRound {
			return OutdatedTimeout
		}
	case messages.PMRoundRecovery:
		if m.RoundRecovery.Round < currentRound {
			return OutdatedRoundRecovery
		}
	case messages.PMNoEndorsement:
		if m.NoEndorsement.Msg.Round < currentRound {
			return OutdatedNoEndorsement
		}
	case messages.PMAdvanceRound:
		if m.AdvanceRound.LastRoundCertificate.Round() < currentRound {
			if m.AdvanceRound.LastRoundCertificate.IsQC {
				return OutdatedAdvanceRoundQc
			}
			return OutdatedAdvanceRoundTc
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Verify — Rust Unverified::verify: recover author over rlp(message), confirm
// author is a member of the message's epoch validator set.
// ---------------------------------------------------------------------------

func Verify(
	u messages.Unverified,
	epochManager *validator.EpochManager,
	valEpochMap *validator.ValidatorsEpochMapping,
) (messages.Verified, error) {
	epoch, ok := epochManager.GetEpoch(u.Obj.GetRound())
	if !ok {
		return messages.Verified{}, ErrInvalidEpoch
	}
	valSet, ok := valEpochMap.GetValSet(epoch)
	if !ok {
		return messages.Verified{}, ErrValidatorSetDataUnavailable
	}
	pk, err := u.AuthorSignature.RecoverPubKey(crypto.DomainConsensusMessage, u.Obj.EncodeRLP(nil))
	if err != nil {
		return messages.Verified{}, ErrInvalidSignature
	}
	author := types.NewNodeId(pk)
	// valid_pubkey: author must be a staked member of the validator set
	if !valSet.IsMember(author) {
		return messages.Verified{}, ErrInvalidAuthor
	}
	return messages.Verified{Author: author, Message: u}, nil
}

// ---------------------------------------------------------------------------
// EpochToValidators — Rust epoch_to_validators closure factory.
// ---------------------------------------------------------------------------

// EpochToValidators resolves (epoch, round) → (validator_set, cert_mapping,
// leader). Mirrors Rust's epoch_to_validators.
type EpochToValidators func(epoch types.Epoch, round types.Round) (
	*validator.ValidatorSet, *validator.ValidatorMapping, types.NodeId, error)

func NewEpochToValidators(
	epochManager *validator.EpochManager,
	valEpochMap *validator.ValidatorsEpochMapping,
	election validator.LeaderElection,
) EpochToValidators {
	return func(epoch types.Epoch, round types.Round) (*validator.ValidatorSet, *validator.ValidatorMapping, types.NodeId, error) {
		if e, ok := epochManager.GetEpoch(round); !ok || e != epoch {
			return nil, nil, types.NodeId{}, ErrInvalidEpoch
		}
		valSet, ok := valEpochMap.GetValSet(epoch)
		if !ok {
			return nil, nil, types.NodeId{}, ErrValidatorSetDataUnavailable
		}
		certPubkeys, ok := valEpochMap.GetCertPubkeys(epoch)
		if !ok {
			return nil, nil, types.NodeId{}, ErrValidatorSetDataUnavailable
		}
		leader := election.GetLeader(round, valSet)
		return valSet, certPubkeys, leader, nil
	}
}

// ---------------------------------------------------------------------------
// Validate — Rust Verified<Unvalidated>::validate: version check + per-message
// structural/certificate validation. Returns a Validated (trusted) message.
// ---------------------------------------------------------------------------

func Validate(
	v messages.Verified,
	certCache *CertificateCache,
	epochManager *validator.EpochManager,
	valEpochMap *validator.ValidatorsEpochMapping,
	election validator.LeaderElection,
	clientVersion uint32,
	currentRound types.Round,
) (messages.Validated, error) {
	msg := v.Message.Obj // ConsensusMessage (value copy)
	if msg.Version != clientVersion {
		return messages.Validated{}, ErrInvalidVersion
	}
	e2v := NewEpochToValidators(epochManager, valEpochMap, election)

	switch msg.Message.Kind {
	case messages.PMProposal:
		if err := validateProposal(msg.Message.Proposal, certCache, epochManager, e2v); err != nil {
			return messages.Validated{}, err
		}
	case messages.PMVote:
		if err := validateVote(msg.Message.Vote, epochManager); err != nil {
			return messages.Validated{}, err
		}
	case messages.PMTimeout:
		if err := validateTimeout(&v, certCache, epochManager, e2v, currentRound); err != nil {
			return messages.Validated{}, err
		}
	case messages.PMRoundRecovery:
		if err := validateRoundRecovery(msg.Message.RoundRecovery, certCache, epochManager, e2v); err != nil {
			return messages.Validated{}, err
		}
	case messages.PMNoEndorsement:
		if err := validateNoEndorsement(msg.Message.NoEndorsement, epochManager); err != nil {
			return messages.Validated{}, err
		}
	case messages.PMAdvanceRound:
		if err := validateAdvanceRound(msg.Message.AdvanceRound, certCache, e2v); err != nil {
			return messages.Validated{}, err
		}
	}
	return messages.Validated{Verified: v}, nil
}

// ---------------------------------------------------------------------------
// Per-message validate implementations.
// ---------------------------------------------------------------------------

// validateProposal — Rust ProposalMessage::validate.
func validateProposal(
	m *messages.ProposalMessage,
	certCache *CertificateCache,
	epochManager *validator.EpochManager,
	e2v EpochToValidators,
) error {
	if err := wellFormedProposal(m); err != nil {
		return err
	}
	// verify_epoch: proposal_round's epoch must equal proposal_epoch
	if epoch, ok := epochManager.GetEpoch(m.ProposalRound); !ok || epoch != m.ProposalEpoch {
		return ErrInvalidEpoch
	}
	if err := VerifyTip(certCache, e2v, &m.Tip); err != nil {
		return err
	}
	if m.LastRoundTC != nil {
		if err := VerifyTC(certCache, e2v, m.LastRoundTC); err != nil {
			return err
		}
	}
	return nil
}

// wellFormedProposal — Rust well_formed_proposal.
func wellFormedProposal(m *messages.ProposalMessage) error {
	if m.Tip.BlockHeader.BlockBodyId != m.BlockBody.GetId() {
		return ErrNotWellFormed
	}
	if m.ProposalRound.ImmediatelyFollows(m.Tip.BlockHeader.QC.GetRound()) {
		// consecutive QC
		if m.LastRoundTC != nil {
			return ErrNotWellFormed
		}
		return nil
	}
	// last_round_tc must exist
	tc := m.LastRoundTC
	if tc == nil {
		return ErrNotWellFormed
	}
	// last_round_tc must be from the previous round
	if !m.ProposalRound.ImmediatelyFollows(tc.Round) {
		return ErrNotWellFormed
	}
	if tc.HighExtend.IsTip {
		tcTip := tc.HighExtend.Tip
		if tcTip == &m.Tip || tipsEqual(tcTip, &m.Tip) {
			// matches high_tip; qc of p.tc.high_extend and p.tip match implied
		} else {
			if m.ProposalRound != m.Tip.BlockHeader.BlockRound {
				return ErrNotWellFormed
			}
			if tcTip.BlockHeader.QC.GetRound() != m.Tip.BlockHeader.QC.GetRound() {
				return ErrNotWellFormed
			}
		}
	} else {
		if tc.HighExtend.QC.GetRound() != m.Tip.BlockHeader.QC.GetRound() {
			return ErrNotWellFormed
		}
	}
	return nil
}

// tipsEqual — structural compare used for `tc_tip == &self.tip` in Rust.
func tipsEqual(a, b *cstypes.ConsensusTip) bool {
	return a.BlockHeader.GetId() == b.BlockHeader.GetId() && a.Signature == b.Signature
}

// validateVote — Rust VoteMessage::validate: sig validity + epoch check.
// (BLS signature aggregation is deferred to the vote-state collection path.)
func validateVote(m *messages.VoteMessage, epochManager *validator.EpochManager) error {
	if err := m.Sig.Validate(); err != nil {
		return ErrInvalidSignature
	}
	if epoch, ok := epochManager.GetEpoch(m.Vote.Round); !ok || epoch != m.Vote.Epoch {
		return ErrInvalidEpoch
	}
	return nil
}

// validateTimeout — Rust TimeoutMessage::validate. Mutates the embedded
// Timeout: clears last_round_certificate once we've entered the round.
func validateTimeout(
	v *messages.Verified,
	certCache *CertificateCache,
	epochManager *validator.EpochManager,
	e2v EpochToValidators,
	currentRound types.Round,
) error {
	tm := v.Message.Obj.Message.Timeout // *TimeoutMessage
	timeout := tm.Timeout

	if err := timeout.TimeoutSignature.Validate(); err != nil {
		return ErrInvalidSignature
	}
	if err := wellFormedTimeout(&timeout); err != nil {
		return err
	}
	// verify_epoch
	if epoch, ok := epochManager.GetEpoch(timeout.TmInfo.Round); !ok || epoch != timeout.TmInfo.Epoch {
		return ErrInvalidEpoch
	}

	if currentRound >= timeout.TmInfo.Round {
		// Skip verifying last_round_certificate; clear it so it's inaccessible.
		timeout.LastRoundCertificate = nil
	}

	if rc := timeout.LastRoundCertificate; rc != nil {
		if rc.IsQC {
			if err := VerifyQC(certCache, e2v, rc.QC); err != nil {
				return err
			}
		} else {
			if err := VerifyTC(certCache, e2v, rc.TC); err != nil {
				return err
			}
		}
	}
	if err := VerifyHighExtend(certCache, e2v, timeout.HighExtend.AsHighExtend()); err != nil {
		return err
	}

	// Write the (possibly-cleared) Timeout back into the message.
	tm.Timeout = timeout
	return nil
}

// wellFormedTimeout — Rust well_formed_timeout.
func wellFormedTimeout(timeout *cstypes.Timeout) error {
	if timeout.HighExtend.Rank().Cmp(timeout.TmInfo.Rank()) != 0 {
		return ErrNotWellFormed
	}
	if timeout.TmInfo.Round.ImmediatelyFollows(timeout.HighExtend.GetQC().GetRound()) {
		if timeout.LastRoundCertificate != nil {
			return ErrNotWellFormed
		}
		return nil
	}
	rc := timeout.LastRoundCertificate
	if rc == nil {
		return ErrNotWellFormed
	}
	if !timeout.TmInfo.Round.ImmediatelyFollows(rc.Round()) {
		return ErrNotWellFormed
	}
	return nil
}

// validateRoundRecovery — Rust RoundRecoveryMessage::validate.
func validateRoundRecovery(
	m *messages.RoundRecoveryMessage,
	certCache *CertificateCache,
	epochManager *validator.EpochManager,
	e2v EpochToValidators,
) error {
	// well_formed_round_recovery
	if !m.Round.ImmediatelyFollows(m.TC.Round) {
		return ErrInvalidTcRound
	}
	if !m.TC.HighExtend.IsTip {
		return ErrNotWellFormed
	}
	// verify_epoch
	if epoch, ok := epochManager.GetEpoch(m.Round); !ok || epoch != m.Epoch {
		return ErrInvalidEpoch
	}
	return VerifyTC(certCache, e2v, &m.TC)
}

// validateNoEndorsement — Rust NoEndorsementMessage::validate.
func validateNoEndorsement(m *messages.NoEndorsementMessage, epochManager *validator.EpochManager) error {
	if err := m.Signature.Validate(); err != nil {
		return ErrInvalidSignature
	}
	if epoch, ok := epochManager.GetEpoch(m.Msg.Round); !ok || epoch != m.Msg.Epoch {
		return ErrInvalidEpoch
	}
	return nil
}

// validateAdvanceRound — Rust AdvanceRoundMessage::validate.
func validateAdvanceRound(
	m *messages.AdvanceRoundMessage,
	certCache *CertificateCache,
	e2v EpochToValidators,
) error {
	rc := &m.LastRoundCertificate
	if rc.IsQC {
		return VerifyQC(certCache, e2v, rc.QC)
	}
	return VerifyTC(certCache, e2v, rc.TC)
}

// ---------------------------------------------------------------------------
// Certificate verifiers.
// ---------------------------------------------------------------------------

// VerifyTC — Rust verify_tc.
func VerifyTC(
	certCache *CertificateCache,
	e2v EpochToValidators,
	tc *cstypes.TimeoutCertificate,
) error {
	if certCache.TCIsCachedValidated(tc) {
		return nil
	}
	validators, mapping, _, err := e2v(tc.Epoch, tc.Round)
	if err != nil {
		return err
	}
	if len(tc.TipRounds) > validators.Len() {
		return ErrTooManyTcTipRound
	}

	var nodeIds []types.NodeId
	highestRank := cstypes.HighExtendRank{QcRound: types.GENESIS_ROUND}
	seenTipRounds := make(map[[2]types.Round]struct{})
	seenNodeIds := make(map[[33]byte]struct{})

	for _, t := range tc.TipRounds {
		if t.HighQcRound >= tc.Round {
			return ErrInvalidTcRound
		}
		key := [2]types.Round{t.HighQcRound, t.HighTipRound}
		if _, dup := seenTipRounds[key]; dup {
			return ErrDuplicateTcTipRound
		}
		seenTipRounds[key] = struct{}{}

		if t.Sigs.NumSignatures() == 0 {
			return ErrEmptySignersTcTipRound
		}
		if t.Rank().Cmp(highestRank) > 0 {
			highestRank = t.Rank()
		}

		td := cstypes.TimeoutInfo{
			Epoch:        tc.Epoch,
			Round:        tc.Round,
			HighQcRound:  t.HighQcRound,
			HighTipRound: t.HighTipRound,
		}
		msg := td.EncodeRLP(nil)
		signers, err := t.Sigs.Verify(crypto.DomainTimeout, mapping, msg)
		if err != nil {
			return ErrInvalidSignature
		}
		for _, signer := range signers {
			k := [33]byte(signer.PubKey)
			if _, dup := seenNodeIds[k]; dup {
				return ErrSignaturesDuplicateNode
			}
			seenNodeIds[k] = struct{}{}
		}
		nodeIds = append(nodeIds, signers...)
	}

	if ok, err := validators.HasSuperMajorityVotes(nodeIds); err != nil {
		return ErrSignaturesDuplicateNode
	} else if !ok {
		return ErrInsufficientStake
	}

	if err := VerifyHighExtend(certCache, e2v, tc.HighExtend); err != nil {
		return err
	}
	if tc.HighExtend.Rank().Cmp(highestRank) != 0 {
		return ErrNotWellFormed
	}

	certCache.CacheValidatedTC(tc)
	return nil
}

// VerifyQC — Rust verify_qc.
func VerifyQC(
	certCache *CertificateCache,
	e2v EpochToValidators,
	qc *cstypes.QuorumCertificate,
) error {
	if certCache.QCIsCachedValidated(qc) {
		return nil
	}
	validators, mapping, _, err := e2v(qc.GetEpoch(), qc.GetRound())
	if err != nil {
		return err
	}
	if qc.GetRound() == types.GENESIS_ROUND {
		if qcEqual(qc, genesisQC()) {
			return nil
		}
		return ErrInvalidSignature
	}
	qcMsg := qc.Info.EncodeRLP(nil)
	nodeIds, err := qc.Signatures.Verify(crypto.DomainVote, mapping, qcMsg)
	if err != nil {
		return ErrInvalidSignature
	}
	if ok, err := validators.HasSuperMajorityVotes(nodeIds); err != nil {
		return ErrSignaturesDuplicateNode
	} else if !ok {
		return ErrInsufficientStake
	}
	certCache.CacheValidatedQC(qc)
	return nil
}

// VerifyHighExtend — Rust verify_high_extend.
func VerifyHighExtend(
	certCache *CertificateCache,
	e2v EpochToValidators,
	highExtend cstypes.HighExtend,
) error {
	if highExtend.IsTip {
		return VerifyTip(certCache, e2v, highExtend.Tip)
	}
	return VerifyQC(certCache, e2v, highExtend.QC)
}

// VerifyTip — Rust verify_tip.
func VerifyTip(
	certCache *CertificateCache,
	e2v EpochToValidators,
	tip *cstypes.ConsensusTip,
) error {
	_, _, leader, err := e2v(tip.BlockHeader.Epoch, tip.BlockHeader.BlockRound)
	if err != nil {
		return err
	}
	tipAuthor, err := tip.SignatureAuthor()
	if err != nil {
		return ErrInvalidSignature
	}
	if tipAuthor != leader.PubKey || tipAuthor != tip.BlockHeader.Author.PubKey {
		return ErrInvalidAuthor
	}

	if tip.BlockHeader.BlockRound.ImmediatelyFollows(tip.BlockHeader.QC.GetRound()) {
		// consecutive QC, no fresh_certificate needed
		if tip.FreshCertificate != nil {
			return ErrNotWellFormed
		}
	} else {
		// fresh_certificate needed
		fc := tip.FreshCertificate
		if fc == nil {
			return ErrNotWellFormed
		}
		if fc.IsNec {
			nec := fc.Nec
			if nec.Msg.Round != tip.BlockHeader.BlockRound {
				return ErrNotWellFormed
			}
			if nec.Msg.TipQcRound != tip.BlockHeader.QC.GetRound() {
				return ErrNotWellFormed
			}
		} else {
			noTip := fc.NoTip
			if !tip.BlockHeader.BlockRound.ImmediatelyFollows(noTip.Round) {
				return ErrNotWellFormed
			}
			if noTip.HighQc.GetRound() != tip.BlockHeader.QC.GetRound() {
				return ErrNotWellFormed
			}
		}
	}

	if err := VerifyQC(certCache, e2v, &tip.BlockHeader.QC); err != nil {
		return err
	}
	if fc := tip.FreshCertificate; fc != nil {
		if fc.IsNec {
			return VerifyNEC(certCache, e2v, fc.Nec)
		}
		noTip := fc.NoTip
		return VerifyTC(certCache, e2v, &cstypes.TimeoutCertificate{
			Epoch:      noTip.Epoch,
			Round:      noTip.Round,
			TipRounds:  noTip.TipRounds,
			HighExtend: cstypes.HighExtendQc(noTip.HighQc),
		})
	}
	return nil
}

// VerifyNEC — Rust verify_nec.
func VerifyNEC(
	certCache *CertificateCache,
	e2v EpochToValidators,
	nec *cstypes.NoEndorsementCertificate,
) error {
	if certCache.NECIsCachedValidated(nec) {
		return nil
	}
	validators, mapping, _, err := e2v(nec.Msg.Epoch, nec.Msg.Round)
	if err != nil {
		return err
	}
	necMsg := nec.Msg.EncodeRLP(nil)
	nodeIds, err := nec.Signatures.Verify(crypto.DomainNoEndorsement, mapping, necMsg)
	if err != nil {
		return ErrInvalidSignature
	}
	if ok, err := validators.HasSuperMajorityVotes(nodeIds); err != nil {
		return ErrSignaturesDuplicateNode
	} else if !ok {
		return ErrInsufficientStake
	}
	certCache.CacheValidatedNEC(nec)
	return nil
}

// qcEqual — Rust `qc == &QuorumCertificate::genesis_qc()`.
func qcEqual(a, b *cstypes.QuorumCertificate) bool {
	return bytes.Equal(a.EncodeRLP(nil), b.EncodeRLP(nil))
}

func genesisQC() *cstypes.QuorumCertificate {
	qc := cstypes.GenesisQC()
	return &qc
}

// IsProposal — Rust Unverified::is_proposal.
func IsProposal(u *messages.Unverified) bool {
	return u.Obj.Message.Kind == messages.PMProposal
}
