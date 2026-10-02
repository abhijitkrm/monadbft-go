package bridge

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"sync"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmtcrypto "github.com/cometbft/cometbft/crypto"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/cosmos/evm/evmd"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/testutil"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Validator — one validator's key material across both stacks: the MonadBFT
// consensus keys (secp256k1 NodeId + BLS cert key) and the app-side consensus
// key (ed25519, what the SDK validator set carries). Pubkey fields are always
// populated; the private halves are only set for the local node (from the
// monad key file) or test keys.
//
// Until x/consensuskeys exists, the cons-key ↔ consensus-key binding is
// established by the validator binding file (or testnet genesis tooling),
// not on-chain.
type Validator struct {
	SecpPub  crypto.SecpPubKey
	BlsPub   [48]byte
	ConsPub  cmted25519.PubKey
	Secp     *crypto.SecpKeyPair
	Bls      *crypto.BlsKeyPair
	ConsPriv cmted25519.PrivKey
}

// NewValidator — full key material (local node / tests).
func NewValidator(secp *crypto.SecpKeyPair, bls *crypto.BlsKeyPair, cons cmted25519.PrivKey) Validator {
	v := Validator{Secp: secp, Bls: bls, ConsPriv: cons}
	v.SecpPub = secp.PubKey()
	copy(v.BlsPub[:], bls.PubKey().Compress())
	v.ConsPub = cmted25519.PubKey(cons.PubKey().Bytes())
	return v
}

// PubValidator — a peer validator's public key material (validator binding
// file); no private keys.
func PubValidator(secpPub crypto.SecpPubKey, blsPub [48]byte, consPub cmted25519.PubKey) Validator {
	return Validator{SecpPub: secpPub, BlsPub: blsPub, ConsPub: consPub}
}

// NodeId — the MonadBFT node identity (secp256k1 pubkey).
func (v *Validator) NodeId() types.NodeId { return types.NewNodeId(v.SecpPub) }

// ConsAddr — the SDK consensus address (sha256(pubkey)[:20] for ed25519).
func (v *Validator) ConsAddr() []byte { return v.ConsPub.Address() }

// ConsPubKey — the cometbft pubkey carried in ValidatorUpdates.
func (v *Validator) ConsPubKey() cmtcrypto.PubKey { return v.ConsPub }

// CertPubKey — the BLS cert pubkey (compressed, 48B).
func (v *Validator) CertPubKey() [48]byte { return v.BlsPub }

// MakeValidators — deterministic per-index key material, mirroring the
// swarm's CreateKeysWithValidators for the MonadBFT keys and deriving the
// ed25519 cons key from the same seed.
func MakeValidators(n int) []Validator {
	vals := make([]Validator, n)
	for i := range vals {
		seed := sha256.Sum256([]byte(fmt.Sprintf("bridge-cons-key-%d", i)))
		vals[i] = NewValidator(testutil.GetKey(uint64(i)),
			testutil.GetCertKey(uint64(i)),
			cmted25519.GenPrivKeyFromSecret(seed[:]))
	}
	return vals
}

// CmtValidatorSet — the cometbft validator set for genesis: every validator
// at equal voting power.
func CmtValidatorSet(vals []Validator) *cmttypes.ValidatorSet {
	vs := make([]*cmttypes.Validator, len(vals))
	for i, v := range vals {
		vs[i] = cmttypes.NewValidator(v.ConsPubKey(), 1)
	}
	return cmttypes.NewValidatorSet(vs)
}

// App is the bridge's handle on an in-process ABCI application. It wraps the
// app (the "local client" seam — calls go straight to the Application
// interface) plus the bookkeeping the bridge needs:
//
//   - the canonical validator set (for decided_last_commit ordering and
//     ValidatorUpdates accumulation)
//   - cons-addr ↔ MonadBFT-key mapping
//   - per-height finalized execution results (app hash index)
type App struct {
	app abcitypes.Application
	raw *evmd.EVMD // concrete app when built via NewEvmdApp (nil otherwise)

	monadVals []Validator            // sorted by NodeId — QC bit order
	appSet    *cmttypes.ValidatorSet // canonical order for VoteInfo
	byCons    map[string]int         // consAddr → monadVals index

	// mu guards height/results: the swarm drives an App single-threaded, but
	// under the node runtime the ledger commits on the node's loop goroutine
	// while tests/RPC read concurrently.
	mu      sync.Mutex
	height  int64                 // last committed height
	results map[int64]resultEntry // committed height → execution result
	txIndex map[string]int64      // tmhash hex → committed height (RPC /tx)
	store   *ResultStore          // durable index; nil until AttachStore

	chainID    string
	consParams *cmtproto.ConsensusParams
	// valSets — per-height canonical app validator set *after* that height's
	// updates (the set validating h is valSets[h-1]; genesis set is
	// valSets[0]). Entries alias when a height carried no updates.
	valSets    map[int64]*cmttypes.ValidatorSet
	lastValSet *cmttypes.ValidatorSet

	// opMu serializes store-touching ABCI calls. With SpecApp's async
	// worker, FinalizeBlock+Commit run off the node loop while
	// CheckTx/PrepareProposal still run on it — the SDK's single cms +
	// mode slots aren't safe for concurrent use, so every app-level call
	// pairs holds this mutex.
	opMu sync.Mutex
}

type resultEntry struct {
	header     *EvmFinalizedHeader
	blockID    types.BlockId
	txs        [][]byte
	txResults  []*abcitypes.ExecTxResult
	events     []abcitypes.Event
	valUpdates []abcitypes.ValidatorUpdate
}

// NewApp wraps an ABCI application with genesis validator bookkeeping.
// vals is the full validator key set shared by all nodes.
func NewApp(app abcitypes.Application, vals []Validator) *App {
	monadVals := append([]Validator(nil), vals...)
	sort.Slice(monadVals, func(i, j int) bool {
		return monadVals[i].NodeId().Cmp(monadVals[j].NodeId()) < 0
	})
	a := &App{
		app:       app,
		monadVals: monadVals,
		byCons:    map[string]int{},
		results:   map[int64]resultEntry{},
		txIndex:   map[string]int64{},
		valSets:   map[int64]*cmttypes.ValidatorSet{},
	}
	for i := range monadVals {
		a.byCons[string(monadVals[i].ConsAddr())] = i
	}
	return a
}

// ABCI — the underlying application.
func (a *App) ABCI() abcitypes.Application { return a.app }

// InitChain runs the app's InitChain with the given genesis doc, records the
// initial validator set, and seeds result[0] with the genesis app hash.
func (a *App) InitChain(ctx context.Context, req *abcitypes.RequestInitChain) error {
	res, err := a.app.InitChain(ctx, req)
	if err != nil {
		return fmt.Errorf("InitChain: %w", err)
	}
	a.chainID = req.ChainId
	a.consParams = req.ConsensusParams
	if err := a.applyUpdates(0, res.Validators); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.results[0] = resultEntry{
		header:  &EvmFinalizedHeader{Number: 0, AppHash: res.AppHash},
		blockID: types.GENESIS_BLOCK_ID,
	}
	if a.store != nil {
		if err := a.store.PutGenesis(req.ChainId, req.ConsensusParams, a.appSet); err != nil {
			return fmt.Errorf("bridge: persist genesis meta: %w", err)
		}
	}
	return nil
}

// applyUpdates folds ValidatorUpdates into the canonical set via cometbft's
// UpdateWithChangeSet (power 0 removes, known pubkey updates power) and
// records the post-update set under h (it validates h+1).
func (a *App) applyUpdates(h int64, updates []abcitypes.ValidatorUpdate) error {
	changes := make([]*cmttypes.Validator, 0, len(updates))
	for _, u := range updates {
		pk, err := cryptoenc.PubKeyFromProto(u.PubKey)
		if err != nil {
			return fmt.Errorf("bridge: validator update pubkey: %w", err)
		}
		changes = append(changes, cmttypes.NewValidator(pk, u.Power))
	}
	if a.appSet == nil {
		pos := make([]*cmttypes.Validator, 0, len(changes))
		for _, v := range changes {
			if v.VotingPower > 0 {
				pos = append(pos, v)
			}
		}
		a.appSet = cmttypes.NewValidatorSet(pos)
	} else if err := a.appSet.UpdateWithChangeSet(changes); err != nil {
		return fmt.Errorf("bridge: apply validator updates: %w", err)
	}
	a.mu.Lock()
	if len(updates) > 0 || a.lastValSet == nil {
		a.lastValSet = a.appSet.Copy()
	}
	a.valSets[h] = a.lastValSet
	a.mu.Unlock()
	a.persistValSet()
	return nil
}

// persistValSet write-throughs the canonical set (AttachStore must precede
// the first commit for restart-safe valset recovery).
func (a *App) persistValSet() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store != nil && a.appSet != nil {
		if err := a.store.SaveValSet(a.appSet); err != nil {
			panic(fmt.Sprintf("bridge: persist valset: %v", err))
		}
	}
}

// FinalizeBlock — ABCI FinalizeBlock passthrough.
func (a *App) FinalizeBlock(ctx context.Context, req *abcitypes.RequestFinalizeBlock) (*abcitypes.ResponseFinalizeBlock, error) {
	return a.app.FinalizeBlock(ctx, req)
}

// Commit — ABCI Commit passthrough. The app's PrepareCheckStater hook
// (evmd installs one that fires mempool.NotifyNewBlock when no CometBFT
// event bus is wired) advances the mempool's height sync here.
func (a *App) Commit(ctx context.Context) error {
	_, err := a.app.Commit(ctx, &abcitypes.RequestCommit{})
	return err
}

// SetRaw binds the concrete evmd app (engine path — NewEvmdApp sets it
// inline for tests). Needed for store-level access (SpecApp, block height).
func (a *App) SetRaw(r *evmd.EVMD) { a.raw = r }

// Raw — the concrete evmd app when built via NewEvmdApp (nil for other
// ABCI apps). SpecApp needs it for CommitMultiStore rollback.
func (a *App) Raw() *evmd.EVMD { return a.raw }

// LockOps/UnlockOps — serialize store-touching ABCI calls across
// goroutines (spec worker vs node loop). Callers batch related calls
// (ReapTxs+PrepareProposal, CheckTx+InsertTx) under one hold.
func (a *App) LockOps()   { a.opMu.Lock() }
func (a *App) UnlockOps() { a.opMu.Unlock() }

// StoreTip — the last committed store height (a.height tracks the
// canonicalized tip; the store itself runs ahead when SpecApp has
// committed speculative heights — those are still "latest committed
// state" for mempool validation purposes).
func (a *App) StoreTip() int64 {
	if a.raw != nil {
		return a.raw.LastBlockHeight()
	}
	return a.committedHeight()
}

// Height — last committed height.
func (a *App) Height() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.height
}

// Result — the finalized execution result (app hash) committed at height h.
func (a *App) Result(h int64) *EvmFinalizedHeader {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.results[h]; ok {
		return e.header
	}
	return nil
}

// Txs — the tx list committed at height h (test/assertion seam).
func (a *App) Txs(h int64) [][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.results[h]; ok {
		return e.txs
	}
	return nil
}

// AttachStore opens the durable result index and rebuilds committed-height
// bookkeeping (tip, results, tx index, canonical valset). On a fresh store
// this is a no-op. Call before the node starts committing blocks.
func (a *App) AttachStore(s *ResultStore) error {
	tip, res, txIdx, vs, err := s.Load()
	if err != nil {
		return fmt.Errorf("bridge: load result store: %w", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.store = s
	for h, e := range res {
		a.results[h] = e
	}
	for k, v := range txIdx {
		a.txIndex[k] = v
	}
	if tip > a.height {
		a.height = tip
	}
	if vs != nil {
		a.appSet = vs
	}
	g, err := s.LoadGenesis()
	if err != nil {
		return fmt.Errorf("bridge: load genesis meta: %w", err)
	}
	if g != nil {
		a.chainID = g.chainID
		a.consParams = g.consParams
	}
	// rebuild per-height valsets: genesis set + replay stored updates
	cur := vs
	if g != nil && g.valSet != nil {
		cur = g.valSet
	}
	if cur != nil {
		a.valSets[0] = cur
		for h := int64(1); h <= tip; h++ {
			if e, ok := res[h]; ok && len(e.valUpdates) > 0 {
				next, err := applyValUpdates(cur, e.valUpdates)
				if err != nil {
					return fmt.Errorf("bridge: replay valset @%d: %w", h, err)
				}
				cur = next
			}
			a.valSets[h] = cur
		}
		a.lastValSet = cur
	}
	return nil
}

// applyValUpdates — UpdateWithChangeSet on a copy (replay helper).
func applyValUpdates(vs *cmttypes.ValidatorSet, updates []abcitypes.ValidatorUpdate) (*cmttypes.ValidatorSet, error) {
	changes := make([]*cmttypes.Validator, 0, len(updates))
	for _, u := range updates {
		pk, err := cryptoenc.PubKeyFromProto(u.PubKey)
		if err != nil {
			return nil, err
		}
		changes = append(changes, cmttypes.NewValidator(pk, u.Power))
	}
	cp := vs.Copy()
	return cp, cp.UpdateWithChangeSet(changes)
}

// recordCommit — ledger-facing write of the committed height + result.
// Durably writes through to the result store when attached — a failed write
// means committed state would be lost on crash, which is unrecoverable.
func (a *App) recordCommit(seq int64, entry resultEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.store != nil {
		if err := a.store.Put(seq, entry); err != nil {
			panic(fmt.Sprintf("bridge: persist committed result %d: %v", seq, err))
		}
	}
	a.height = seq
	a.results[seq] = entry
	for _, tx := range entry.txs {
		a.txIndex[fmt.Sprintf("%X", tmhash.Sum(tx))] = seq
	}
}

// TxLookup — the height a tx hash committed at (CometBFT tx-hash = tmhash).
func (a *App) TxLookup(hashHex string) (height int64, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	h, ok := a.txIndex[hashHex]
	return h, ok
}

// CommittedEntry — the full committed record at height h for RPC serving.
func (a *App) CommittedEntry(h int64) (header *EvmFinalizedHeader, blockID types.BlockId, txs [][]byte,
	txResults []*abcitypes.ExecTxResult, events []abcitypes.Event, updates []abcitypes.ValidatorUpdate, ok bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	e, found := a.results[h]
	if !found {
		return nil, types.BlockId{}, nil, nil, nil, nil, false
	}
	return e.header, e.blockID, e.txs, e.txResults, e.events, e.valUpdates, true
}

// ValSetAt — the canonical validator set that validated height h
// (valSets[h-1]); genesis set for h<=1, latest for h>tip.
func (a *App) ValSetAt(h int64) *cmttypes.ValidatorSet {
	a.mu.Lock()
	defer a.mu.Unlock()
	if h <= 1 {
		return a.valSets[0]
	}
	if vs, ok := a.valSets[h-1]; ok {
		return vs
	}
	return a.lastValSet
}

// ChainID / ConsensusParams — captured at InitChain (persisted via
// ResultStore so restarts recover them).
func (a *App) ChainID() string { return a.chainID }

func (a *App) ConsensusParams() *cmtproto.ConsensusParams { return a.consParams }

// Validators — the current canonical app-side validator set.
func (a *App) Validators() []*cmttypes.Validator {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.appSet == nil {
		return nil
	}
	return append([]*cmttypes.Validator(nil), a.appSet.Validators...)
}

// committedHeight — ledger-facing read of the last committed height.
func (a *App) committedHeight() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.height
}

// LastCommit — the ABCI decided_last_commit for a block being finalized:
// the parent QC's signer bitmap mapped onto the app's canonical validator
// order (cometbft requires votes indexed by validator-set position).
//
// The genesis QC carries no signers — height-1 FinalizeBlock gets an empty
// CommitInfo, matching CometBFT.
func (a *App) LastCommit(qc cstypes.QuorumCertificate) abcitypes.CommitInfo {
	if a.appSet == nil || qc.Signatures.Signers.Len() == 0 {
		return abcitypes.CommitInfo{Round: int32(qc.Info.Round)}
	}
	votes := make([]abcitypes.VoteInfo, len(a.appSet.Validators))
	for i, v := range a.appSet.Validators {
		flag := cmtproto.BlockIDFlagAbsent
		if mi, ok := a.byCons[string(v.Address)]; ok &&
			mi < qc.Signatures.Signers.Len() && qc.Signatures.Signers.Bits[mi] {
			flag = cmtproto.BlockIDFlagCommit
		}
		votes[i] = abcitypes.VoteInfo{
			Validator:   abcitypes.Validator{Address: v.Address, Power: v.VotingPower},
			BlockIdFlag: flag,
		}
	}
	return abcitypes.CommitInfo{Round: int32(qc.Info.Round), Votes: votes}
}

// LocalLastCommit — the ExtendedCommitInfo variant used by PrepareProposal
// (same signer bitmap, empty vote extensions — the milestone does not use
// vote extensions).
func (a *App) LocalLastCommit(qc cstypes.QuorumCertificate) abcitypes.ExtendedCommitInfo {
	if a.appSet == nil || qc.Signatures.Signers.Len() == 0 {
		return abcitypes.ExtendedCommitInfo{Round: int32(qc.Info.Round)}
	}
	votes := make([]abcitypes.ExtendedVoteInfo, len(a.appSet.Validators))
	for i, v := range a.appSet.Validators {
		flag := cmtproto.BlockIDFlagAbsent
		if mi, ok := a.byCons[string(v.Address)]; ok &&
			mi < qc.Signatures.Signers.Len() && qc.Signatures.Signers.Bits[mi] {
			flag = cmtproto.BlockIDFlagCommit
		}
		votes[i] = abcitypes.ExtendedVoteInfo{
			Validator:   abcitypes.Validator{Address: v.Address, Power: v.VotingPower},
			BlockIdFlag: flag,
		}
	}
	return abcitypes.ExtendedCommitInfo{Round: int32(qc.Info.Round), Votes: votes}
}

// ConsAddr — the cons address for a MonadBFT author NodeId.
func (a *App) ConsAddr(id types.NodeId) []byte {
	for i := range a.monadVals {
		if a.monadVals[i].NodeId() == id {
			return a.monadVals[i].ConsAddr()
		}
	}
	return nil
}

// ValidatorsHash — the canonical set hash (RequestFinalizeBlock.
// NextValidatorsHash).
func (a *App) ValidatorsHash() []byte {
	if a.appSet == nil {
		return nil
	}
	return a.appSet.Hash()
}

// ValidatorSetData — the MonadBFT validator set for the app's current
// canonical set, sorted by NodeId (QC bit order).
func (a *App) ValidatorSetData() (glue.ValidatorSetData, error) {
	if a.appSet == nil {
		return glue.ValidatorSetData{}, fmt.Errorf("bridge: no validator set yet")
	}
	var vds []glue.ValidatorData
	for _, v := range a.appSet.Validators {
		mi, ok := a.byCons[string(v.Address)]
		if !ok {
			return glue.ValidatorSetData{}, fmt.Errorf(
				"bridge: validator %x not in genesis key map (x/consensuskeys not implemented)", v.Address)
		}
		vds = append(vds, glue.ValidatorData{
			NodeId:     a.monadVals[mi].NodeId(),
			Stake:      types.StakeFromUint64(uint64(v.VotingPower)),
			CertPubKey: a.monadVals[mi].CertPubKey(),
		})
	}
	sort.Slice(vds, func(i, j int) bool { return vds[i].NodeId.Cmp(vds[j].NodeId) < 0 })
	return glue.ValidatorSetData{Validators: vds}, nil
}
