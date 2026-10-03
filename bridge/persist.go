package bridge

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/cockroachdb/pebble"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/abhijitkrm/monadbft-go/types"
)

// ResultStore — the bridge's durable committed-result index. Consensus
// blocks persist in store.BlockStore; this side index holds what blocks
// don't carry: per-height tx results, finalize events, validator updates,
// and the canonical app validator set — everything App bookkeeping needs to
// rebuild on restart without replaying execution.
//
// Key spaces:
//
//	res/{h8be}       → JSON storedResult
//	tx/{hexhash}     → 8-byte big-endian committed height
//	chash/{hash32}   → 8-byte big-endian height (synthesized comet block hash)
//	vs/{h8be}        → proto cmtproto.ValidatorSet (written only on change at h)
//	meta/height      → 8-byte big-endian committed tip
//	meta/valset      → proto cmtproto.ValidatorSet (canonical app set at tip)
type ResultStore struct {
	db *pebble.DB
}

type storedResult struct {
	AppHash    []byte   `json:"app_hash"`
	BlockID    []byte   `json:"block_id"`
	Txs        [][]byte `json:"txs,omitempty"`
	TxResults  [][]byte `json:"tx_results,omitempty"` // proto ExecTxResult each
	Events     [][]byte `json:"events,omitempty"`     // proto Event each
	ValUpdates [][]byte `json:"val_updates,omitempty"`
}

var syncWrite = &pebble.WriteOptions{Sync: true}

func resKey(h int64) []byte {
	k := make([]byte, 4+8)
	copy(k, "res/")
	binary.BigEndian.PutUint64(k[4:], uint64(h))
	return k
}

func txKey(hashHex string) []byte {
	k := make([]byte, 3+len(hashHex))
	copy(k, "tx/")
	copy(k[3:], hashHex)
	return k
}

func chashKey(hash []byte) []byte {
	k := make([]byte, 6+len(hash))
	copy(k, "chash/")
	copy(k[6:], hash)
	return k
}

func vsKey(h int64) []byte {
	k := make([]byte, 3+8)
	copy(k, "vs/")
	binary.BigEndian.PutUint64(k[3:], uint64(h))
	return k
}

// OpenResultStore opens (creating if needed) the result index under dir.
func OpenResultStore(dir string) (*ResultStore, error) {
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		return nil, err
	}
	return &ResultStore{db: db}, nil
}

func (s *ResultStore) Close() error { return s.db.Close() }

// Put records one committed height's result durably (idempotent on height).
func (s *ResultStore) Put(h int64, e resultEntry) error {
	rec := storedResult{BlockID: e.blockID[:], Txs: e.txs}
	if e.header != nil {
		rec.AppHash = e.header.AppHash
	}
	for _, r := range e.txResults {
		b, err := r.Marshal()
		if err != nil {
			return fmt.Errorf("marshal txresult: %w", err)
		}
		rec.TxResults = append(rec.TxResults, b)
	}
	for _, ev := range e.events {
		b, err := ev.Marshal()
		if err != nil {
			return fmt.Errorf("marshal event: %w", err)
		}
		rec.Events = append(rec.Events, b)
	}
	for _, u := range e.valUpdates {
		b, err := u.Marshal()
		if err != nil {
			return fmt.Errorf("marshal valupdate: %w", err)
		}
		rec.ValUpdates = append(rec.ValUpdates, b)
	}
	buf, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(resKey(h), buf, nil); err != nil {
		return err
	}
	var hb [8]byte
	binary.BigEndian.PutUint64(hb[:], uint64(h))
	for _, tx := range e.txs {
		if err := batch.Set(txKey(fmt.Sprintf("%X", tmhash.Sum(tx))), hb[:], nil); err != nil {
			return err
		}
	}
	if err := batch.Set([]byte("meta/height"), hb[:], nil); err != nil {
		return err
	}
	return batch.Commit(syncWrite)
}

// Get — one committed height's entry; ok=false when absent/pruned.
func (s *ResultStore) Get(h int64) (resultEntry, bool, error) {
	v, closer, err := s.db.Get(resKey(h))
	if err == pebble.ErrNotFound {
		return resultEntry{}, false, nil
	}
	if err != nil {
		return resultEntry{}, false, err
	}
	defer closer.Close()
	e, err := decodeResult(h, v)
	return e, err == nil, err
}

// Tip — the committed tip recorded by the last Put; 0 on an empty store.
func (s *ResultStore) Tip() (int64, error) {
	v, closer, err := s.db.Get([]byte("meta/height"))
	if err == pebble.ErrNotFound {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer closer.Close()
	return int64(binary.BigEndian.Uint64(v)), nil
}

// TxHeight — committed height for a tx hash (tmhash hex); ok=false when the
// tx was never committed through this store.
func (s *ResultStore) TxHeight(hashHex string) (int64, bool, error) {
	v, closer, err := s.db.Get(txKey(hashHex))
	if err == pebble.ErrNotFound {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	defer closer.Close()
	return int64(binary.BigEndian.Uint64(v)), true, nil
}

// PutCmtHash — the synthesized comet block hash index for one height.
func (s *ResultStore) PutCmtHash(hash []byte, h int64) error {
	var hb [8]byte
	binary.BigEndian.PutUint64(hb[:], uint64(h))
	return s.db.Set(chashKey(hash), hb[:], syncWrite)
}

// CmtHeight — height for a synthesized comet block hash.
func (s *ResultStore) CmtHeight(hash []byte) (int64, bool, error) {
	v, closer, err := s.db.Get(chashKey(hash))
	if err == pebble.ErrNotFound {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	defer closer.Close()
	return int64(binary.BigEndian.Uint64(v)), true, nil
}

// PutValSetChange — record the canonical validator set at a height where it
// changed (applyUpdates with non-empty updates). Unchanged heights are
// served by carrying the greatest vs/ entry ≤ h forward.
func (s *ResultStore) PutValSetChange(h int64, vs *cmttypes.ValidatorSet) error {
	p, err := vs.ToProto()
	if err != nil {
		return err
	}
	b, err := p.Marshal()
	if err != nil {
		return err
	}
	return s.db.Set(vsKey(h), b, syncWrite)
}

// ValSetBefore — the persisted changed-set at or below h; nil when no change
// is recorded (caller falls back to the genesis set).
func (s *ResultStore) ValSetBefore(h int64) (*cmttypes.ValidatorSet, error) {
	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte("vs/"),
		UpperBound: []byte("vs0"),
	})
	if err != nil {
		return nil, err
	}
	defer it.Close()
	// greatest vs/ key ≤ h — the set that was canonical at h.
	if !it.SeekLT(vsKey(h + 1)) {
		return nil, it.Error()
	}
	var pv cmtproto.ValidatorSet
	if err := pv.Unmarshal(it.Value()); err != nil {
		return nil, fmt.Errorf("valset decode: %w", err)
	}
	return cmttypes.ValidatorSetFromProto(&pv)
}

// PruneBefore — drop res/ rows below floor (bounded disk retention). tx/ and
// chash/ indexes are kept: they are per-tx/per-block index entries, and a
// pruned lookup degrades to "not found" anyway.
func (s *ResultStore) PruneBefore(floor int64) error {
	return s.db.DeleteRange([]byte("res/"), resKey(floor), syncWrite)
}

// decodeResult — one storedResult row → resultEntry.
func decodeResult(h int64, v []byte) (resultEntry, error) {
	var rec storedResult
	if err := json.Unmarshal(v, &rec); err != nil {
		return resultEntry{}, fmt.Errorf("result decode @%d: %w", h, err)
	}
	e := resultEntry{
		header: &EvmFinalizedHeader{Number: types.SeqNum(h), AppHash: rec.AppHash},
		txs:    rec.Txs,
	}
	copy(e.blockID[:], rec.BlockID)
	for _, b := range rec.TxResults {
		r := new(abcitypes.ExecTxResult)
		if err := r.Unmarshal(b); err != nil {
			return resultEntry{}, fmt.Errorf("txresult decode @%d: %w", h, err)
		}
		e.txResults = append(e.txResults, r)
	}
	for _, b := range rec.Events {
		ev := new(abcitypes.Event)
		if err := ev.Unmarshal(b); err != nil {
			return resultEntry{}, fmt.Errorf("event decode @%d: %w", h, err)
		}
		e.events = append(e.events, *ev)
	}
	for _, b := range rec.ValUpdates {
		u := new(abcitypes.ValidatorUpdate)
		if err := u.Unmarshal(b); err != nil {
			return resultEntry{}, fmt.Errorf("valupdate decode @%d: %w", h, err)
		}
		e.valUpdates = append(e.valUpdates, *u)
	}
	return e, nil
}

// SaveValSet snapshots the canonical app validator set at the commit tip.
func (s *ResultStore) SaveValSet(vs *cmttypes.ValidatorSet) error {
	p, err := vs.ToProto()
	if err != nil {
		return err
	}
	b, err := p.Marshal()
	if err != nil {
		return err
	}
	return s.db.Set([]byte("meta/valset"), b, syncWrite)
}

// LoadRecent rebuilds the committed index for serving: tip, res/ entries at
// heights ≥ from (the in-memory window — older heights are served on demand
// via Get), and the canonical validator set at tip. The tx/ index is
// store-resident (TxHeight), not rebuilt into memory.
func (s *ResultStore) LoadRecent(from int64) (tip int64, res map[int64]resultEntry,
	vs *cmttypes.ValidatorSet, err error) {
	res = map[int64]resultEntry{}

	tip, err = s.Tip()
	if err != nil {
		return 0, nil, nil, err
	}
	if v, closer, gerr := s.db.Get([]byte("meta/valset")); gerr == nil {
		var pv cmtproto.ValidatorSet
		if err = pv.Unmarshal(v); err != nil {
			closer.Close()
			return 0, nil, nil, fmt.Errorf("valset decode: %w", err)
		}
		closer.Close()
		if vs, err = cmttypes.ValidatorSetFromProto(&pv); err != nil {
			return 0, nil, nil, fmt.Errorf("valset decode: %w", err)
		}
	} else if gerr != pebble.ErrNotFound {
		return 0, nil, nil, gerr
	}

	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: resKey(from),
		UpperBound: []byte("res0"),
	})
	if err != nil {
		return 0, nil, nil, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		h := int64(binary.BigEndian.Uint64(it.Key()[4:]))
		e, err := decodeResult(h, it.Value())
		if err != nil {
			return 0, nil, nil, err
		}
		res[h] = e
	}
	return tip, res, vs, it.Error()
}

// genesisMeta — chain identity + initial set, needed to rebuild header
// synthesis and per-height valsets on restart (InitChain never re-runs).
type genesisMeta struct {
	chainID    string
	consParams *cmtproto.ConsensusParams
	valSet     *cmttypes.ValidatorSet
}

type storedGenesis struct {
	ChainID          string `json:"chain_id"`
	ConsensusParamsB []byte `json:"consensus_params,omitempty"` // proto ConsensusParams
	ValSetB          []byte `json:"val_set,omitempty"`          // proto cmtproto.ValidatorSet
}

// PutGenesis records the genesis metadata (called once from InitChain).
func (s *ResultStore) PutGenesis(chainID string, params *cmtproto.ConsensusParams, vs *cmttypes.ValidatorSet) error {
	g := storedGenesis{ChainID: chainID}
	if params != nil {
		b, err := params.Marshal()
		if err != nil {
			return err
		}
		g.ConsensusParamsB = b
	}
	if vs != nil {
		p, err := vs.ToProto()
		if err != nil {
			return err
		}
		b, err := p.Marshal()
		if err != nil {
			return err
		}
		g.ValSetB = b
	}
	buf, err := json.Marshal(g)
	if err != nil {
		return err
	}
	return s.db.Set([]byte("meta/genesis"), buf, syncWrite)
}

// LoadGenesis — nil meta when absent.
func (s *ResultStore) LoadGenesis() (*genesisMeta, error) {
	v, closer, err := s.db.Get([]byte("meta/genesis"))
	if err == pebble.ErrNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer closer.Close()
	var g storedGenesis
	if err := json.Unmarshal(v, &g); err != nil {
		return nil, err
	}
	m := &genesisMeta{chainID: g.ChainID}
	if g.ConsensusParamsB != nil {
		m.consParams = new(cmtproto.ConsensusParams)
		if err := m.consParams.Unmarshal(g.ConsensusParamsB); err != nil {
			return nil, fmt.Errorf("genesis params decode: %w", err)
		}
	}
	if g.ValSetB != nil {
		var pv cmtproto.ValidatorSet
		if err := pv.Unmarshal(g.ValSetB); err != nil {
			return nil, fmt.Errorf("genesis valset decode: %w", err)
		}
		if m.valSet, err = cmttypes.ValidatorSetFromProto(&pv); err != nil {
			return nil, fmt.Errorf("genesis valset decode: %w", err)
		}
	}
	return m, nil
}
