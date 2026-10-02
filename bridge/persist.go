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
//	res/{h8be}    → JSON storedResult
//	meta/height   → 8-byte big-endian committed tip
//	meta/valset   → proto cmtproto.ValidatorSet (canonical app set at tip)
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
	var tip [8]byte
	binary.BigEndian.PutUint64(tip[:], uint64(h))
	if err := batch.Set([]byte("meta/height"), tip[:], nil); err != nil {
		return err
	}
	return batch.Commit(syncWrite)
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

// Load rebuilds the committed index: tip, per-height entries, tx-hash index,
// and the canonical validator set at tip.
func (s *ResultStore) Load() (tip int64, res map[int64]resultEntry,
	txIdx map[string]int64, vs *cmttypes.ValidatorSet, err error) {
	res = map[int64]resultEntry{}
	txIdx = map[string]int64{}

	if v, closer, gerr := s.db.Get([]byte("meta/height")); gerr == nil {
		tip = int64(binary.BigEndian.Uint64(v))
		closer.Close()
	} else if gerr != pebble.ErrNotFound {
		return 0, nil, nil, nil, gerr
	}
	if v, closer, gerr := s.db.Get([]byte("meta/valset")); gerr == nil {
		var pv cmtproto.ValidatorSet
		if err = pv.Unmarshal(v); err != nil {
			closer.Close()
			return 0, nil, nil, nil, fmt.Errorf("valset decode: %w", err)
		}
		closer.Close()
		if vs, err = cmttypes.ValidatorSetFromProto(&pv); err != nil {
			return 0, nil, nil, nil, fmt.Errorf("valset decode: %w", err)
		}
	} else if gerr != pebble.ErrNotFound {
		return 0, nil, nil, nil, gerr
	}

	it, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte("res/"),
		UpperBound: []byte("res0"),
	})
	if err != nil {
		return 0, nil, nil, nil, err
	}
	defer it.Close()
	for it.First(); it.Valid(); it.Next() {
		h := int64(binary.BigEndian.Uint64(it.Key()[4:]))
		var rec storedResult
		if err := json.Unmarshal(it.Value(), &rec); err != nil {
			return 0, nil, nil, nil, fmt.Errorf("result decode @%d: %w", h, err)
		}
		e := resultEntry{
			header: &EvmFinalizedHeader{Number: types.SeqNum(h), AppHash: rec.AppHash},
			txs:    rec.Txs,
		}
		copy(e.blockID[:], rec.BlockID)
		for _, b := range rec.TxResults {
			r := new(abcitypes.ExecTxResult)
			if err := r.Unmarshal(b); err != nil {
				return 0, nil, nil, nil, fmt.Errorf("txresult decode @%d: %w", h, err)
			}
			e.txResults = append(e.txResults, r)
		}
		for _, b := range rec.Events {
			ev := new(abcitypes.Event)
			if err := ev.Unmarshal(b); err != nil {
				return 0, nil, nil, nil, fmt.Errorf("event decode @%d: %w", h, err)
			}
			e.events = append(e.events, *ev)
		}
		for _, b := range rec.ValUpdates {
			u := new(abcitypes.ValidatorUpdate)
			if err := u.Unmarshal(b); err != nil {
				return 0, nil, nil, nil, fmt.Errorf("valupdate decode @%d: %w", h, err)
			}
			e.valUpdates = append(e.valUpdates, *u)
		}
		res[h] = e
		for _, tx := range e.txs {
			txIdx[fmt.Sprintf("%X", tmhash.Sum(tx))] = h
		}
	}
	return tip, res, txIdx, vs, it.Error()
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
