package node

import (
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/abhijitkrm/monadbft-go/consensus"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/store"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/wal"
)

// Persistence — the node's open durable handles. Layout under Dir:
//
//	{Dir}/wal/wal_{ts}.{gen}     chunked write-ahead event log (waltrace)
//	{Dir}/blocks/               pebble consensus block store
//	{Dir}/forkpoint.rlp         latest checkpoint (root + high certificate)
//	{Dir}/validators.rlp        trailing locked-epoch validator sets
//	{Dir}/safety.rlp            Safety watermarks (double-sign protection)
//
// Callers may open it ahead of Node (Config.Persistence) when executors
// need the block store before the first init commands run — the bridge
// ledger seeds its block index from it.
type Persistence struct {
	WAL        *wal.Logger
	Blocks     *store.BlockStore
	ConfigFile *store.ConfigFile

	// lastSafety is the serialized watermark set last written — writes are
	// skipped when nothing changed (most events don't move the watermarks).
	lastSafety []byte
}

// OpenPersistence opens the durable handles under dir (created if needed).
func OpenPersistence(dir string, ep *exec.Protocol, syncWAL, walEnabled bool) (*Persistence, error) {
	if err := ensureDir(dir); err != nil {
		return nil, err
	}
	bs, err := store.OpenBlockStore(filepath.Join(dir, "blocks"), ep)
	if err != nil {
		return nil, fmt.Errorf("node: block store: %w", err)
	}
	cf := store.NewConfigFile(dir, ep)
	if err := cf.LoadPersisted(); err != nil {
		bs.Close()
		return nil, fmt.Errorf("node: load config: %w", err)
	}
	p := &Persistence{Blocks: bs, ConfigFile: cf}
	if walEnabled {
		w, err := wal.NewLoggerConfig(filepath.Join(dir, "wal"), syncWAL).Build()
		if err != nil {
			bs.Close()
			return nil, fmt.Errorf("node: wal: %w", err)
		}
		p.WAL = w
	}
	return p, nil
}

func (p *Persistence) Close() {
	if p == nil {
		return
	}
	if p.WAL != nil {
		p.WAL.Close()
	}
	if p.Blocks != nil {
		p.Blocks.Close()
	}
}

// logEvent — append-before-dispatch (Rust main.rs ordering): every WAL-logged
// event is persisted before MonadState.Update sees it. The log is a waltrace —
// upstream semantics: observability + out-of-band forensic replay, never
// re-dispatched on boot (crash state comes from forkpoint + safety.rlp).
func (p *Persistence) logEvent(ev glue.MonadEvent) error {
	if p == nil || p.WAL == nil || !glue.IsWalLogged(ev) {
		return nil
	}
	payload, err := glue.LogFriendlyMonadEvent{Timestamp: wallNow(), Event: ev}.Serialize()
	if err != nil {
		return fmt.Errorf("wal serialize %T: %w", ev, err)
	}
	if _, ts := ev.(glue.EvTimestampUpdate); ts {
		return p.WAL.PushNoSync(payload)
	}
	return p.WAL.Push(payload)
}

// writeSafety — persist watermarks iff they moved. Must run after every
// Update and before the resulting commands execute, so a vote/propose/NE
// can never reach the wire before its safety record is durable.
func (p *Persistence) writeSafety(dir string, snap *consensus.SafetySnapshot) error {
	enc := snap.EncodeRLP(nil)
	if bytes.Equal(enc, p.lastSafety) {
		return nil
	}
	if err := store.WriteSafety(dir, snap); err != nil {
		return err
	}
	p.lastSafety = enc
	return nil
}

// loadPersistedState — the restart builder inputs: the last checkpoint as the
// forkpoint plus the locked-epoch validator sets covering it. Returns
// (nil, nil, nil) on a fresh data dir so the caller can take the genesis path.
func loadPersistedState(dir string, ep *exec.Protocol) (*cstypes.Checkpoint, []glue.ValidatorSetDataWithEpoch, error) {
	cp, err := store.LoadCheckpoint(dir, ep)
	if err != nil {
		return nil, nil, err
	}
	if cp == nil {
		return nil, nil, nil
	}
	sets, err := store.LoadValidatorSets(dir)
	if err != nil {
		return nil, nil, err
	}
	byEpoch := map[types.Epoch]glue.ValidatorSetDataWithEpoch{}
	for _, s := range sets {
		byEpoch[s.Epoch] = s
	}
	locked := make([]glue.ValidatorSetDataWithEpoch, 0, len(cp.ValidatorSets))
	for _, le := range cp.ValidatorSets {
		s, ok := byEpoch[le.Epoch]
		if !ok {
			return nil, nil, fmt.Errorf("node: locked epoch %v missing validator set", le.Epoch)
		}
		locked = append(locked, s)
	}
	return cp, locked, nil
}
