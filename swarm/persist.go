package swarm

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/monadstate"
	"github.com/abhijitkrm/monadbft-go/store"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/wal"
)

// wallNow — the record timestamp. Rust uses Utc::now() (wall clock, not swarm
// time); it is informational and never read by consensus.
func wallNow() time.Time { return time.Now().UTC() }

// PersistSpec — per-node persistence configuration. When set on a
// NodeBuilder, the node gets:
//
//	{Dir}/wal/          chunked write-ahead event log (monad-wal port)
//	{Dir}/blocks/      pebble consensus block store
//	{Dir}/forkpoint.rlp, validators.rlp, *.bak — config-file persistence
type PersistSpec struct {
	Dir string
	// SyncWAL fsyncs every record (production-grade durability; slower).
	SyncWAL bool
	// The WAL is append-only waltrace (Rust monad-node parity): every
	// dispatched event is logged for observability but never replayed.
	// Restart recovery is forkpoint + validators + block store + the
	// surviving execution state — the same as Rust's forkpoint.rs tests.
}

// Persistence — the open handles created from a PersistSpec at Build.
type Persistence struct {
	Spec       PersistSpec
	WAL        *wal.Logger
	Blocks     *store.BlockStore
	ConfigFile *store.ConfigFile
}

func (p PersistSpec) walDir() string { return filepath.Join(p.Dir, "wal") }
func (p PersistSpec) blockDir() string {
	return filepath.Join(p.Dir, "blocks")
}

// open creates the wal/blocks/configfile handles under Spec.Dir.
func (p PersistSpec) open(ep *exec.Protocol) (*Persistence, error) {
	bs, err := store.OpenBlockStore(p.blockDir(), ep)
	if err != nil {
		return nil, fmt.Errorf("persist: block store: %w", err)
	}
	cfg := store.NewConfigFile(p.Dir, ep)
	if err := cfg.LoadPersisted(); err != nil {
		bs.Close()
		return nil, fmt.Errorf("persist: load config: %w", err)
	}
	w, err := wal.NewLoggerConfig(p.walDir(), p.SyncWAL).Build()
	if err != nil {
		bs.Close()
		return nil, fmt.Errorf("persist: wal: %w", err)
	}
	return &Persistence{Spec: p, WAL: w, Blocks: bs, ConfigFile: cfg}, nil
}

// Close releases the wal and block store.
func (p *Persistence) Close() {
	if p.WAL != nil {
		p.WAL.Close()
	}
	if p.Blocks != nil {
		p.Blocks.Close()
	}
}

// logEvent — append-before-dispatch: every WAL-logged event is pushed before
// MonadState.Update sees it (Rust main.rs ordering).
func (p *Persistence) logEvent(ev glue.MonadEvent) {
	if !glue.IsWalLogged(ev) {
		return
	}
	lfe := glue.LogFriendlyMonadEvent{Timestamp: wallNow(), Event: ev}
	payload, err := lfe.Serialize()
	if err != nil {
		panic(fmt.Sprintf("persist: wal serialize %T: %v", ev, err))
	}
	if err := p.WAL.Push(payload); err != nil {
		panic(fmt.Sprintf("persist: wal push: %v", err))
	}
}

// LoadPersistedState — the restart builder inputs: the last checkpoint as the
// forkpoint plus the trailing locked-epoch validator sets.
func LoadPersistedState(dir string, ep *exec.Protocol) (*monadstate.Forkpoint, []glue.ValidatorSetDataWithEpoch, error) {
	cp, err := store.LoadCheckpoint(dir, ep)
	if err != nil {
		return nil, nil, err
	}
	if cp == nil {
		return nil, nil, fmt.Errorf("persist: no forkpoint at %s", dir)
	}
	sets, err := store.LoadValidatorSets(dir)
	if err != nil {
		return nil, nil, err
	}
	if len(sets) == 0 {
		return nil, nil, fmt.Errorf("persist: no validator sets at %s", dir)
	}
	// The forkpoint's locked epochs must be covered by the persisted sets.
	fp := monadstate.Forkpoint{Checkpoint: *cp}
	byEpoch := map[types.Epoch]glue.ValidatorSetDataWithEpoch{}
	for _, s := range sets {
		byEpoch[s.Epoch] = s
	}
	var locked []glue.ValidatorSetDataWithEpoch
	for _, le := range cp.ValidatorSets {
		s, ok := byEpoch[le.Epoch]
		if !ok {
			return nil, nil, fmt.Errorf("persist: locked epoch %v missing validator set", le.Epoch)
		}
		locked = append(locked, s)
	}
	return &fp, locked, nil
}
