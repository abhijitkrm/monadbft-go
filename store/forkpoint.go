// Package store ports the durable persistence layer: the consensus block
// store (pebble) and the forkpoint/validator-set file writer — the Go
// equivalent of monad-updaters::config_file::ConfigFile plus a block db.
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// File names mirror Rust: forkpoint.rlp holds the latest checkpoint;
// validators.rlp holds the trailing validator sets (Rust writes toml — ours
// are RLP, the "equivalent" per PLAN).
const (
	forkpointFile  = "forkpoint.rlp"
	validatorsFile = "validators.rlp"
)

// writeAtomic — Rust write_checkpoint_bytes_to_path: write a named backup
// {path}.{seq}.{round}, then write a .wip temp and rename over the target.
func writeAtomic(dir, file string, backupSuffix string, data []byte) error {
	if backupSuffix != "" {
		if err := os.WriteFile(filepath.Join(dir, file+backupSuffix), data, 0o666); err != nil {
			return fmt.Errorf("store: write backup: %w", err)
		}
	}
	tmp := filepath.Join(dir, file+".wip")
	if err := os.WriteFile(tmp, data, 0o666); err != nil {
		return fmt.Errorf("store: write wip: %w", err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, file)); err != nil {
		return fmt.Errorf("store: rename: %w", err)
	}
	return nil
}

// ConfigFile — port of monad-updaters::config_file::ConfigFile: the executor
// that persists checkpoints and validator-set data to disk.
//
// Checkpoint and ValSetData mirror the last written values in memory (Rust's
// MockConfigFile does the same for test inspection / restart forkpoints).
type ConfigFile struct {
	dir        string
	ep         *exec.Protocol
	lastValSet *glue.ValidatorSetDataWithEpoch

	Checkpoint *cstypes.Checkpoint
	ValSetData *glue.ValidatorSetDataWithEpoch
}

func NewConfigFile(dir string, ep *exec.Protocol) *ConfigFile {
	return &ConfigFile{dir: dir, ep: ep}
}

// LastCheckpoint — the last written checkpoint (restart forkpoint).
func (c *ConfigFile) LastCheckpoint() *cstypes.Checkpoint { return c.Checkpoint }

// LoadPersisted — reload the last checkpoint into memory after process
// restart (fs contents survive; the in-memory mirror does not).
func (c *ConfigFile) LoadPersisted() error {
	cp, err := LoadCheckpoint(c.dir, c.ep)
	if err != nil {
		return err
	}
	c.Checkpoint = cp
	sets, err := LoadValidatorSets(c.dir)
	if err != nil {
		return err
	}
	if len(sets) > 0 {
		last := sets[len(sets)-1]
		c.ValSetData = &last
		// lastValSet stays nil — Rust restarts with last_validator_set=None;
		// the init-time UpdateValidators events re-trace the locked epochs.
	}
	return nil
}

// Exec — Rust Executor::exec(ConfigFileCommand).
func (c *ConfigFile) Exec(cmds []glue.ConfigFileCommand) {
	for _, cmd := range cmds {
		switch cmd := cmd.(type) {
		case glue.ConfigFileCheckpoint:
			c.WriteCheckpoint(cmd.RootSeqNum, cmd.Checkpoint)
		case glue.ConfigFileValidatorSetData:
			c.WriteValidatorSet(cmd.ValidatorSetData)
		}
	}
}

// WriteCheckpoint — Rust write_checkpoint: backup at
// forkpoint.rlp.{root_seq}.{hc_round} then atomic forkpoint.rlp update.
func (c *ConfigFile) WriteCheckpoint(rootSeqNum types.SeqNum, cp cstypes.Checkpoint) {
	c.Checkpoint = &cp
	suffix := fmt.Sprintf(".%d.%d", rootSeqNum.Uint64(), cp.HighCertificate.Round().Uint64())
	if err := writeAtomic(c.dir, forkpointFile, suffix, cp.EncodeRLP(nil)); err != nil {
		panic(fmt.Sprintf("store: failed to write checkpoint: %v", err))
	}
}

// WriteValidatorSet — Rust write_validator_set: per-epoch backup at
// validators.{epoch} then atomic validators.rlp update. We keep the on-disk
// coverage superset of Rust's trailing (last, new) pair: persisted sets are
// merged and only epochs below the checkpoint's oldest locked epoch are
// dropped, so validators.rlp always covers the forkpoint's locked epochs.
// Duplicate updates for already-seen epochs are skipped (restart init replays
// the locked-epoch pair over a surviving store); a forward gap remains a
// panic, matching Rust's assert.
func (c *ConfigFile) WriteValidatorSet(vset glue.ValidatorSetDataWithEpoch) {
	c.ValSetData = &vset
	if last := c.lastValSet; last != nil {
		if vset.Epoch <= last.Epoch {
			return // replayed/duplicate epoch — already persisted
		}
		if vset.Epoch != last.Epoch+1 {
			panic(fmt.Sprintf("store: validator set epoch %v does not follow %v", vset.Epoch, last.Epoch))
		}
	}
	c.lastValSet = &vset

	epochBackup := fmt.Sprintf("validators.%d", vset.Epoch.Uint64())
	if err := os.WriteFile(filepath.Join(c.dir, epochBackup), vset.EncodeRLP(nil), 0o666); err != nil {
		panic(fmt.Sprintf("store: failed to write validators backup: %v", err))
	}

	// merge persisted sets with the new one
	byEpoch := map[types.Epoch]glue.ValidatorSetDataWithEpoch{}
	if existing, err := LoadValidatorSets(c.dir); err == nil {
		for _, s := range existing {
			byEpoch[s.Epoch] = s
		}
	}
	byEpoch[vset.Epoch] = vset

	var minLocked types.Epoch
	hasCheckpoint := c.Checkpoint != nil && len(c.Checkpoint.ValidatorSets) > 0
	if hasCheckpoint {
		minLocked = c.Checkpoint.ValidatorSets[0].Epoch
		for _, le := range c.Checkpoint.ValidatorSets {
			if le.Epoch < minLocked {
				minLocked = le.Epoch
			}
		}
	}
	var sets []glue.ValidatorSetDataWithEpoch
	for _, s := range byEpoch {
		if hasCheckpoint && s.Epoch < minLocked {
			continue
		}
		sets = append(sets, s)
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].Epoch < sets[j].Epoch })
	if len(sets) == 0 {
		sets = []glue.ValidatorSetDataWithEpoch{vset}
	}

	data := rlp.AppendList(nil, func(p []byte) []byte {
		for _, s := range sets {
			p = s.EncodeRLP(p)
		}
		return p
	})
	if err := writeAtomic(c.dir, validatorsFile, "", data); err != nil {
		panic(fmt.Sprintf("store: failed to write validators: %v", err))
	}
}

// LoadCheckpoint — read the persisted forkpoint checkpoint, nil if absent.
func LoadCheckpoint(dir string, ep *exec.Protocol) (*cstypes.Checkpoint, error) {
	data, err := os.ReadFile(filepath.Join(dir, forkpointFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cp cstypes.Checkpoint
	if err := cp.DecodeRLP(rlp.NewStream(data), ep); err != nil {
		return nil, err
	}
	return &cp, nil
}

// LoadValidatorSets — read the persisted trailing validator sets.
func LoadValidatorSets(dir string) ([]glue.ValidatorSetDataWithEpoch, error) {
	data, err := os.ReadFile(filepath.Join(dir, validatorsFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	s := rlp.NewStream(data)
	l, err := s.List()
	if err != nil {
		return nil, err
	}
	var out []glue.ValidatorSetDataWithEpoch
	for l.Remaining() > 0 {
		var v glue.ValidatorSetDataWithEpoch
		if err := v.DecodeRLP(l); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := l.Done(); err != nil {
		return nil, err
	}
	return out, s.Done()
}
