package store

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/abhijitkrm/monadbft-go/consensus"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/rlp"
)

// safetyFile — the durable Safety watermarks (safety.rlp). Written on every
// safety mutation before the resulting vote/propose/no-endorse reaches the
// wire: after a crash the restored watermarks prevent double-signing, which
// forkpoint+blockstore alone cannot (votes cast after the last checkpoint
// would otherwise be repeatable).
const safetyFile = "safety.rlp"

// WriteSafety — atomic safety.rlp update (wip + rename, same as forkpoint).
func WriteSafety(dir string, snap *consensus.SafetySnapshot) error {
	return writeAtomic(dir, safetyFile, "", snap.EncodeRLP(nil))
}

// LoadSafety — read the persisted safety snapshot, nil if absent.
func LoadSafety(dir string, ep *exec.Protocol) (*consensus.SafetySnapshot, error) {
	data, err := os.ReadFile(filepath.Join(dir, safetyFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var snap consensus.SafetySnapshot
	if err := snap.DecodeRLP(rlp.NewStream(data), ep); err != nil {
		return nil, fmt.Errorf("store: decode safety: %w", err)
	}
	return &snap, nil
}
