package swarm

import (
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
)

// MockConfigFile — port of monad-updaters::config_file::MockConfigFile.
//
// Records the latest checkpoint and validator-set data the node writes — the
// swarm reads it back via executor.checkpoint() to build restart forkpoints.
type MockConfigFile struct {
	Checkpoint *cstypes.Checkpoint
	ValSetData *glue.ValidatorSetDataWithEpoch
}

func NewMockConfigFile() *MockConfigFile { return &MockConfigFile{} }

// Exec — Rust Executor::exec(ConfigFileCommand).
func (c *MockConfigFile) Exec(cmds []glue.ConfigFileCommand) {
	for _, cmd := range cmds {
		switch cmd := cmd.(type) {
		case glue.ConfigFileCheckpoint:
			cp := cmd.Checkpoint
			c.Checkpoint = &cp
		case glue.ConfigFileValidatorSetData:
			d := cmd.ValidatorSetData
			c.ValSetData = &d
		}
	}
}
