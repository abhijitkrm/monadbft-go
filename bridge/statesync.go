package bridge

import (
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/swarm"
)

// NopStateSync — a statesync executor that drops all commands and never
// emits events. The bridge milestone runs without state sync (thresholds are
// sized to avoid it); Cosmos snapshot-based sync is a later milestone.
type NopStateSync struct{}

var _ swarm.StateSync = NopStateSync{}

func (NopStateSync) Exec([]glue.StateSyncCommand) {}
func (NopStateSync) Ready() bool                  { return false }
func (NopStateSync) Next() glue.MonadEvent        { return nil }
