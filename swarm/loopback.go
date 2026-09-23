package swarm

import "github.com/abhijitkrm/monadbft-go/glue"

// LoopbackExecutor — port of monad-updaters::loopback::LoopbackExecutor.
//
// Routes MonadEvents produced by one child state back into MonadState as
// inputs (e.g. StateRootUpdate). Delivery is async and events must be
// idempotent on the target.
type LoopbackExecutor struct {
	buffer []glue.MonadEvent
}

var _ EventSource = (*LoopbackExecutor)(nil)

func NewLoopbackExecutor() *LoopbackExecutor { return &LoopbackExecutor{} }

// Exec — Rust Executor::exec(LoopbackCommand::Forward).
func (l *LoopbackExecutor) Exec(cmds []glue.LoopbackCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.LoopbackForward:
			l.buffer = append(l.buffer, c.Event)
		}
	}
}

func (l *LoopbackExecutor) Ready() bool { return len(l.buffer) > 0 }

func (l *LoopbackExecutor) Next() glue.MonadEvent {
	if len(l.buffer) == 0 {
		return nil
	}
	ev := l.buffer[0]
	l.buffer = l.buffer[1:]
	return ev
}
