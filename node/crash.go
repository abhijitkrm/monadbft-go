package node

import (
	"errors"
	"runtime"

	"github.com/abhijitkrm/monadbft-go/glue"
)

// CrashStage — a persistence stage inside event handling where a simulated
// crash can fire. The stages bound the windows a real crash can land in:
// each is immediately after one durable write or executor boundary.
type CrashStage uint8

const (
	// CrashBeforeWAL — die before the event is appended to the wal.
	CrashBeforeWAL CrashStage = iota
	// CrashAfterWAL — wal append done; Update has not seen the event.
	CrashAfterWAL
	// CrashAfterUpdate — MonadState.Update ran (Safety mutated in memory)
	// but the watermarks have not been persisted and no command escaped.
	CrashAfterUpdate
	// CrashAfterSafety — safety.rlp durable; commands never dispatched.
	// The CometBFT window: signature state persisted, message never sent.
	CrashAfterSafety
	// CrashAfterLedger — dispatch partially complete: ledger/blockstore
	// writes done, forkpoint/config and router publish not yet reached.
	CrashAfterLedger
	// CrashAfterConfigFile — forkpoint.rlp/validators.rlp written; router
	// publish not yet reached.
	CrashAfterConfigFile
	// CrashAfterPublish — router publish attempted: any vote/proposal the
	// event produced is on the wire, then the node dies before the next
	// event — the "sent then died" window.
	CrashAfterPublish
)

// ErrSimulatedCrash — Wait/Err report this after a CrashHook fires so tests
// can distinguish the kill -9 emulation from a clean Stop or a real fault.
var ErrSimulatedCrash = errors.New("node: simulated crash")

// CrashHook — test-only fault injection. Consulted at every CrashStage with
// the event being handled; returning true crashes the node.
//
// The crash emulates process death: the in-flight dispatch is abandoned
// mid-call — no queue drain, no graceful cleanup — and the durable handles
// are released the way the OS releases file locks and sockets on teardown,
// so a new Node can Open the same Dir afterward. Only waltrace/disk state
// survives, exactly like a real crash.
type CrashHook func(stage CrashStage, ev glue.MonadEvent) bool

// crashAt — consult the configured CrashHook. No-op outside the handle loop
// (ev == nil during Open's init dispatch).
func (n *Node) crashAt(stage CrashStage, ev glue.MonadEvent) {
	if n.cfg.Crash == nil || ev == nil {
		return
	}
	if n.cfg.Crash(stage, ev) {
		n.simulateCrash()
	}
}

// simulateCrash — abrupt kill -9 emulation, running on the loop goroutine.
// Closes the resources process teardown would release (sockets, timers,
// file locks) without draining anything, then Goexit unwinds the loop: the
// deferred close(done) fires, marking the node dead.
func (n *Node) simulateCrash() {
	n.mu.Lock()
	n.stopped = true // a later Stop() is a no-op — the process is already gone
	n.crashed = true
	n.fatal = ErrSimulatedCrash
	n.mu.Unlock()

	if t := n.exec.Transport; t != nil {
		t.Close()
	}
	n.timers.close()
	n.timestamper.stop()
	n.persist.Close()
	n.queue.close() // producers are dead too; late pushes drop silently

	runtime.Goexit()
}

// Crashed reports whether the node died via a CrashHook.
func (n *Node) Crashed() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.crashed
}
