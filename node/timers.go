package node

import (
	"sync"
	"time"

	"github.com/abhijitkrm/monadbft-go/glue"
)

// timerExec — wall-clock TimerCommand executor. Ports the swarm's
// timerQueue semantics onto time.Timer: at most one armed timer per
// TimeoutVariant; scheduling re-arms (schedule implies reset).
//
// On fire, the timer pushes its OnTimeout MonadEvent into the node queue —
// the event is WAL-logged on dispatch like any other, preserving the
// append-before-dispatch invariant.
type timerExec struct {
	mu     sync.Mutex
	timers map[glue.TimeoutVariant]*time.Timer
	sink   EventSink
	closed bool
}

func newTimerExec(sink EventSink) *timerExec {
	return &timerExec{
		timers: make(map[glue.TimeoutVariant]*time.Timer),
		sink:   sink,
	}
}

// exec — Rust Executor::exec(TimerCommand). Called on the node loop
// goroutine; the mutex guards the timer callbacks racing close().
func (t *timerExec) exec(cmds []glue.TimerCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.TimerScheduleReset:
			t.reset(c.Variant)
		case glue.TimerSchedule:
			t.schedule(c.Variant, c.Duration, c.OnTimeout)
		}
	}
}

func (t *timerExec) schedule(variant glue.TimeoutVariant, d time.Duration, onTimeout glue.MonadEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	if old, ok := t.timers[variant]; ok {
		old.Stop()
	}
	ev := onTimeout
	sink := t.sink
	t.timers[variant] = time.AfterFunc(d, func() {
		t.mu.Lock()
		delete(t.timers, variant)
		closed := t.closed
		t.mu.Unlock()
		if !closed {
			sink(ev)
		}
	})
}

func (t *timerExec) reset(variant glue.TimeoutVariant) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.timers[variant]; ok {
		old.Stop()
		delete(t.timers, variant)
	}
}

func (t *timerExec) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for k, tm := range t.timers {
		tm.Stop()
		delete(t.timers, k)
	}
}
