package node

import (
	"context"
	"sync"

	"github.com/abhijitkrm/monadbft-go/glue"
)

// eventQueue — unbounded, closeable MonadEvent queue. Every event source
// (transport inbound, timers, timestamper, executors, loopback) pushes here;
// the node loop pops and dispatches into MonadState.
//
// Unbounded by design: consensus events must never block their producer
// (a full channel would deadlock a synchronous producer pushing from inside
// the dispatch loop, e.g. loopback). Backpressure on inbound network traffic
// belongs at the transport's socket read layer, not here.
type eventQueue struct {
	mu     sync.Mutex
	q      []glue.MonadEvent
	notify chan struct{} // cap 1: at most one waiter wakes per push batch
	closed bool
}

func newEventQueue() *eventQueue {
	return &eventQueue{notify: make(chan struct{}, 1)}
}

// push appends an event. Silently dropped after close — late producers
// (in-flight timers, executor completions racing shutdown) must not panic.
func (q *eventQueue) push(e glue.MonadEvent) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	q.q = append(q.q, e)
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// tryPop returns the next event without blocking.
func (q *eventQueue) tryPop() (glue.MonadEvent, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.q) == 0 {
		return nil, false
	}
	ev := q.q[0]
	q.q[0] = nil // don't retain the reference
	q.q = q.q[1:]
	return ev, true
}

// pop blocks until an event is available, the queue is closed-and-empty, or
// ctx is done. After close, already-queued events are still returned (drain
// semantics: in-flight ledger commits complete on graceful shutdown).
func (q *eventQueue) pop(ctx context.Context) (glue.MonadEvent, bool) {
	for {
		if ev, ok := q.tryPop(); ok {
			return ev, true
		}
		q.mu.Lock()
		closed := q.closed
		q.mu.Unlock()
		if closed {
			return nil, false
		}
		select {
		case <-q.notify:
		case <-ctx.Done():
			return nil, false
		}
	}
}

// close stops producers and lets the consumer drain what remains.
func (q *eventQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	select {
	case q.notify <- struct{}{}:
	default:
	}
}
