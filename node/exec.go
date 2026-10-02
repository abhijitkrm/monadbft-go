package node

import (
	"github.com/abhijitkrm/monadbft-go/glue"
)

// EventSink — push-model event injection: the node's own producers
// (timers, timestamper) and the queue itself use it. Executors stay
// pull-model (EventSource) for parity with the swarm.
type EventSink func(glue.MonadEvent)

// EventSource — the pull-model event contract every executor shares with the
// swarm (swarm.EventSource): the executor buffers MonadEvents produced while
// handling commands; the node drains them after every dispatch round.
type EventSource interface {
	Ready() bool
	Next() glue.MonadEvent
}

// WakeProducer — optional seam for executors that produce events outside an
// Exec call (async work: real statesync downloads, external tx ingress). The
// node hands the executor a wake func at Open; calling it pokes the event
// loop, which then drains the executor's pull queue. Without it, events
// produced while the loop is idle would starve until the next unrelated event.
type WakeProducer interface {
	SetWakeFunc(func())
}

// Executors — the production executor set, mirroring swarm.MockExecutor's
// slots. All Exec methods are invoked on the node loop goroutine in Rust's
// dispatch order (timer → timestamp → ledger → txpool → configfile → valset
// → loopback → statesync → router); they must return promptly — heavy work
// belongs on executor-owned goroutines reporting back via the pull queue.
type Executors struct {
	// Ledger — block persistence + execution commits. Must tolerate replayed
	// LedgerCommit commands for already-committed seqnums (WAL replay
	// contract: idempotent below the app's committed height).
	Ledger interface {
		Exec([]glue.LedgerCommand)
		EventSource
	}
	// TxPool — proposal building + tx ingress/forwarding.
	TxPool interface {
		Exec([]glue.TxPoolCommand)
		EventSource
		SendTransaction(tx []byte)
	}
	// ValSet — epoch-boundary validator-set snapshots.
	ValSet interface {
		Exec([]glue.ValSetCommand)
		EventSource
	}
	// StateSync — snapshot sync upstream/downstream serving.
	StateSync interface {
		Exec([]glue.StateSyncCommand)
		EventSource
	}
	// ControlPanel — metrics/peer/log-filter reads+writes. Optional.
	ControlPanel interface {
		Exec([]glue.ControlPanelCommand)
	}
	// Transport — RouterCommand executor; see Transport contract.
	Transport Transport
}

// execCommands — Rust Executor::exec(Command): split into families and apply
// in upstream's order. Runs on the node loop goroutine.
func (n *Node) execCommands(cmds []glue.Command) {
	g := glue.SplitCommands(cmds)

	n.timers.exec(g.Timer)
	n.timestamper.handle(g.Timestamp)

	if n.exec.Ledger != nil {
		n.exec.Ledger.Exec(g.Ledger)
	}
	if n.exec.TxPool != nil {
		n.exec.TxPool.Exec(g.TxPool)
	}
	if n.configFile != nil {
		n.configFile.Exec(g.ConfigFile)
	}
	if n.exec.ValSet != nil {
		n.exec.ValSet.Exec(g.ValSet)
	}

	// Loopback: events produced by one child state re-enter MonadState
	// dispatch. The swarm buffers them in a pull queue; the node pushes
	// straight into the event queue — same FIFO position relative to
	// everything produced by this round.
	for _, cmd := range g.Loopback {
		if c, ok := cmd.(glue.LoopbackForward); ok {
			n.queue.push(c.Event)
		}
	}

	if n.exec.StateSync != nil {
		n.exec.StateSync.Exec(g.StateSync)
	}

	n.execRouter(g.Router)

	if n.exec.ControlPanel != nil {
		n.exec.ControlPanel.Exec(g.ControlPanel)
	}
	// ConfigReload: nop until config reload exists (upstream warns + nops
	// most fields too).
}

// drainPull — harvest ready events from the pull-model executors. Runs after
// every dispatch round and whenever an async executor calls its wake func.
func (n *Node) drainPull() {
	drain := func(src EventSource) {
		if src == nil {
			return
		}
		for src.Ready() {
			if ev := src.Next(); ev != nil {
				n.queue.push(ev)
			} else {
				break
			}
		}
	}
	drain(n.exec.Ledger)
	drain(n.exec.TxPool)
	drain(n.exec.ValSet)
	drain(n.exec.StateSync)
}

// wake — pushes a nil sentinel so the loop breaks out of pop, runs
// drainPull, and re-blocks. Used by WakeProducer executors.
func (n *Node) wake() { n.queue.push(nil) }

// execRouter — RouterCommand dispatch onto the Transport.
func (n *Node) execRouter(cmds []glue.RouterCommand) {
	t := n.exec.Transport
	if t == nil {
		return
	}
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.RouterPublish:
			t.Send(c.Target, c.Message.Serialize())
		case glue.RouterPublishWithPriority:
			t.Send(c.Target, c.Message.Serialize()) // no priority lane on TCP
		case glue.RouterPublishToFullNodes:
			t.PublishToFullNodes(c.Epoch, c.Round, c.BroadcastMode, c.Message.Serialize())
		case glue.RouterAddEpochValidatorSet:
			t.AddEpochValidatorSet(c.Epoch, c.EpochStart, c.ValidatorSet)
		case glue.RouterUpdateCurrentRound:
			t.UpdateCurrentRound(c.Epoch, c.Round)
		case glue.RouterUpdatePeers:
			t.UpdatePeers(c.PeerEntries, c.DedicatedFullNodes, c.PrioritizedFullNodes)
		case glue.RouterUpdateFullNodes:
			t.UpdateFullNodes(c.DedicatedFullNodes, c.PrioritizedFullNodes)
		case glue.RouterGetPeers, glue.RouterGetFullNodes:
			// Response channel not ported (upstream uses a oneshot); the
			// control-panel peers read is served by transport.Peers() when
			// an RPC surface lands.
		}
	}
}
