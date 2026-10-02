// Package node is the production node runtime: MonadState driven by a
// wall-clock event loop over real timers, a real transport, and durable
// persistence (WAL + block store + forkpoint). It is the daemon half of the
// Rust `monad-node` binary — the app-facing executors (ledger/txpool/valset)
// stay behind the same command seam the swarm simulator uses, so the bridge
// module can drive a Cosmos app without the core knowing about ABCI.
package node

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/consensus"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/monadstate"
	"github.com/abhijitkrm/monadbft-go/store"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// Config — one MonadBFT node's construction parameters.
type Config struct {
	// Dir is the persistence root (wal/, blocks/, forkpoint.rlp,
	// validators.rlp). Required.
	Dir string
	// Protocol is the execution-lane codec family (exec.Mock for tests,
	// bridge.Evm for evmd).
	Protocol *exec.Protocol

	// Identity. NodeId = secp256k1 pubkey; CertKeypair signs QCs/TCs/NECs.
	Keypair     *crypto.SecpKeyPair
	CertKeypair *crypto.BlsKeyPair
	// Beneficiary — proposer fee-recipient address stamped into proposals.
	Beneficiary [20]byte

	ConsensusConfig *consensusstate.Config

	// Consensus-side seams over execution state — the app-facing hal(ves of
	// the blocktree BlockPolicy. For the EVM lane these come from the bridge.
	BlockValidator blocktree.BlockValidator
	BlockPolicy    blocktree.BlockPolicy
	StateRead      blocktree.ExecutionStateRead

	// GenesisValidators is the epoch-1 locked validator set, used only when
	// Dir holds no persisted forkpoint (fresh chain start). The forkpoint's
	// locked epochs are all mapped onto this set at genesis.
	GenesisValidators glue.ValidatorSetData

	// Executors — see Executors. Transport may be nil (single-node).
	Executors Executors

	// Persistence — optional pre-opened durable handles. Supply when an
	// executor needs the block store before Open runs init commands (e.g.
	// the bridge ledger seeds its index from it). Nil → Open opens Dir.
	Persistence *Persistence

	Timestamper TimestamperConfig

	// SyncWAL fsyncs every WAL record (production-grade durability). When
	// false the OS flushes at its leisure — a crash can lose the tail of the
	// event log. WAL can be disabled entirely only for tests (DisableWAL).
	SyncWAL    bool
	DisableWAL bool

	BlocksyncOverridePeers []types.NodeId
	BlocksyncRngSeed       *uint64
	StatesyncExpandToGroup bool
	ServeStatesync         bool

	// Crash — test-only fault injection; see CrashHook. Nil in production.
	Crash CrashHook

	Logger *slog.Logger
}

// Node — one running MonadBFT node.
type Node struct {
	cfg         Config
	log         *slog.Logger
	state       *monadstate.MonadState
	exec        Executors
	queue       *eventQueue
	timers      *timerExec
	timestamper *timestamper

	persist    *Persistence
	configFile *store.ConfigFile

	mu      sync.Mutex
	started bool
	stopped bool
	crashed bool
	fatal   error
	done    chan struct{}

	// curEv — the event mid-dispatch on the loop goroutine; consulted by
	// crashAt inside execCommands so a mid-dispatch crash knows its event.
	curEv glue.MonadEvent
}

// Open builds a node: opens persistence, constructs MonadState from the
// persisted forkpoint (or genesis), replays the WAL, and executes the
// resulting init commands. The node is not running until Start.
func Open(cfg Config) (*Node, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("node: Dir required")
	}
	if cfg.Protocol == nil {
		return nil, fmt.Errorf("node: Protocol required")
	}
	if cfg.Keypair == nil || cfg.CertKeypair == nil {
		return nil, fmt.Errorf("node: Keypair and CertKeypair required")
	}
	if cfg.ConsensusConfig == nil {
		return nil, fmt.Errorf("node: ConsensusConfig required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Timestamper.Period == 0 {
		cfg.Timestamper = DefaultTimestamperConfig()
	}

	persist := cfg.Persistence
	if persist == nil {
		var err error
		persist, err = OpenPersistence(cfg.Dir, cfg.Protocol, cfg.SyncWAL, !cfg.DisableWAL)
		if err != nil {
			return nil, err
		}
	}

	n := &Node{
		cfg:        cfg,
		log:        cfg.Logger,
		exec:       cfg.Executors,
		queue:      newEventQueue(),
		done:       make(chan struct{}),
		persist:    persist,
		configFile: persist.ConfigFile,
	}
	n.timers = newTimerExec(n.queue.push)
	n.timestamper = newTimestamper(cfg.Timestamper)

	// Executors that produce events asynchronously get a wake func; pulling
	// happens in the loop via drainPull.
	wire := func(e any) {
		if p, ok := e.(WakeProducer); ok {
			p.SetWakeFunc(n.wake)
		}
	}
	wire(cfg.Executors.Ledger)
	wire(cfg.Executors.TxPool)
	wire(cfg.Executors.ValSet)
	wire(cfg.Executors.StateSync)
	wire(cfg.Executors.ControlPanel)

	if t := cfg.Executors.Transport; t != nil {
		t.SetHandler(n.handleInbound)
	}

	// Safety watermarks: restored from safety.rlp when present — the
	// double-sign guard across crashes. Merged (max-only) into the
	// forkpoint-derived Safety at the sync→live transition.
	var restored *consensus.Safety
	if snap, err := store.LoadSafety(cfg.Dir, cfg.Protocol); err != nil {
		persist.Close()
		return nil, fmt.Errorf("node: load safety: %w", err)
	} else if snap != nil {
		restored = consensus.SafetyFromSnapshot(snap)
		n.log.Info("restored safety watermarks",
			"highest_vote", snap.HighestVote.Uint64(),
			"qc_round", snap.HighCertificateQcRound.Uint64())
	}

	// Forkpoint: persisted checkpoint or genesis.
	var forkpoint monadstate.Forkpoint
	var lockedEpochs []glue.ValidatorSetDataWithEpoch
	cp, locked, err := loadPersistedState(cfg.Dir, cfg.Protocol)
	if err != nil {
		persist.Close()
		return nil, err
	}
	if cp != nil {
		forkpoint = monadstate.Forkpoint{Checkpoint: *cp}
		lockedEpochs = locked
		n.log.Info("resuming from persisted forkpoint",
			"root", fmt.Sprintf("%x", cp.Root[:8]), "hc_round", cp.HighCertificate.Round().Uint64(),
			"locked_epochs", len(lockedEpochs))
	} else {
		forkpoint = monadstate.ForkpointGenesis()
		if len(cfg.GenesisValidators.Validators) == 0 {
			persist.Close()
			return nil, fmt.Errorf("node: fresh dir requires GenesisValidators")
		}
		for _, le := range forkpoint.Checkpoint.ValidatorSets {
			lockedEpochs = append(lockedEpochs, glue.ValidatorSetDataWithEpoch{
				Epoch:      le.Epoch,
				Validators: cfg.GenesisValidators,
			})
		}
	}

	state, initCmds := monadstate.Builder{
		LeaderElection:            validator.WeightedRoundRobin{},
		BlockValidator:            cfg.BlockValidator,
		BlockPolicy:               cfg.BlockPolicy,
		StateRead:                 cfg.StateRead,
		Forkpoint:                 forkpoint,
		LockedEpochValidators:     lockedEpochs,
		Keypair:                   cfg.Keypair,
		CertKeypair:               cfg.CertKeypair,
		Beneficiary:               cfg.Beneficiary,
		BlockSyncOverridePeers:    cfg.BlocksyncOverridePeers,
		BlocksyncRngSeed:          cfg.BlocksyncRngSeed,
		WhitelistedStatesyncNodes: map[types.NodeId]struct{}{},
		StatesyncExpandToGroup:    cfg.StatesyncExpandToGroup,
		ServeStatesync:            cfg.ServeStatesync,
		ConsensusConfig:           cfg.ConsensusConfig,
		RestoredSafety:            restored,
	}.Build()
	n.state = state

	// Init commands: epoch validator sets to router, timers, maybe-start.
	n.execCommands(initCmds)

	return n, nil
}

// IsRunning — true once started until Stop.
func (n *Node) IsRunning() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.started && !n.stopped
}

// Start launches the transport, timestamp feed, and the event loop.
func (n *Node) Start(ctx context.Context) error {
	n.mu.Lock()
	if n.started {
		n.mu.Unlock()
		return fmt.Errorf("node: already started")
	}
	n.started = true
	n.mu.Unlock()

	if t := n.exec.Transport; t != nil {
		if err := t.Start(); err != nil {
			return fmt.Errorf("node: transport start: %w", err)
		}
	}
	n.timestamper.start(n.queue.push)

	go n.loop()
	go func() {
		select {
		case <-ctx.Done():
			n.Stop()
		case <-n.done:
		}
	}()
	return nil
}

// Stop gracefully shuts the node down: transport first (stops inbound),
// then timers/timestamper (stops new events), then the queue closes and the
// loop drains remaining events before resources are released.
func (n *Node) Stop() {
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return
	}
	n.stopped = true
	started := n.started
	n.mu.Unlock()

	if !started {
		// Never Start()'ed: no loop owns persist.Close; do it here.
		n.persist.Close()
		close(n.done)
		return
	}

	if t := n.exec.Transport; t != nil {
		t.Close()
	}
	n.timers.close()
	n.timestamper.stop()
	n.queue.close()
	<-n.done
}

// Wait blocks until the node exits (Stop called or fatal error).
func (n *Node) Wait() error {
	<-n.done
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.fatal
}

// Err exposes a fatal consensus/persistence error after Stop.
func (n *Node) Err() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.fatal
}

// loop — the single dispatch goroutine: WAL-append → MonadState.Update →
// executor dispatch. Mirrors swarm.Node::step_until on wall clock.
func (n *Node) loop() {
	defer close(n.done)
	for {
		// Harvest pull-executors before blocking — anything they produced
		// during the last dispatch (or asynchronously via wake) lands ahead
		// of whatever network/timer traffic queued since.
		n.drainPull()
		ev, ok := n.queue.pop(context.Background())
		if !ok {
			n.persist.Close()
			return
		}
		if ev == nil {
			continue // wake sentinel — drainPull runs next iteration
		}
		n.handle(ev)
	}
}

// handle — one event through the machine. A panic in MonadState or an
// executor is fatal: the node stops (a half-alive consensus participant is
// worse than a dead one — Rust aborts the process on consensus panics too).
func (n *Node) handle(ev glue.MonadEvent) {
	defer func() {
		if r := recover(); r != nil {
			n.log.Error("consensus panic — shutting down", "event", fmt.Sprintf("%T", ev), "panic", r,
				"stack", string(debug.Stack()))
			n.mu.Lock()
			n.fatal = fmt.Errorf("consensus panic on %T: %v", ev, r)
			n.mu.Unlock()
			go n.Stop()
		}
	}()
	switch ev.(type) {
	case glue.EvBlockSyncRequest, glue.EvBlockSyncTimeout,
		glue.EvBlockSyncSelfRequest, glue.EvBlockSyncSelfCancelRequest,
		glue.EvBlockSyncResponse, glue.EvBlockSyncSelfResponse,
		glue.EvConsensusBlockSync, glue.EvStateSyncInbound,
		glue.EvStateSyncOutbound, glue.EvStateSyncDoneSync,
		glue.EvStateSyncBlockSync, glue.EvStateSyncRequestSync:
		n.log.Debug("sync event", "type", fmt.Sprintf("%T", ev), "ev", fmt.Sprintf("%+v", ev))
	}
	n.crashAt(CrashBeforeWAL, ev)
	if err := n.persist.logEvent(ev); err != nil {
		panic(fmt.Sprintf("wal append: %v", err))
	}
	n.crashAt(CrashAfterWAL, ev)
	cmds := n.state.Update(ev)
	n.curEv = ev
	n.crashAt(CrashAfterUpdate, ev)
	// Durability ordering (CometBFT saveSigned): the safety watermarks
	// guarding any vote/propose this Update produced must be on disk before
	// the corresponding publish can reach the wire in execCommands.
	n.persistSafety()
	n.crashAt(CrashAfterSafety, ev)
	n.execCommands(cmds)
}

// persistSafety — durability ordering: the watermarks that guard a
// vote/propose/no-endorse must be on disk before the message can be sent.
// Runs after Update (which mutates Safety) and before execCommands (which
// publishes the resulting RouterPublish commands).
func (n *Node) persistSafety() {
	live := n.state.Consensus()
	if live == nil || live.Consensus == nil || live.Consensus.Safety == nil {
		return
	}
	if err := n.persist.writeSafety(n.cfg.Dir, live.Consensus.Safety.Snapshot()); err != nil {
		panic(fmt.Sprintf("safety persist: %v", err))
	}
}

// handleInbound — transport callback: decode wire bytes into a MonadEvent
// and enqueue. Malformed traffic is dropped, never fatal.
func (n *Node) handleInbound(from types.NodeId, payload []byte) {
	msg, err := glue.DecodeMonadMessage(payload, n.cfg.Protocol)
	if err != nil {
		n.log.Debug("inbound decode failed", "from", from, "err", err)
		return
	}
	ev := msg.Event(from)
	if ev == nil {
		return
	}
	n.queue.push(ev)
}

// SendTransaction — external tx ingress (RPC submission, later gossip).
func (n *Node) SendTransaction(tx []byte) {
	if n.exec.TxPool != nil {
		n.exec.TxPool.SendTransaction(tx)
	}
}

// Accessors.
func (n *Node) State() *monadstate.MonadState { return n.state }
func (n *Node) Metrics() *metrics.Metrics     { return n.state.Metrics() }
func (n *Node) NodeID() types.NodeId          { return n.state.NodeID() }

// BlockStore — the node's durable block store. Executors that persist
// consensus blocks (the bridge ledger) need the same handle the node opened.
func (n *Node) BlockStore() *store.BlockStore { return n.persist.Blocks }

func wallNow() time.Time { return time.Now().UTC() }

func ensureDir(dir string) error { return os.MkdirAll(dir, 0o777) }
