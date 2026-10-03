package bridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"
	cryptoenc "github.com/cometbft/cometbft/crypto/encoding"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	rpcclient "github.com/cometbft/cometbft/rpc/client"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/cosmos/cosmos-sdk/server"
	"github.com/cosmos/evm/engine"
	"github.com/cosmos/evm/evmd"
	evmtypes "github.com/cosmos/evm/x/vm/types"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/net/peerdisc"
	"github.com/abhijitkrm/monadbft-go/node"
	"github.com/abhijitkrm/monadbft-go/store"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Kind — registered engine backend name (`engine = "monadbft"`).
const Kind = "monadbft"

func init() { engine.Register(Kind, Start) }

// EngineConfig — `monadbft.json` under the node's config dir. Consensus
// parameters that upstream keeps in chain config live here until
// x/consensuskeys / a config.toml section exists.
type EngineConfig struct {
	// "tcp" | "raptorcast" | "none" (single-node dev).
	Transport string `json:"transport"`
	// TCP listen addr — the tcp transport's listener, or the raptorcast
	// composite's TCP socket (blocksync/statesync/point-to-point).
	TCPAddress string `json:"tcp_address"`
	// RaptorCast sockets (required when transport=raptorcast).
	UDPPort  int `json:"udp_port"`
	AuthPort int `json:"auth_port"`
	// PeersFile — bootstrap records JSON (upstream node.toml [[peers]]).
	PeersFile string `json:"peers_file"`
	// KeyFile — this node's monad consensus keys (default monad.key.json).
	KeyFile string `json:"key_file"`
	// ValidatorsFile — genesis binding: cons pubkey → secp+BLS pubkeys.
	// Optional for single-validator chains (self-binding derives).
	ValidatorsFile string `json:"validators_file"`

	ExecutionDelay     uint64 `json:"execution_delay"`     // ≥2
	DeltaMs            int    `json:"delta_ms"`            // round timer base (default 400)
	EpochLength        uint64 `json:"epoch_length"`        // valset boundary (default: never)
	StatesyncThreshold uint64 `json:"statesync_threshold"` // blocks behind → statesync (default 1000)

	// RetainBlocks — in-memory window of committed blocks/results served
	// hot (RPC tip, blocksync, event synthesis). Older heights resolve
	// through the durable stores. 0 = unbounded (dev). Default 4096.
	RetainBlocks uint64 `json:"retain_blocks"`
	// PruneKeepBlocks — durable retention: prune block/result stores to the
	// last N seqs. 0 = archive (keep all). Must be ≥ retain_blocks when set —
	// pruning below the mem window strands the on-demand fallbacks. WARNING:
	// pruning breaks statesync serving for peers behind the floor.
	PruneKeepBlocks uint64 `json:"prune_keep_blocks"`

	// TimestampLatencyMs — the timestamp-vs-arrival slack bound stamped on
	// votes (upstream timestamp_latency_estimate). Raise for WAN fleets.
	TimestampLatencyMs int `json:"timestamp_latency_ms"`
	// MetricsAddr — optional "host:port" serving /metrics (Prometheus
	// exposition of the consensus counters). Empty = disabled.
	MetricsAddr string `json:"metrics_addr"`

	// RPCAddr — CometBFT-compat JSON-RPC listen address ("host:port").
	// Empty = use config.toml rpc.laddr; "off" disables the surface.
	RPCAddr string `json:"rpc_addr"`

	// RaptorCast/peerdisc fleet tuning (upstream devnet defaults apply).
	MaxNumPeers  int `json:"max_num_peers"`  // peerdisc cap (default 200)
	MaxGroupSize int `json:"max_group_size"` // raptorcast group size (default 10)

	BaseFee     uint64 `json:"base_fee"`    // proposal base-fee stamp (wei, default 100 gwei)
	Beneficiary string `json:"beneficiary"` // 20B hex proposer fee recipient (default: self cons addr)
	// Chain-param overrides (0 = chaincfg.DefaultParams). These are
	// consensus-critical: all validators MUST agree — treat as
	// chain config, not local tuning.
	TxLimit           uint64 `json:"tx_limit"`            // txs per proposal
	ProposalGasLimit  uint64 `json:"proposal_gas_limit"`  // gas per proposal
	ProposalByteLimit uint64 `json:"proposal_byte_limit"` // bytes per proposal
	VotePaceMs        int    `json:"vote_pace_ms"`        // vote broadcast pace
	BindIP            string `json:"bind_ip"`             // raptorcast bind address (default 0.0.0.0)
	// AdvertiseIP — the address signed into the self name record that
	// peerdisc gossips (replaces any stale-seq peers-file record). Required
	// when bind_ip is unspecified (0.0.0.0): peers need a routable address.
	AdvertiseIP string `json:"advertise_ip"`
	// PeerdiscRefreshMs — peer-discovery refresh period (bootstrap re-ping,
	// prune, lookup churn). Default 120s (upstream devnet); devnets want ~2s.
	PeerdiscRefreshMs int `json:"peerdisc_refresh_ms"`
}

// DefaultEngineConfig — sane single-node defaults.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Transport:          "none",
		ExecutionDelay:     4,
		DeltaMs:            400,
		StatesyncThreshold: 1000,
		RetainBlocks:       4096,
		TimestampLatencyMs: 10,
		BaseFee:            100_000_000_000, // 100 gwei
		BindIP:             "0.0.0.0",
	}
}

// Validate — bounds + cross-field checks for monadbft.json. Called after
// defaults+file merge in Start; also usable standalone in tests.
func (c EngineConfig) Validate() error {
	switch c.Transport {
	case "", "none", "tcp", "raptorcast":
	default:
		return fmt.Errorf("unknown transport %q", c.Transport)
	}
	if c.DeltaMs <= 0 || c.DeltaMs > 60_000 {
		return fmt.Errorf("delta_ms %d out of range (0, 60000]", c.DeltaMs)
	}
	if c.ExecutionDelay < 2 {
		return fmt.Errorf("execution_delay must be ≥2 (seq-1 cannot speculate safely)")
	}
	// statesync thresholds decompose into StartExecution = thr/2,
	// StatesyncToLive = thr, LiveToStatesync = 3thr/2 — a threshold below
	// 2*execution_delay makes sync machinery unusable relative to the
	// delayed-result window it must serve.
	if c.StatesyncThreshold != 0 && c.StatesyncThreshold < c.ExecutionDelay {
		return fmt.Errorf("statesync_threshold %d must be ≥ execution_delay (%d) or 0",
			c.StatesyncThreshold, c.ExecutionDelay)
	}
	if c.RetainBlocks != 0 && c.RetainBlocks < 128 {
		return fmt.Errorf("retain_blocks %d too small (<128): the serving window must cover execution_delay + recent commits", c.RetainBlocks)
	}
	if c.PruneKeepBlocks != 0 && c.PruneKeepBlocks < c.RetainBlocks {
		return fmt.Errorf("prune_keep_blocks %d < retain_blocks %d: pruning below the mem window strands store fallbacks",
			c.PruneKeepBlocks, c.RetainBlocks)
	}
	if c.EpochLength != 0 && c.EpochLength < c.ExecutionDelay {
		return fmt.Errorf("epoch_length %d < execution_delay %d: epoch locking needs ≥ delay", c.EpochLength, c.ExecutionDelay)
	}
	if c.TimestampLatencyMs < 0 {
		return fmt.Errorf("timestamp_latency_ms < 0")
	}
	if c.BindIP != "" {
		if _, err := netip.ParseAddr(c.BindIP); err != nil {
			return fmt.Errorf("bind_ip: %w", err)
		}
	}
	if c.AdvertiseIP != "" {
		if _, err := netip.ParseAddr(c.AdvertiseIP); err != nil {
			return fmt.Errorf("advertise_ip: %w", err)
		}
	}
	if c.Transport == "raptorcast" {
		bind := netip.MustParseAddr(c.BindIP)
		if !bind.Is4() || bind.IsUnspecified() {
			if _, err := netip.ParseAddr(c.AdvertiseIP); err != nil || c.AdvertiseIP == "" {
				return fmt.Errorf("advertise_ip required when bind_ip is unspecified (raptorcast)")
			}
		}
	}
	if c.Beneficiary != "" {
		if bb, err := hex.DecodeString(c.Beneficiary); err != nil || len(bb) != 20 {
			return fmt.Errorf("beneficiary must be 20B hex")
		}
	}
	return nil
}

type monadEngine struct {
	// nodeMu guards node/persist — supervise swaps them across the
	// live→statesync restart; the swap happens under the lock so Stop can
	// never miss a half-built node.
	nodeMu  sync.Mutex
	node    *node.Node
	persist *node.Persistence
	nodeErr error // last node exit error (informational)

	// openNode rebuilds the consensus node end-to-end: fresh persistence,
	// re-attached ledger, fresh transport. Called by Start and again by
	// supervise on each statesync restart.
	openNode func() (*node.Node, *node.Persistence, error)
	supDone  chan struct{} // closed when supervise exits
	stopCh   chan struct{} // closed by stop — suppresses restarts

	rs     *ResultStore
	ledger *Ledger
	spec   *SpecApp
	app    *App

	metricsSrv *http.Server // /metrics endpoint (empty addr = disabled)
	rpcSrv     *RPCServer   // CometBFT-compat HTTP+WS surface
	bus        *cmttypes.EventBus
	client     *Client
	consSnap   atomic.Pointer[map[string]any] // last-commit round snapshot

	stopOnce sync.Once
}

var _ engine.Engine = (*monadEngine)(nil)

func (e *monadEngine) Client() rpcclient.Client     { return e.client }
func (e *monadEngine) EventBus() *cmttypes.EventBus { return e.bus }

// curNode — the live consensus node handle; nil during a restart window.
func (e *monadEngine) curNode() *node.Node {
	e.nodeMu.Lock()
	defer e.nodeMu.Unlock()
	return e.node
}

func (e *monadEngine) IsRunning() bool {
	n := e.curNode()
	return n != nil && n.IsRunning()
}

// supervise — the in-process operator for the live→statesync transition.
// Rust aborts the node on the maybe_statesync panic and relies on an
// external restart into statesync; here the panic path persists
// statesync-target.rlp first, so supervise just rebuilds the node — the
// next boot re-roots the forkpoint at the observed tip, blocksyncs the
// ancestry, drives the statesync executor, and goes live near the tip.
func (e *monadEngine) supervise() {
	defer close(e.supDone)
	for {
		cur := e.curNode()
		if cur == nil {
			return
		}
		err := cur.Wait()
		if !errors.Is(err, node.ErrNeedStatesync) {
			e.nodeMu.Lock()
			e.nodeErr = err
			e.nodeMu.Unlock()
			return
		}
		nn, persist, rerr := e.openNode()
		if rerr != nil {
			e.nodeMu.Lock()
			e.nodeErr = rerr
			e.nodeMu.Unlock()
			return
		}
		e.nodeMu.Lock()
		select {
		case <-e.stopCh:
			e.nodeMu.Unlock()
			nn.Stop()
			return
		default:
		}
		if err := nn.Start(context.Background()); err != nil {
			e.nodeMu.Unlock()
			e.nodeMu.Lock()
			e.nodeErr = err
			e.nodeMu.Unlock()
			nn.Stop()
			return
		}
		e.node, e.persist = nn, persist
		e.nodeMu.Unlock()
		slog.Info("restarted node into statesync", "engine", "monadbft")
	}
}

func (e *monadEngine) Stop() error {
	var err error
	e.stopOnce.Do(func() { err = e.stop() })
	return err
}

func (e *monadEngine) stop() error {
	close(e.stopCh)
	e.nodeMu.Lock()
	n := e.node
	e.nodeMu.Unlock()
	if n != nil {
		// node.Stop owns persist.Close (the node loop closes it on drain).
		n.Stop()
	}
	<-e.supDone
	// Drain canonical commits before closing spec: the commit worker may
	// still consult the spec index (CommittedResult) for its tail.
	if e.ledger != nil {
		e.ledger.Close()
	}
	if e.spec != nil {
		e.spec.Close()
	}
	if e.rpcSrv != nil {
		e.rpcSrv.Close()
	}
	if e.client != nil && e.client.IsRunning() {
		_ = e.client.Stop()
	}
	if e.bus != nil && e.bus.IsRunning() {
		_ = e.bus.Stop()
	}
	if e.rs != nil {
		_ = e.rs.Close()
	}
	if e.metricsSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = e.metricsSrv.Shutdown(ctx)
		cancel()
	}
	return nil
}

// Start — engine.Starter for "monadbft": keys + binding + genesis handshake
// + consensus node + transport + RPC client + event bus.
func Start(opts engine.Options) (engine.Engine, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("monadbft: nil comet config")
	}
	root := opts.Config.RootDir
	cfgPath := filepath.Join(root, "config", "monadbft.json")
	cfg := DefaultEngineConfig()
	if raw, err := os.ReadFile(cfgPath); err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("monadbft.json: %w", err)
		}
	} else if os.IsNotExist(err) {
		// Scaffold: first boot writes the defaults so operators have the
		// full knob surface to edit. transport=none stays legal (single-
		// node devnets) but is loud — a multi-validator chain on none
		// would silently never peer.
		if raw, err := json.MarshalIndent(cfg, "", "  "); err == nil {
			_ = os.WriteFile(cfgPath, append(raw, '\n'), 0o644)
			slog.Warn("monadbft: scaffolded config/monadbft.json with defaults")
		}
	} else {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("monadbft.json: %w", err)
	}
	if cfg.Transport == "none" || cfg.Transport == "" {
		slog.Warn("monadbft: transport=none — this node cannot peer (single-node dev only)")
	}

	raw, ok := opts.App.(*evmd.EVMD)
	if !ok {
		return nil, fmt.Errorf("monadbft: app is %T, want *evmd.EVMD", opts.App)
	}

	// consensus keys + validator binding
	keyFile := cfg.KeyFile
	if keyFile == "" {
		keyFile = "monad.key.json"
	}
	secp, bls, err := LoadOrGenMonadKey(filepath.Join(root, "config", keyFile))
	if err != nil {
		return nil, err
	}
	selfID := types.NewNodeId(secp.PubKey())

	pvPub, err := opts.PrivValidator.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("priv_validator pubkey: %w", err)
	}
	var consPub cmted25519.PubKey = append(cmted25519.PubKey(nil), pvPub.Bytes()...)

	var vals []Validator
	if cfg.ValidatorsFile != "" {
		vals, err = LoadValidators(resolvePath(root, cfg.ValidatorsFile))
		if err != nil {
			return nil, err
		}
		found := false
		for i := range vals {
			if vals[i].NodeId() == selfID {
				vals[i].Secp, vals[i].Bls = secp, bls
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("self secp pubkey %x not in validators file", secp.PubKey().Bytes())
		}
	} else {
		vals = []Validator{SelfBinding(secp, bls, consPub)}
	}

	genDoc, err := opts.GenDocProvider()
	if err != nil {
		return nil, fmt.Errorf("genesis doc: %w", err)
	}

	// bridge app + durable indexes
	bapp := NewApp(server.NewCometABCIWrapper(raw), vals)
	bapp.SetRaw(raw)
	bapp.SetRetain(int64(cfg.RetainBlocks))
	rs, err := OpenResultStore(filepath.Join(root, "data", "bridge-results"))
	if err != nil {
		return nil, err
	}
	if err := bapp.AttachStore(rs); err != nil {
		rs.Close()
		return nil, err
	}

	// genesis handshake — only when the app has never committed.
	if raw.LastBlockHeight() == 0 && bapp.Height() == 0 {
		req, err := initChainRequest(genDoc)
		if err != nil {
			return nil, err
		}
		if err := bapp.InitChain(context.Background(), req); err != nil {
			return nil, fmt.Errorf("InitChain: %w", err)
		}
	}
	vsd, err := bapp.ValidatorSetData()
	if err != nil {
		return nil, fmt.Errorf("monad validator set: %w", err)
	}
	self := findSelf(vals, selfID)

	// executors — engine-scoped; they survive the supervised statesync
	// restart (the ledger's block index and the app's result index are the
	// durable state the restarted node re-attaches to).
	dataDir := filepath.Join(root, "data", "monadbft")
	spec := NewAsyncSpecApp(bapp)
	ledger := NewLedger(bapp, spec)
	ledger.SetRetain(types.SeqNum(cfg.RetainBlocks), types.SeqNum(cfg.PruneKeepBlocks))
	pool := NewTxPool(bapp)
	pool.SetFeeParams(cfg.BaseFee, 0, 0)
	epochLen := types.SeqNum(cfg.EpochLength)
	if cfg.EpochLength == 0 {
		epochLen = types.SeqNum(^uint64(0)) // boundary never reached
	}
	valsetExec, err := NewValSet(bapp, epochLen)
	if err != nil {
		return nil, err
	}

	var beneficiary [20]byte
	if cfg.Beneficiary != "" {
		bb, err := hex.DecodeString(cfg.Beneficiary)
		if err != nil || len(bb) != 20 {
			return nil, fmt.Errorf("beneficiary must be 20B hex")
		}
		copy(beneficiary[:], bb)
	} else {
		copy(beneficiary[:], self.ConsAddr())
	}
	delay := types.SeqNum(cfg.ExecutionDelay)
	maxU64 := ^uint64(0)

	eng := &monadEngine{
		rs: rs, ledger: ledger, spec: spec, app: bapp,
		supDone: make(chan struct{}), stopCh: make(chan struct{}),
	}
	eng.openNode = func() (*node.Node, *node.Persistence, error) {
		persist, err := node.OpenPersistence(dataDir, Evm, true, true)
		if err != nil {
			return nil, nil, err
		}
		cp, err := store.LoadCheckpoint(dataDir, Evm)
		if err != nil {
			persist.Close()
			return nil, nil, fmt.Errorf("forkpoint: %w", err)
		}
		if err := ledger.AttachBlockStore(persist.Blocks, cp); err != nil {
			persist.Close()
			return nil, nil, fmt.Errorf("blockstore: %w", err)
		}
		transport, err := buildTransport(cfg, selfID, secp, vsd, root, dataDir)
		if err != nil {
			persist.Close()
			return nil, nil, err
		}
		// The statesync executor is session-scoped — startedExecution and the
		// in-flight sync belong to a single consensus boot, not the engine.
		statesyncExec := NewStateSync(bapp, ledger, spec)
		n, err := node.Open(node.Config{
			Dir:         dataDir,
			Protocol:    Evm,
			Persistence: persist,
			Keypair:     secp,
			CertKeypair: bls,
			Beneficiary: beneficiary,
			ConsensusConfig: &consensusstate.Config{
				ExecutionDelay: delay,
				Delta:          time.Duration(cfg.DeltaMs) * time.Millisecond,
				ChainConfig: chaincfg.StaticConfig{
					P:                 cfg.chainParams(),
					EpochLength:       epochLen,
					EpochStartDelay:   types.Round(maxU64),
					StakingActivation: types.Epoch(maxU64),
				},
				StatesyncToLiveThreshold:   types.SeqNum(cfg.StatesyncThreshold),
				LiveToStatesyncThreshold:   types.SeqNum(cfg.StatesyncThreshold * 3 / 2),
				StartExecutionThreshold:    types.SeqNum(cfg.StatesyncThreshold / 2),
				TimestampLatencyEstimateNs: types.U128FromUint64(uint64(cfg.TimestampLatencyMs) * 1_000_000),
			},
			BlockValidator:         NewEvmBlockValidator(raw.TxConfig().TxDecoder(), ethChainID(raw)),
			BlockPolicy:            blocktree.NewEvmBlockPolicy(delay, cfg.BaseFee, 0, 0),
			StateRead:              NewStateRead(bapp, spec),
			GenesisValidators:      vsd,
			StatesyncExpandToGroup: true,
			ServeStatesync:         true,
			Executors: node.Executors{
				Ledger:    ledger,
				TxPool:    pool,
				ValSet:    valsetExec,
				StateSync: statesyncExec,
				Transport: transport,
			},
			SyncWAL: true,
		})
		if err != nil {
			persist.Close()
			return nil, nil, fmt.Errorf("monadbft node: %w", err)
		}
		return n, persist, nil
	}

	n, persist, err := eng.openNode()
	if err != nil {
		return nil, err
	}
	eng.node, eng.persist = n, persist
	if err := n.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("monadbft start: %w", err)
	}

	bus := cmttypes.NewEventBus()
	if err := bus.Start(); err != nil {
		return nil, err
	}
	eng.bus = bus
	ledger.SetCommitHook(eng.publishCommit)

	client := NewClient(bapp, ledger, pool, bus, genDoc,
		func() bool {
			cur := eng.curNode()
			return cur != nil && cur.State().IsStatesyncing()
		}, self)
	client.SetPeersFunc(func() []glue.PeerEntry {
		if n := eng.curNode(); n != nil {
			return n.Peers()
		}
		return nil
	})
	if err := client.Start(); err != nil {
		return nil, err
	}

	// CometBFT-compat HTTP/WS RPC — CometBFT normally binds this itself
	// from rpc.laddr; monadbft must serve its own. rpc_addr in
	// monadbft.json overrides ("" or "off" disables).
	laddr := cfg.RPCAddr
	if laddr == "" && opts.Config != nil && opts.Config.RPC != nil {
		laddr = strings.TrimPrefix(opts.Config.RPC.ListenAddress, "tcp://")
	}
	if laddr != "" && laddr != "off" {
		srv := NewRPCServer(bapp, ledger, pool, selfID, genDoc.ChainID)
		srv.SetPeersFunc(func() []glue.PeerEntry {
			if n := eng.curNode(); n != nil {
				return n.Peers()
			}
			return nil
		})
		srv.SetEventBus(bus)
		srv.SetConsStateFunc(func() map[string]any {
			if snap := eng.consSnap.Load(); snap != nil {
				return *snap
			}
			return map[string]any{"height": "0", "step": "no commits yet"}
		})
		if err := srv.Start(laddr); err != nil {
			slog.Warn("monadbft: RPC server start failed", "addr", laddr, "err", err)
		} else {
			eng.rpcSrv = srv
			slog.Info("monadbft: CometBFT RPC listening", "addr", srv.Addr())
		}
	}
	eng.client = client

	// /metrics — live counters off the current node (resolves per-request so
	// a supervised statesync restart doesn't strand the endpoint).
	if cfg.MetricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := eng.curNode()
			if n == nil {
				http.Error(w, "restarting", http.StatusServiceUnavailable)
				return
			}
			metrics.PrometheusHandler(n.Metrics()).ServeHTTP(w, r)
		}))
		eng.metricsSrv = &http.Server{Addr: cfg.MetricsAddr, Handler: mux,
			ReadHeaderTimeout: 5 * time.Second}
		go func() {
			if err := eng.metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Warn("metrics server stopped", "err", err)
			}
		}()
	}
	go eng.supervise()
	return eng, nil
}

// publishCommit — fire the comet event set subscribers expect after a
// commit: NewBlock → NewBlockHeader → NewBlockEvents → per-tx Tx events.
// Runs on the node loop under the ledger mutex; publishes are queued to
// the bus's pubsub server, never blocking on subscribers.
func (e *monadEngine) publishCommit(seq int64) {
	b := e.ledger.committedBlock(types.SeqNum(uint64(seq)))
	if b == nil {
		return
	}
	cmtBlock := e.app.SynthBlock(b)
	_, _, _, txRes, events, updates, ok := e.app.CommittedEntry(seq)
	if !ok {
		return
	}
	_ = e.bus.PublishEventNewBlock(cmttypes.EventDataNewBlock{
		Block:   cmtBlock,
		BlockID: cmttypes.BlockID{Hash: cmtBlock.Hash()},
		ResultFinalizeBlock: abcitypes.ResponseFinalizeBlock{
			Events:           events,
			TxResults:        txRes,
			ValidatorUpdates: updates,
			AppHash:          cmtBlock.Header.AppHash,
		},
	})
	_ = e.bus.PublishEventNewBlockHeader(cmttypes.EventDataNewBlockHeader{Header: cmtBlock.Header})
	_ = e.bus.PublishEventNewBlockEvents(cmttypes.EventDataNewBlockEvents{
		Height: seq, Events: events,
	})
	for i, tx := range cmtBlock.Data.Txs {
		var res abcitypes.ExecTxResult
		if i < len(txRes) && txRes[i] != nil {
			res = *txRes[i]
		}
		_ = e.bus.PublishEventTx(cmttypes.EventDataTx{TxResult: abcitypes.TxResult{
			Height: seq, Index: uint32(i), Tx: tx, Result: res,
		}})
	}

	// dump_consensus_state snapshot — this hook is the one safe read
	// point into consensus internals (the state machine itself is owned
	// by the node loop). Height/round describe the last finalized block;
	// CometBFT's live step is not reproducible outside the loop.
	h := b.Header
	qc := h.QC
	id := h.GetId()
	author := ""
	if e.app != nil {
		author = strings.ToUpper(hex.EncodeToString(e.app.ConsAddr(h.Author)))
	}
	vals := e.app.Validators()
	valsJSON := make([]map[string]any, len(vals))
	for i, v := range vals {
		valsJSON[i] = map[string]any{
			"address":      strings.ToUpper(hex.EncodeToString(v.Address)),
			"voting_power": strconv.FormatInt(v.VotingPower, 10),
		}
	}
	votes := e.app.LastCommit(qc)
	votesJSON := make([]map[string]any, len(votes.Votes))
	for i, v := range votes.Votes {
		votesJSON[i] = map[string]any{
			"validator_address": strings.ToUpper(hex.EncodeToString(v.Validator.Address)),
			"block_id_flag":     int(v.BlockIdFlag),
		}
	}
	e.consSnap.Store(&map[string]any{
		"height":              strconv.FormatInt(seq, 10),
		"round":               strconv.FormatUint(uint64(qc.Info.Round), 10),
		"step":                "commit",
		"start_time":          time.Unix(0, int64(h.TimestampNs.Uint64())).UTC().Format(time.RFC3339Nano),
		"commit_time":         time.Now().UTC().Format(time.RFC3339Nano),
		"proposal_block_hash": strings.ToUpper(hex.EncodeToString(id[:])),
		"proposer_address":    author,
		"validators":          valsJSON,
		"votes":               votesJSON,
	})
}

// -- helpers --

func maxOr(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func resolvePath(root, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(root, "config", p)
}

func findSelf(vals []Validator, id types.NodeId) *Validator {
	for i := range vals {
		if vals[i].NodeId() == id {
			return &vals[i]
		}
	}
	return nil
}

// initChainRequest — RequestInitChain from the comet genesis doc.
func initChainRequest(genDoc *cmttypes.GenesisDoc) (*abcitypes.RequestInitChain, error) {
	var vals []abcitypes.ValidatorUpdate
	for _, v := range genDoc.Validators {
		pk, err := cryptoenc.PubKeyToProto(v.PubKey)
		if err != nil {
			return nil, err
		}
		vals = append(vals, abcitypes.ValidatorUpdate{PubKey: pk, Power: v.Power})
	}
	var params *cmtproto.ConsensusParams
	if genDoc.ConsensusParams != nil {
		p := genDoc.ConsensusParams.ToProto()
		params = &p
	}
	return &abcitypes.RequestInitChain{
		Time:    genDoc.GenesisTime,
		ChainId: genDoc.ChainID,

		ConsensusParams: params,
		Validators:      vals,
		AppStateBytes:   genDoc.AppState,
		InitialHeight:   genDoc.InitialHeight,
	}, nil
}

// chainParams — DefaultParams with monadbft.json overrides applied.
func (c EngineConfig) chainParams() chaincfg.Params {
	p := chaincfg.DefaultParams()
	if c.TxLimit > 0 {
		p.TxLimit = c.TxLimit
	}
	if c.ProposalGasLimit > 0 {
		p.ProposalGasLimit = c.ProposalGasLimit
	}
	if c.ProposalByteLimit > 0 {
		p.ProposalByteLimit = c.ProposalByteLimit
	}
	if c.VotePaceMs > 0 {
		p.VotePace = time.Duration(c.VotePaceMs) * time.Millisecond
	}
	return p
}

// ethChainID — the EVM module's chain-id for tx static checks; nil when the
// app hasn't configured one (test apps) so the check is skipped.
func ethChainID(raw *evmd.EVMD) *big.Int {
	if cc := evmtypes.GetEthChainConfig(); cc != nil && cc.ChainID != nil {
		return cc.ChainID
	}
	return nil
}

// buildTransport — the networking half of the engine: tcp | raptorcast |
// none (single-node devnet).
func buildTransport(cfg EngineConfig, self types.NodeId, key *crypto.SecpKeyPair,
	vsd glue.ValidatorSetData, root, dataDir string) (node.Transport, error) {
	switch cfg.Transport {
	case "", "none":
		// Single-node devnet: no sockets, but consensus still needs its own
		// proposal/votes delivered back (self-delivery, same as the mesh).
		return node.NewSoloTransport(self), nil
	case "tcp":
		if cfg.TCPAddress == "" {
			return nil, fmt.Errorf("monadbft: tcp transport requires tcp_address")
		}
		host, portStr, err := net.SplitHostPort(cfg.TCPAddress)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(host); err != nil && host != "" {
			return nil, fmt.Errorf("tcp_address: %w", err)
		}
		_ = portStr
		// Static peering reuses the bootstrap peers file — each signed name
		// record's TCP socket is the dial target (self is filtered inside
		// BootstrapRecords).
		peers := map[types.NodeId]string{}
		if cfg.PeersFile != "" {
			recs, err := node.LoadBootstrapPeersFile(resolvePath(root, cfg.PeersFile))
			if err != nil {
				return nil, fmt.Errorf("tcp peers_file: %w", err)
			}
			for id, nr := range node.BootstrapRecords(recs, self) {
				peers[id] = nr.TCPSocket().String()
			}
		}
		return node.NewTCPTransport(self, node.TCPConfig{
			Key:    key,
			Listen: cfg.TCPAddress,
			Peers:  peers,
		}), nil
	case "raptorcast":
		return buildRaptorcast(cfg, self, key, vsd, root, dataDir)
	default:
		return nil, fmt.Errorf("monadbft: unknown transport %q", cfg.Transport)
	}
}

// buildRaptorcast — the upstream composite: wireauth UDP + plain UDP + TCP,
// peerdisc bootstrap from the peers file, own signed name record.
func buildRaptorcast(cfg EngineConfig, self types.NodeId, key *crypto.SecpKeyPair,
	vsd glue.ValidatorSetData, root, dataDir string) (node.Transport, error) {
	ip := netip.MustParseAddr(cfg.BindIP)
	tcpPort := 0
	if cfg.TCPAddress != "" {
		_, ps, err := net.SplitHostPort(cfg.TCPAddress)
		if err != nil {
			return nil, err
		}
		if tcpPort, err = strconv.Atoi(ps); err != nil {
			return nil, err
		}
	}
	if cfg.UDPPort == 0 || cfg.AuthPort == 0 || tcpPort == 0 {
		return nil, fmt.Errorf("monadbft: raptorcast requires tcp_address, udp_port, auth_port")
	}

	// Self-record seq must exceed whatever the peers file advertised for us
	// (peers drop stale-seq records as anti-replay). Wall-clock seconds, as
	// upstream does when re-signing self records at boot.
	// The self record's address is what peers dial — advertise_ip, falling
	// back to bind_ip when it's a concrete (routable) address.
	adv := ip
	if cfg.AdvertiseIP != "" {
		adv = netip.MustParseAddr(cfg.AdvertiseIP)
	}
	selfRecord := peerdisc.NewMonadNameRecord(
		peerdisc.NewNameRecordWithPorts(adv,
			uint16(tcpPort), uint16(cfg.UDPPort), uint16(cfg.AuthPort), 0, 0,
			uint64(time.Now().Unix())),
		key)

	var bootstrap map[types.NodeId]peerdisc.MonadNameRecord
	if cfg.PeersFile != "" {
		peers, err := node.LoadBootstrapPeersFile(resolvePath(root, cfg.PeersFile))
		if err != nil {
			return nil, err
		}
		bootstrap = node.BootstrapRecords(peers, self)
	}

	epochVals := map[types.Epoch]map[types.NodeId]struct{}{1: {}}
	for _, vd := range vsd.Validators {
		epochVals[1][vd.NodeId] = struct{}{}
	}

	refresh := 120 * time.Second
	if cfg.PeerdiscRefreshMs > 0 {
		refresh = time.Duration(cfg.PeerdiscRefreshMs) * time.Millisecond
	}
	return node.NewRaptorcastTransport(node.RaptorcastTransportConfig{
		SelfID:   self,
		Key:      key,
		AuthUDP:  netip.AddrPortFrom(ip, uint16(cfg.AuthPort)),
		PlainUDP: netip.AddrPortFrom(ip, uint16(cfg.UDPPort)),
		TCPAddr:  netip.AddrPortFrom(ip, uint16(tcpPort)),
		PeerDisc: peerdisc.PeerDiscoveryBuilder{
			SelfID:          self,
			SelfRecord:      selfRecord,
			CurrentEpoch:    1,
			EpochValidators: epochVals,
			BootstrapPeers:  bootstrap,
			// upstream devnet node.toml values
			RefreshPeriod:                   refresh,
			RequestTimeout:                  5 * time.Second,
			UnresponsivePruneThreshold:      5,
			LastParticipationPruneThreshold: types.Round(5000),
			MinNumPeers:                     0,
			MaxNumPeers:                     maxOr(cfg.MaxNumPeers, 200),
			MaxGroupSize:                    maxOr(cfg.MaxGroupSize, 10),
			PingRateLimitPerSecond:          100,
			PersistedPeersPath:              filepath.Join(dataDir, "peers.rlp"),
			RngSeed:                         uint64(self.PubKey[0])*2654435761 + 1,
		},
	})
}
