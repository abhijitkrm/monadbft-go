package bridge

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
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

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/chaincfg"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/net/peerdisc"
	"github.com/abhijitkrm/monadbft-go/node"
	"github.com/abhijitkrm/monadbft-go/store"
	"github.com/abhijitkrm/monadbft-go/swarm"
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

	BaseFee     uint64 `json:"base_fee"`    // proposal base-fee stamp (wei)
	Beneficiary string `json:"beneficiary"` // 20B hex proposer fee recipient (default: self cons addr)
	BindIP      string `json:"bind_ip"`     // raptorcast bind address (default 0.0.0.0)
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
		BaseFee:            swarm.MinBaseFee,
		BindIP:             "0.0.0.0",
	}
}

type monadEngine struct {
	node    *node.Node
	persist *node.Persistence
	rs      *ResultStore
	ledger  *Ledger
	spec    *SpecApp
	app     *App
	bus     *cmttypes.EventBus
	client  *Client

	stopOnce sync.Once
}

var _ engine.Engine = (*monadEngine)(nil)

func (e *monadEngine) Client() rpcclient.Client     { return e.client }
func (e *monadEngine) EventBus() *cmttypes.EventBus { return e.bus }
func (e *monadEngine) IsRunning() bool              { return e.node != nil && e.node.IsRunning() }

func (e *monadEngine) Stop() error {
	var err error
	e.stopOnce.Do(func() { err = e.stop() })
	return err
}

func (e *monadEngine) stop() error {
	// node.Stop owns persist.Close (the node loop closes it on drain).
	e.node.Stop()
	// Drain canonical commits before closing spec: the commit worker may
	// still consult the spec index (CommittedResult) for its tail.
	if e.ledger != nil {
		e.ledger.Close()
	}
	if e.spec != nil {
		e.spec.Close()
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
	return nil
}

// Start — engine.Starter for "monadbft": keys + binding + genesis handshake
// + consensus node + transport + RPC client + event bus.
func Start(opts engine.Options) (engine.Engine, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("monadbft: nil comet config")
	}
	root := opts.Config.RootDir
	cfg := DefaultEngineConfig()
	if raw, err := os.ReadFile(filepath.Join(root, "config", "monadbft.json")); err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("monadbft.json: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if cfg.ExecutionDelay < 2 {
		return nil, fmt.Errorf("monadbft: execution_delay must be ≥2 (seq-1 cannot speculate safely)")
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

	// executors
	dataDir := filepath.Join(root, "data", "monadbft")
	persist, err := node.OpenPersistence(dataDir, Evm, true, true)
	if err != nil {
		return nil, err
	}
	spec := NewAsyncSpecApp(bapp)
	ledger := NewLedger(bapp, spec)
	cp, err := store.LoadCheckpoint(dataDir, Evm)
	if err != nil {
		persist.Close()
		return nil, fmt.Errorf("forkpoint: %w", err)
	}
	if err := ledger.AttachBlockStore(persist.Blocks, cp); err != nil {
		persist.Close()
		return nil, fmt.Errorf("blockstore: %w", err)
	}
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
	statesyncExec := NewStateSync(bapp, ledger, spec)

	transport, err := buildTransport(cfg, selfID, secp, vsd, root, dataDir)
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
				P:                 swarm.DefaultChainParams(),
				EpochLength:       epochLen,
				EpochStartDelay:   types.Round(maxU64),
				StakingActivation: types.Epoch(maxU64),
			},
			StatesyncToLiveThreshold:   types.SeqNum(cfg.StatesyncThreshold),
			LiveToStatesyncThreshold:   types.SeqNum(cfg.StatesyncThreshold * 3 / 2),
			StartExecutionThreshold:    types.SeqNum(cfg.StatesyncThreshold / 2),
			TimestampLatencyEstimateNs: types.U128FromUint64(10_000_000),
		},
		BlockValidator:         blocktree.MockValidator{},
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
		return nil, fmt.Errorf("monadbft node: %w", err)
	}
	if err := n.Start(context.Background()); err != nil {
		return nil, fmt.Errorf("monadbft start: %w", err)
	}

	bus := cmttypes.NewEventBus()
	if err := bus.Start(); err != nil {
		return nil, err
	}
	eng := &monadEngine{node: n, persist: persist, rs: rs, ledger: ledger, spec: spec, app: bapp, bus: bus}
	ledger.SetCommitHook(eng.publishCommit)

	client := NewClient(bapp, ledger, pool, bus, genDoc,
		func() bool { return n.State().IsStatesyncing() }, self)
	if err := client.Start(); err != nil {
		return nil, err
	}
	eng.client = client
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
}

// -- helpers --

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
	selfRecord := peerdisc.NewMonadNameRecord(
		peerdisc.NewNameRecordWithPorts(ip,
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
			MaxNumPeers:                     200,
			MaxGroupSize:                    10,
			PingRateLimitPerSecond:          100,
			PersistedPeersPath:              filepath.Join(dataDir, "peers.rlp"),
			RngSeed:                         uint64(self.PubKey[0])*2654435761 + 1,
		},
	})
}
