// Command monadbft-node runs one MonadBFT validator as a real process — the
// multi-process devnet building block. The execution lane uses the swarm
// mocks (deterministic key table, in-memory state, empty blocks); the bridge
// wires the same node.Node API onto an evmd app for real chains.
//
// Example (4 validators):
//
//	monadbft-node -data /tmp/n0 -index 0 -validators 4 \
//	  -listen 127.0.0.1:9000 -peers 0@127.0.0.1:9000,1@127.0.0.1:9001,... \
//	  -heightfile /tmp/n0.height
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/net/peerdisc"
	"github.com/abhijitkrm/monadbft-go/node"
	"github.com/abhijitkrm/monadbft-go/swarm"
	"github.com/abhijitkrm/monadbft-go/types"
)

func main() {
	var (
		dataDir    = flag.String("data", "", "persistence root (required)")
		index      = flag.Int("index", -1, "validator index into the devnet key table (required)")
		validators = flag.Int("validators", 0, "total validator count (required)")
		listen     = flag.String("listen", "127.0.0.1:0", "TCP bind address")
		peers      = flag.String("peers", "", "peer table: \"idx@host:port,...\" (self entry ignored)")
		execDelay  = flag.Uint64("exec-delay", 4, "execution delay (seqnums)")
		deltaMs    = flag.Uint64("delta", 20, "round delta (ms)")
		heightFile = flag.String("heightfile", "", "write \"height=<n> tip=<hex>\" here on change")
		debug      = flag.Bool("debug", false, "verbose (debug) logging")
		// raptorcast transport (upstream dual-socket datapath)
		transportKind = flag.String("transport", "tcp", "peer transport: tcp | raptorcast")
		bindIP        = flag.String("bind-ip", "127.0.0.1", "bind + advertised IPv4")
		tcpPort       = flag.Int("tcp-port", 0, "raptorcast TCP port (default: -listen port)")
		udpPort       = flag.Int("udp-port", 0, "unauthenticated raptorcast UDP port (required for -transport=raptorcast)")
		authPort      = flag.Int("auth-port", 0, "wireauth UDP port (required for -transport=raptorcast)")
		recordSeq     = flag.Uint64("record-seq", 1, "self name-record sequence number")
		peersFile     = flag.String("peers-file", "", "JSON bootstrap peers file (raptorcast; upstream node.toml [[peers]])")
		genRecord     = flag.String("genrecord", "", "write this node's signed bootstrap record to PATH and exit")
		metricsAddr   = flag.String("metrics-addr", "", "serve Prometheus metrics on ADDR (e.g. :9090)")
	)
	flag.Parse()

	if *debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	if *index < 0 || *validators <= 0 || (*dataDir == "" && *genRecord == "") {
		flag.Usage()
		os.Exit(2)
	}
	if *index >= *validators {
		log.Fatalf("index %d out of range for %d validators", *index, *validators)
	}

	gv := swarm.CreateKeysWithValidators(*validators)
	self := types.NewNodeId(gv.Keys[*index].PubKey())

	if *genRecord != "" {
		// emit this node's signed bootstrap record (upstream node.toml
		// [[peers]] entry) — devnets collect all nodes' records into a JSON
		// array passed back via -peers-file.
		rec := node.SelfBootstrapPeer(
			gv.Keys[*index], mustIP(*bindIP),
			uint16(*tcpPort), uint16(*udpPort), uint16(*authPort),
			0, 0, *recordSeq)
		if err := node.WriteBootstrapPeer(*genRecord, rec); err != nil {
			log.Fatalf("write bootstrap record: %v", err)
		}
		log.Printf("wrote bootstrap record %s (id %s)", *genRecord, self)
		return
	}

	peerAddrs := map[types.NodeId]string{}
	if *peers != "" {
		for _, ent := range strings.Split(*peers, ",") {
			idxStr, addr, ok := strings.Cut(ent, "@")
			if !ok {
				log.Fatalf("bad peer entry %q (want idx@addr)", ent)
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 0 || idx >= *validators {
				log.Fatalf("bad peer index %q", idxStr)
			}
			if idx == *index {
				continue
			}
			peerAddrs[types.NewNodeId(gv.Keys[idx].PubKey())] = addr
		}
	}

	delay := types.SeqNum(*execDelay)
	sr := swarm.NewInMemoryStateGenesis(delay)

	persist, err := node.OpenPersistence(*dataDir, exec.Mock, false, true)
	if err != nil {
		log.Fatalf("OpenPersistence: %v", err)
	}
	ledger := swarm.NewMockLedger(sr).WithBlockStore(persist.Blocks)

	var transport node.Transport
	switch *transportKind {
	case "tcp":
		transport = node.NewTCPTransport(self, node.TCPConfig{
			Key:    gv.Keys[*index],
			Listen: *listen,
			Peers:  peerAddrs,
		})
	case "raptorcast":
		transport = raptorcastTransportOrDie(gv, *index, *bindIP, *listen, *tcpPort, *udpPort, *authPort, *recordSeq, *peersFile, *dataDir)
	default:
		log.Fatalf("unknown -transport %q", *transportKind)
	}

	maxU64 := uint64(math.MaxUint64)
	n, err := node.Open(node.Config{
		Dir:         *dataDir,
		Protocol:    exec.Mock,
		Persistence: persist,
		Keypair:     gv.Keys[*index],
		CertKeypair: gv.CertKeys[*index],
		ConsensusConfig: &consensusstate.Config{
			ExecutionDelay:             delay,
			Delta:                      time.Duration(*deltaMs) * time.Millisecond,
			ChainConfig:                swarm.MockChainConfig(),
			StatesyncToLiveThreshold:   types.SeqNum(100),
			LiveToStatesyncThreshold:   types.SeqNum(150),
			StartExecutionThreshold:    types.SeqNum(50),
			TimestampLatencyEstimateNs: types.U128FromUint64(10_000_000),
		},
		BlockValidator:         blocktree.MockValidator{},
		BlockPolicy:            blocktree.NewMockBlockPolicy(delay),
		StateRead:              sr,
		StatesyncExpandToGroup: true,
		ServeStatesync:         true,
		GenesisValidators:      gv.ValidatorData,
		Executors: node.Executors{
			Ledger:    ledger,
			TxPool:    swarm.NewMockTxPoolExecutor(),
			ValSet:    swarm.NewMockValSetUpdaterNop(gv.ValidatorData, types.SeqNum(maxU64)),
			StateSync: swarm.NewMockStateSyncExecutor(sr),
			Transport: transport,
		},
	})
	if err != nil {
		persist.Close()
		log.Fatalf("Open: %v", err)
	}

	stop := make(chan os.Signal, 2)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	if err := n.Start(context.Background()); err != nil {
		log.Fatalf("Start: %v", err)
	}
	log.Printf("node %d up (transport=%s, id %s)", *index, *transportKind, self)

	if *heightFile != "" {
		go reportHeight(*heightFile, ledger)
	}

	if *metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.PrometheusHandler(n.Metrics()))
		go func() {
			ln, err := net.Listen("tcp", *metricsAddr)
			if err != nil {
				log.Printf("metrics listen %s: %v", *metricsAddr, err)
				return
			}
			log.Printf("metrics on %s/metrics", ln.Addr())
			_ = http.Serve(ln, mux)
		}()
	}

	sig := <-stop
	log.Printf("node %d got %v — stopping", *index, sig)
	n.Stop()
	if err := n.Err(); err != nil {
		log.Fatalf("node error: %v", err)
	}
}

// reportHeight appends "height=N tip=hex" to the heightfile each time the
// finalized tip advances — an append-only history the devnet/test parses to
// check progress and compare tips at a common height across processes.
func reportHeight(path string, l *swarm.MockLedger) {
	last := -1
	for range time.Tick(100 * time.Millisecond) {
		blocks := l.GetFinalizedBlocks()
		if len(blocks) == last {
			continue
		}
		// backfill any heights skipped between polls
		for i := max(0, last); i < len(blocks); i++ {
			b := blocks[i]
			tip := b.Block.GetId()
			line := fmt.Sprintf("height=%d tip=%x\n", b.SeqNum.Uint64(), tip[:16])
			func() {
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
				if err != nil {
					return
				}
				defer f.Close()
				_, _ = f.WriteString(line)
			}()
		}
		last = len(blocks)
	}
}

// mustIP — bind/advertise IPv4 for flags.
func mustIP(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		log.Fatalf("bind ip %q: want IPv4", s)
	}
	return a
}

// raptorcastTransportOrDie builds the upstream composite transport:
// wireauth UDP + non-auth UDP + TCP sockets, peer discovery with bootstrap
// records from -peers-file, and the node's own signed name record.
func raptorcastTransportOrDie(gv swarm.GenesisValidators, index int, bindIP, listen string, tcpPort, udpPort, authPort int, recordSeq uint64, peersFile, dataDir string) node.Transport {
	ip := mustIP(bindIP)
	if tcpPort == 0 {
		_, ps, err := net.SplitHostPort(listen)
		if err != nil {
			log.Fatalf("bad -listen %q: %v", listen, err)
		}
		p, err := strconv.Atoi(ps)
		if err != nil || p == 0 {
			log.Fatalf("bad -listen port %q", ps)
		}
		tcpPort = p
	}
	if udpPort == 0 || authPort == 0 {
		log.Fatalf("-transport=raptorcast requires -udp-port and -auth-port")
	}
	self := types.NewNodeId(gv.Keys[index].PubKey())
	selfRecord := peerdisc.NewMonadNameRecord(
		peerdisc.NewNameRecordWithPorts(ip,
			uint16(tcpPort), uint16(udpPort), uint16(authPort), 0, 0, recordSeq),
		gv.Keys[index])

	var bootstrap map[types.NodeId]peerdisc.MonadNameRecord
	if peersFile != "" {
		peers, err := node.LoadBootstrapPeersFile(peersFile)
		if err != nil {
			log.Fatalf("load %s: %v", peersFile, err)
		}
		bootstrap = node.BootstrapRecords(peers, self)
		log.Printf("bootstrap peers: %d verified", len(bootstrap))
	}

	epochVals := map[types.Epoch]map[types.NodeId]struct{}{1: {}}
	for _, vd := range gv.ValidatorData.Validators {
		epochVals[1][vd.NodeId] = struct{}{}
	}

	tr, err := node.NewRaptorcastTransport(node.RaptorcastTransportConfig{
		SelfID:   self,
		Key:      gv.Keys[index],
		AuthUDP:  netip.AddrPortFrom(ip, uint16(authPort)),
		PlainUDP: netip.AddrPortFrom(ip, uint16(udpPort)),
		TCPAddr:  netip.AddrPortFrom(ip, uint16(tcpPort)),
		PeerDisc: peerdisc.PeerDiscoveryBuilder{
			SelfID:          self,
			SelfRecord:      selfRecord,
			CurrentEpoch:    1,
			EpochValidators: epochVals,
			BootstrapPeers:  bootstrap,
			// upstream devnet node.toml values
			RefreshPeriod:                   120 * time.Second,
			RequestTimeout:                  5 * time.Second,
			UnresponsivePruneThreshold:      5,
			LastParticipationPruneThreshold: types.Round(5000),
			MinNumPeers:                     0,
			MaxNumPeers:                     200,
			MaxGroupSize:                    10,
			PingRateLimitPerSecond:          100,
			PersistedPeersPath:              filepath.Join(dataDir, "peers.rlp"),
			RngSeed:                         uint64(index)*2654435761 + 1,
		},
	})
	if err != nil {
		log.Fatalf("raptorcast transport: %v", err)
	}
	return tr
}
