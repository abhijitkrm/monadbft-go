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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/consensusstate"
	"github.com/abhijitkrm/monadbft-go/exec"
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
	)
	flag.Parse()

	if *debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	if *dataDir == "" || *index < 0 || *validators <= 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *index >= *validators {
		log.Fatalf("index %d out of range for %d validators", *index, *validators)
	}

	gv := swarm.CreateKeysWithValidators(*validators)
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

	self := types.NewNodeId(gv.Keys[*index].PubKey())
	transport := node.NewTCPTransport(self, node.TCPConfig{
		Listen: *listen,
		Peers:  peerAddrs,
	})

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
	log.Printf("node %d up at %s (id %s)", *index, transport.Addr(), self)

	if *heightFile != "" {
		go reportHeight(*heightFile, ledger)
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
