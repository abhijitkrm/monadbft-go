package bridge

// engine_config_test.go — EngineConfig bounds/cross-field checks, the
// /metrics exposition, and retention-window store fallback.

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	abci "github.com/cometbft/cometbft/abci/types"

	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/types"
	testconstants "github.com/cosmos/evm/testutil/constants"
)

func TestEngineConfigValidate(t *testing.T) {
	ok := DefaultEngineConfig()
	if err := ok.Validate(); err != nil {
		t.Fatalf("default config invalid: %v", err)
	}
	cases := []struct {
		name string
		mut  func(*EngineConfig)
	}{
		{"bad transport", func(c *EngineConfig) { c.Transport = "pigeon" }},
		{"zero delta", func(c *EngineConfig) { c.DeltaMs = 0 }},
		{"negative delta", func(c *EngineConfig) { c.DeltaMs = -5 }},
		{"huge delta", func(c *EngineConfig) { c.DeltaMs = 120_000 }},
		{"delay < 2", func(c *EngineConfig) { c.ExecutionDelay = 1 }},
		{"statesync under delay", func(c *EngineConfig) { c.StatesyncThreshold = 2 }},
		{"tiny retain window", func(c *EngineConfig) { c.RetainBlocks = 512; c.RetainBlocks = 8 }},
		{"prune under retain", func(c *EngineConfig) {
			c.RetainBlocks = 512
			c.PruneKeepBlocks = 128
		}},
		{"epoch under delay", func(c *EngineConfig) { c.EpochLength = 2 }},
		{"negative ts latency", func(c *EngineConfig) { c.TimestampLatencyMs = -1 }},
		{"bad bind ip", func(c *EngineConfig) { c.BindIP = "not-an-ip" }},
		{"bad beneficiary", func(c *EngineConfig) { c.Beneficiary = "0x1234" }},
	}
	for _, tc := range cases {
		c := ok
		tc.mut(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: expected validation error", tc.name)
		}
	}
}

// TestMetricsHandler — the same handler /metrics serves emits monadbft_-
// prefixed consensus counters from a live node.
func TestMetricsHandler(t *testing.T) {
	nodes, _, _, _ := bringUpDevnet(t, "e2e-metrics", "tcp", 0)
	defer func() {
		for _, dn := range nodes {
			if dn.eng != nil {
				dn.stop(t)
			}
		}
	}()
	dn := nodes[0]
	probeWaitHeight(t, dn.me, 3, 60*time.Second)

	rec := httptest.NewRecorder()
	metrics.PrometheusHandler(dn.me.curNode().Metrics()).ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if body := rec.Body.String(); !strings.Contains(body, "monadbft_") {
		t.Fatalf("metrics output lacks monadbft_ prefix:\n%.400s", body)
	}
}

// TestRetentionFallback — small retain window: in-memory maps stay bounded,
// pre-window heights resolve through the durable store.
func TestRetentionFallback(t *testing.T) {
	vals := MakeValidators(1)
	cfg := EvmdConfig{ChainID: "ret-test", EVMChainID: testconstants.EighteenDecimalsChainID}
	app, _, err := NewEvmdApp(cfg, vals)
	if err != nil {
		t.Fatal(err)
	}
	const retain = 4
	app.SetRetain(retain)

	rs, err := OpenResultStore(t.TempDir() + "/res")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	if err := app.AttachStore(rs); err != nil {
		t.Fatal(err)
	}

	for h := int64(1); h <= 12; h++ {
		res, err := app.FinalizeBlock(context.Background(), &abci.RequestFinalizeBlock{
			Height: h, Time: time.Now(), Hash: []byte(fmt.Sprintf("ret-%d", h)),
		})
		if err != nil {
			t.Fatalf("finalize %d: %v", h, err)
		}
		if err := app.Commit(context.Background()); err != nil {
			t.Fatalf("commit %d: %v", h, err)
		}
		// recordCommit is the ledger-facing write — the engine's canonical
		// path calls it; drive it directly to exercise the window+store.
		app.recordCommit(h, resultEntry{
			header:    &EvmFinalizedHeader{Number: types.SeqNum(h), AppHash: res.AppHash},
			txResults: res.TxResults,
			events:    res.Events,
		})
	}
	// genesis (results[0]) is pinned: bound is retain+1.
	if got := len(app.results); got > retain+1 {
		t.Fatalf("in-memory results window %d > retain+1 %d", got, retain+1)
	}
	for h := int64(1); h <= 12; h++ {
		if app.Result(h) == nil {
			t.Fatalf("height %d unresolvable through store fallback", h)
		}
	}
}
