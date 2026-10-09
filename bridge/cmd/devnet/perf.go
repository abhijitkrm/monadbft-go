package main

// Engine-neutral performance capture for soak/bench runs: client-observed
// commit times (node0 /status polled every 50ms) joined with per-tx submit
// times. Latency = time the including height first became visible on node0
// minus the moment the submitting RPC call started — i.e. submit → final
// and executed, as a client sees it, for either engine.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type submitLog struct {
	mu sync.Mutex
	at map[string]time.Time // upper-hex sha256(tx) → submit start
}

func newSubmitLog() *submitLog { return &submitLog{at: map[string]time.Time{}} }

func (s *submitLog) add(tx []byte, t time.Time) {
	h := sha256.Sum256(tx)
	s.mu.Lock()
	s.at[strings.ToUpper(hex.EncodeToString(h[:]))] = t
	s.mu.Unlock()
}

type heightWatch struct {
	mu   sync.Mutex
	seen map[int64]time.Time
	last int64
}

func newHeightWatch() *heightWatch { return &heightWatch{seen: map[int64]time.Time{}} }

// run — poll node i's /status; every height up to the reported tip gets
// the first observation time (heights committed between polls share it).
func (w *heightWatch) run(ctx context.Context, i int) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			h := nodeHeight(i)
			now := time.Now()
			w.mu.Lock()
			if w.last == 0 && h > 0 {
				w.last = h // pre-load heights aren't measured
			}
			for x := w.last + 1; x <= h; x++ {
				w.seen[x] = now
			}
			if h > w.last {
				w.last = h
			}
			w.mu.Unlock()
		}
	}
}

type perfStats struct {
	WindowS         float64 `json:"window_s"`
	Heights         int     `json:"heights"`
	BlockIntervalMs float64 `json:"block_interval_ms_mean"`
	EmptyBlocks     int     `json:"empty_blocks"`
	CommittedTxs    int     `json:"committed_txs"`
	CommittedTPS    float64 `json:"committed_tps"`
	Submitted       int     `json:"submitted_tracked"`
	Included        int     `json:"included"`
	// DuplicateTxs — tx occurrences beyond the first across committed
	// blocks (same hash in more than one block). Must be 0: a repeat
	// fails on nonce and wastes block space.
	DuplicateTxs int     `json:"duplicate_txs"`
	LatencyP50Ms float64 `json:"latency_p50_ms"`
	LatencyP90Ms float64 `json:"latency_p90_ms"`
	LatencyP99Ms float64 `json:"latency_p99_ms"`
	LatencyMaxMs float64 `json:"latency_max_ms"`
}

// computePerf — join the height watch with node0's blocks over the load
// window [loadStart, loadStart+dur].
func computePerf(subs *submitLog, w *heightWatch, loadStart time.Time, dur time.Duration) *perfStats {
	w.mu.Lock()
	seen := make(map[int64]time.Time, len(w.seen))
	for h, t := range w.seen {
		seen[h] = t
	}
	w.mu.Unlock()
	subs.mu.Lock()
	defer subs.mu.Unlock()

	loadEnd := loadStart.Add(dur)
	var hs []int64
	for h, t := range seen {
		if !t.Before(loadStart) && !t.After(loadEnd) {
			hs = append(hs, h)
		}
	}
	sort.Slice(hs, func(a, b int) bool { return hs[a] < hs[b] })
	ps := &perfStats{WindowS: dur.Seconds(), Heights: len(hs), Submitted: len(subs.at)}
	if len(hs) > 1 {
		span := seen[hs[len(hs)-1]].Sub(seen[hs[0]])
		ps.BlockIntervalMs = float64(span.Milliseconds()) / float64(len(hs)-1)
	}

	var lat []float64
	firstSeen := map[[32]byte]bool{}
	for h, t := range seen { // every observed height: late inclusions count for latency
		txs, ok := blockTxs(0, h)
		if !ok {
			continue
		}
		inWindow := !t.Before(loadStart) && !t.After(loadEnd)
		if inWindow {
			ps.CommittedTxs += len(txs)
			if len(txs) == 0 {
				ps.EmptyBlocks++
			}
		}
		for _, tx := range txs {
			sum := sha256.Sum256(tx)
			if firstSeen[sum] {
				ps.DuplicateTxs++
				continue
			}
			firstSeen[sum] = true
			if sub, ok := subs.at[strings.ToUpper(hex.EncodeToString(sum[:]))]; ok {
				ps.Included++
				lat = append(lat, float64(t.Sub(sub).Microseconds())/1000)
			}
		}
	}
	ps.CommittedTPS = float64(ps.CommittedTxs) / dur.Seconds()
	sort.Float64s(lat)
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		return lat[int(p*float64(len(lat)-1))]
	}
	ps.LatencyP50Ms, ps.LatencyP90Ms, ps.LatencyP99Ms = pct(0.50), pct(0.90), pct(0.99)
	if len(lat) > 0 {
		ps.LatencyMaxMs = lat[len(lat)-1]
	}
	return ps
}

// blockTxs — raw txs of the block at height h on node i.
func blockTxs(i int, h int64) ([][]byte, bool) {
	resp, err := getRetry(fmt.Sprintf("http://127.0.0.1:%d/block?height=%d", rpcBase+i, h))
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	var env struct {
		Result struct {
			Block struct {
				Data struct {
					Txs []string `json:"txs"`
				} `json:"data"`
			} `json:"block"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, false
	}
	out := make([][]byte, 0, len(env.Result.Block.Data.Txs))
	for _, b64 := range env.Result.Block.Data.Txs {
		bz, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, false
		}
		out = append(out, bz)
	}
	return out, true
}

// getRetry — GET with backoff on 429/5xx (the RPC shim rate-limits per IP
// unless rpc_rate_per_sec < 0); a throttled height must not be silently
// skipped by the audit or perf scans.
func getRetry(url string) (*http.Response, error) {
	var last error
	for attempt := 0; attempt < 6; attempt++ {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		if err == nil {
			resp.Body.Close()
			last = fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(time.Duration(100<<attempt) * time.Millisecond)
	}
	return nil, last
}

// consensusCounters — selected monadbft_ counters per node from /metrics
// (monadbft engine only; comet nodes don't serve them → empty).
func consensusCounters(n int) map[int]map[string]float64 {
	want := []string{"local_timeout", "rx_execution_lagging", "commit_block", "handle_proposal", "rx_bad_state_root"}
	out := map[int]map[string]float64{}
	client := &http.Client{Timeout: 2 * time.Second}
	for i := 0; i < n; i++ {
		resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsBase+i))
		if err != nil {
			continue
		}
		var body strings.Builder
		_, _ = io.Copy(&body, io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		m := map[string]float64{}
		for _, line := range strings.Split(body.String(), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Fields(line)
			if len(f) != 2 {
				continue
			}
			for _, w := range want {
				if strings.HasSuffix(f[0], "_"+w) {
					var v float64
					fmt.Sscan(f[1], &v)
					m[w] += v
				}
			}
		}
		out[i] = m
	}
	return out
}
