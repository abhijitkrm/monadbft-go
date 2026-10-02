package node

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestDevnetMultiProcess — the real-process devnet: four monadbft-node
// processes over TCP, one SIGKILL'd (a true crash — no in-process
// emulation), restarted on the same data dir, and verified to catch up on
// the same chain as its peers.
//
// Each process writes an append-only heightfile ("height=N tip=hex"), which
// the test polls for liveness and parses for cross-process convergence.
func TestDevnetMultiProcess(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	if _, err := os.Stat(goBin); err != nil {
		t.Skip("go toolchain not found — cannot build the devnet binary")
	}
	if testing.Short() {
		t.Skip("multi-process devnet test")
	}

	// Build the node binary once.
	bin := filepath.Join(t.TempDir(), "monadbft-node")
	build := exec.Command(goBin, "build", "-o", bin, "./cmd/monadbft-node")
	build.Dir = ".." // module root (test runs in node/)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build monadbft-node: %v\n%s", err, out)
	}

	const numNodes = 4
	// Allocate four free ports, then release them for the node processes.
	addrs := make([]string, numNodes)
	var peerEnts []string
	for i := 0; i < numNodes; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addrs[i] = ln.Addr().String()
		_ = ln.Close()
	}
	for i, a := range addrs {
		peerEnts = append(peerEnts, fmt.Sprintf("%d@%s", i, a))
	}
	peers := strings.Join(peerEnts, ",")

	dirs := make([]string, numNodes)
	heights := make([]string, numNodes)
	for i := 0; i < numNodes; i++ {
		dirs[i] = t.TempDir()
		heights[i] = filepath.Join(dirs[i], "height.log")
	}

	spawn := func(i int) *exec.Cmd {
		cmd := exec.Command(bin,
			"-data", dirs[i],
			"-index", strconv.Itoa(i),
			"-validators", strconv.Itoa(numNodes),
			"-listen", addrs[i],
			"-peers", peers,
			"-heightfile", heights[i],
			"-exec-delay", "4",
			"-delta", "25",
		)
		logPath := filepath.Join(dirs[i], "node.log")
		lf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = lf, lf
		if err := cmd.Start(); err != nil {
			t.Fatalf("spawn node %d: %v", i, err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
		return cmd
	}

	procs := make([]*exec.Cmd, numNodes)
	for i := 0; i < numNodes; i++ {
		procs[i] = spawn(i)
	}

	// All four reach height 5; tips must agree — same chain everywhere.
	for i := 0; i < numNodes; i++ {
		waitHeightFile(t, heights[i], dirs[i], 5, 60*time.Second)
	}
	checkTips(t, heights, 5)

	// True crash: SIGKILL node 0 mid-run. Peers continue on 3/4 quorum.
	preKill := maxHeight(heights[0])
	if err := procs[0].Process.Kill(); err != nil {
		t.Fatalf("kill node 0: %v", err)
	}
	_, _ = procs[0].Process.Wait()
	for i := 1; i < numNodes; i++ {
		waitHeightFile(t, heights[i], dirs[i], preKill+3, 60*time.Second)
	}

	// Restart node 0 on the same data dir + same address — a real process
	// restart: forkpoint + safety.rlp + blockstore + waltrace reload, dial
	// loops reconnect, and the node catches up via blocksync/statesync.
	procs[0] = spawn(0)
	peerTip := maxHeight(heights[1])
	waitHeightFile(t, heights[0], dirs[0], peerTip, 120*time.Second)
	checkTipsCommon(t, heights)

	for i, p := range procs {
		if p != nil && p.Process != nil {
			_ = p.Process.Kill()
			_, _ = p.Process.Wait()
		}
		_ = i
	}
}

// waitHeightFile polls the append-only heightfile until it reports a
// finalized height ≥ want.
func waitHeightFile(t *testing.T, path, dir string, want int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if maxHeight(path) >= want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	// surface the node's own log before t.TempDir cleanup erases it
	tail := ""
	if data, err := os.ReadFile(filepath.Join(dir, "node.log")); err == nil {
		lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		if len(lines) > 15 {
			lines = lines[len(lines)-15:]
		}
		tail = "\nnode log tail:\n" + strings.Join(lines, "\n")
	}
	t.Fatalf("heightfile %s never reached %d (at %d)%s", path, want, maxHeight(path), tail)
}

// maxHeight — the largest "height=N" seen so far.
func maxHeight(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	best := -1
	for _, line := range strings.Split(string(data), "\n") {
		if h, ok := strings.CutPrefix(line, "height="); ok {
			if nStr, _, ok := strings.Cut(h, " "); ok {
				if n, err := strconv.Atoi(nStr); err == nil && n > best {
					best = n
				}
			}
		}
	}
	return best
}

// checkTipsCommon — committed sets can be sparse (a block whose ancestors
// were absent at commit time leaves a gap), so compare tips at the highest
// seq every process actually reported: same tip ⇒ same canonical chain.
func checkTipsCommon(t *testing.T, heights []string) {
	t.Helper()
	best := -1
	for h := maxHeight(heights[0]); h >= 1; h-- {
		want := ""
		all := true
		for _, path := range heights {
			tip := tipAt(path, h)
			if tip == "" {
				all = false
				break
			}
			if want == "" {
				want = tip
			} else if tip != want {
				t.Fatalf("chain divergence at height %d", h)
			}
		}
		if all {
			best = h
			break
		}
	}
	if best < 0 {
		t.Fatalf("no common finalized height across heightfiles")
	}
}

// checkTips — the "tip=" recorded for `height` must be identical in every
// heightfile: all processes finalized the same chain.
func checkTips(t *testing.T, heights []string, height int) {
	t.Helper()
	var want string
	for i, path := range heights {
		tip := tipAt(path, height)
		if tip == "" {
			t.Fatalf("heightfile %s has no tip at height %d", path, height)
		}
		if i == 0 {
			want = tip
		} else if tip != want {
			t.Fatalf("chain divergence at height %d: node0=%s node%d=%s", height, want, i, tip)
		}
	}
}

func tipAt(path string, height int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	prefix := fmt.Sprintf("height=%d ", height)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			if rest, ok := strings.CutPrefix(line, prefix); ok {
				if tip, ok := strings.CutPrefix(rest, "tip="); ok {
					return tip
				}
			}
		}
	}
	return ""
}
