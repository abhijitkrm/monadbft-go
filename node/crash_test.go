package node

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/messages"
	"github.com/abhijitkrm/monadbft-go/store"
	"github.com/abhijitkrm/monadbft-go/swarm"
	"github.com/abhijitkrm/monadbft-go/types"
)

// voteRecorder — Transport wrapper capturing every VoteMessage the wrapped
// node publishes (round → wire payloads). Each vote is legitimately sent
// twice — sendVoteAndResetTimer delivers to the next-round and current-round
// leaders — so the invariant is: every payload for a round is identical and
// the total never exceeds the leader fanout. A re-vote after restart
// produces a third/fourth send; a conflicting sign produces a second
// distinct payload.
type voteRecorder struct {
	Transport
	mu    sync.Mutex
	votes map[types.Round][][]byte
}

const maxVoteFanout = 2 // next-round leader + current-round leader

func newVoteRecorder(inner Transport, votes map[types.Round][][]byte) *voteRecorder {
	return &voteRecorder{Transport: inner, votes: votes}
}

func (r *voteRecorder) Send(target types.RouterTarget, payload []byte) {
	if msg, err := glue.DecodeMonadMessage(payload, exec.Mock); err == nil && msg.Consensus != nil {
		if pm := msg.Consensus.Obj.Message; pm.Kind == messages.PMVote && pm.Vote != nil {
			r.mu.Lock()
			r.votes[pm.Vote.Vote.Round] = append(r.votes[pm.Vote.Vote.Round],
				pm.Vote.Vote.EncodeRLP(nil))
			r.mu.Unlock()
		}
	}
	r.Transport.Send(target, payload)
}

// checkRecordedVotes — the no-double-sign invariant over the wire record:
// ≤ maxVoteFanout sends per round and all payloads identical.
func checkRecordedVotes(t *testing.T, votes map[types.Round][][]byte) {
	t.Helper()
	for round, payloads := range votes {
		for _, p := range payloads[1:] {
			if !bytes.Equal(p, payloads[0]) {
				t.Fatalf("round %d double-signed: conflicting vote payloads", round)
			}
		}
		if len(payloads) > maxVoteFanout {
			t.Fatalf("round %d voted %d times — watermark did not survive restart",
				round, len(payloads))
		}
	}
}

// TestNodeCrashStages — for every persistence stage, kill node 0 the moment
// it handles a SendVote timer event (the vote-casting dispatch), reopen it
// on the same dir, and assert: watermarks on disk never moved backward, the
// restarted node rejoins and finalizes a consistent chain, and it never
// re-signs a round.
func TestNodeCrashStages(t *testing.T) {
	stages := []struct {
		name  string
		stage CrashStage
	}{
		{"before-wal", CrashBeforeWAL},
		{"after-wal", CrashAfterWAL},
		{"after-update", CrashAfterUpdate},
		{"after-safety", CrashAfterSafety},
		{"after-ledger", CrashAfterLedger},
		{"after-configfile", CrashAfterConfigFile},
		{"after-publish", CrashAfterPublish},
	}
	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			testCrashAtStage(t, st.stage)
		})
	}
}

func testCrashAtStage(t *testing.T, stage CrashStage) {
	const numNodes = 4
	gv := swarm.CreateKeysWithValidators(numNodes)
	execDelay := types.SeqNum(4)
	mesh := NewMesh()

	dirs := make([]string, numNodes)
	srs := make([]*swarm.InMemoryState, numNodes)
	nodes := make([]*Node, numNodes)
	ledgers := make([]*swarm.MockLedger, numNodes)

	// Crash trigger: the SendVote timer event — the dispatch that produces a
	// signed vote. Only fire once.
	var fired atomic.Bool
	var crashRound atomic.Uint64
	hook := CrashHook(func(s CrashStage, ev glue.MonadEvent) bool {
		if s != stage || fired.Load() {
			return false
		}
		sv, ok := ev.(glue.EvConsensusSendVote)
		if !ok {
			return false
		}
		crashRound.Store(sv.Round.Uint64())
		fired.Store(true)
		return true
	})

	votes := map[types.Round][][]byte{}
	for i := 0; i < numNodes; i++ {
		dirs[i] = t.TempDir()
		srs[i] = swarm.NewInMemoryStateGenesis(execDelay)
		self := types.NewNodeId(gv.Keys[i].PubKey())
		var tr Transport = mesh.Transport(self)
		var hk CrashHook
		if i == 0 {
			tr = newVoteRecorder(tr, votes)
			hk = hook
		}
		nodes[i], ledgers[i] = openTestNodeCrash(t, dirs[i], i, gv, srs[i], tr, execDelay, hk)
	}
	// Stop every live node before TempDir cleanup can fire — registered
	// after the dirs are created so it runs before their RemoveAll.
	t.Cleanup(func() {
		for _, n := range nodes {
			if n != nil {
				n.Stop()
			}
		}
	})
	for _, n := range nodes {
		if err := n.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v", err)
		}
	}

	// Wait for the crash, then confirm process-death semantics.
	deadline := time.Now().Add(30 * time.Second)
	for !nodes[0].Crashed() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !nodes[0].Crashed() {
		t.Error("node 0 never crashed — hook never saw a SendVote")
		return
	}
	if err := nodes[0].Wait(); !errors.Is(err, ErrSimulatedCrash) {
		t.Errorf("crashed node Wait: %v", err)
	}

	// Post-mortem: whatever the watermark reached must be durable.
	preSnap, err := store.LoadSafety(dirs[0], exec.Mock)
	if err != nil {
		t.Errorf("LoadSafety: %v", err)
	}
	if stage >= CrashAfterSafety && preSnap == nil {
		t.Error("crash after safety persist but safety.rlp missing")
	}

	// Reopen on the same dir — same identity, same execution state; the new
	// endpoint registers on the mesh and a fresh recorder shares the vote
	// history so a cross-restart re-sign is detected.
	self0 := types.NewNodeId(gv.Keys[0].PubKey())
	nodes[0], ledgers[0] = openTestNodeCrash(t, dirs[0], 0, gv, srs[0],
		newVoteRecorder(mesh.Transport(self0), votes), execDelay, nil)

	postSnap, err := store.LoadSafety(dirs[0], exec.Mock)
	if err != nil {
		t.Errorf("LoadSafety post-reopen: %v", err)
	}
	if preSnap != nil && postSnap != nil && postSnap.HighestVote < preSnap.HighestVote {
		t.Errorf("watermark regressed across restart: %d -> %d",
			preSnap.HighestVote, postSnap.HighestVote)
	}

	if err := nodes[0].Start(context.Background()); err != nil {
		t.Errorf("restart Start: %v", err)
		return
	}

	// Everyone — including the restarted node — reaches the target.
	const target = 8
	for _, l := range ledgers {
		waitFinalized(t, l, target, 60*time.Second)
	}

	// Stop everything before reading shared state (votes map, ledgers).
	for _, n := range nodes {
		n.Stop()
	}
	for i, n := range nodes {
		if err := n.Err(); err != nil {
			// The restarted instance (new Node object) must run clean.
			t.Errorf("node %d error: %v", i, err)
		}
	}

	// The restarted node's chain matches a peer's — it resynced, not forked.
	ref := ledgers[1].GetFinalizedBlocks()
	got := ledgers[0].GetFinalizedBlocks()
	for j := 0; j < target && j < len(got) && j < len(ref); j++ {
		gotID, refID := got[j].Block.GetId(), ref[j].Block.GetId()
		if gotID != refID {
			t.Errorf("restarted node diverged at block %d: %x vs %x",
				j, gotID[:8], refID[:8])
		}
	}

	// The core invariant: no round was ever voted twice by node 0 — before,
	// across, or after the crash window.
	checkRecordedVotes(t, votes)
	t.Logf("stage %v: crashRound=%d preSnapVote=%v",
		stage, crashRound.Load(), preSnap != nil)
}
