package bridge

import (
	"fmt"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// prefixStatesyncBlocks — the StateSyncRequest.Prefix namespace for the
// bridge's sync payload. Upstream Monad syncs a flat DB keyspace
// partitioned by 64-bit prefixes (account/storage/code/code-deletes); the
// Cosmos-EVM store is module-scoped IAVL with no flat diff surface, so the
// bridge serves canonical committed *blocks* under a dedicated prefix and
// the syncing node replays them through FinalizeBlock+Commit — the same
// deterministic path the canonical ledger runs, QC-verified end to end.
const prefixStatesyncBlocks uint64 = 0xB10C5

// statesyncMaxResponseBytes — serialized-bytes cap per SSNResponse chunk
// (upstream caps responses too; blocks are chunked across ResponseIndex).
const statesyncMaxResponseBytes = 1 << 20

// StateSync — swarm.StateSync executor backed by the bridge ledger+app.
// Mirrors MockStateSyncExecutor's upstream-faithful state machine:
//
//   - RequestSync(header) → broadcast SSNRequest for blocks
//     [appTip+1 .. header.SeqNum] to all upstream peers.
//   - SSNRequest (once execution started) → serve committed blocks as
//     Upsert{UpsertHeader, block.EncodeRLP} chunks.
//   - SSNResponse → buffer blocks, replay the contiguous run, and emit
//     EvStateSyncDoneSync when the app reaches the target — after checking
//     the replayed AppHash against the sync header (fraud check).
//   - Shortfalls re-request the remaining range (the upstream prefix-walk
//     continuation); ExpandUpstreamPeers re-emits the outstanding request
//     to newly-added peers.
type StateSync struct {
	app    *App
	ledger *Ledger
	spec   *SpecApp // nil → finalize-only mode (no spec bookkeeping to reset)

	events []glue.MonadEvent
	peers  []types.NodeId

	startedExecution bool
	maxServiceWindow types.SeqNum

	sync *syncState // in-flight client-side sync; nil when idle
}

type syncState struct {
	request glue.StateSyncRequest // the request outstanding responses must match
	target  types.SeqNum
	appHash []byte // expected canonical AppHash at target (sync-header check)
	pending map[types.SeqNum]*cstypes.ConsensusFullBlock
}

var _ interface {
	Exec([]glue.StateSyncCommand)
	Ready() bool
	Next() glue.MonadEvent
} = (*StateSync)(nil)

func NewStateSync(app *App, ledger *Ledger, spec *SpecApp) *StateSync {
	return &StateSync{
		app:              app,
		ledger:           ledger,
		spec:             spec,
		maxServiceWindow: types.SeqNum(^uint64(0)),
	}
}

// WithMaxServiceWindow — Rust with_max_service_window.
func (s *StateSync) WithMaxServiceWindow(w types.SeqNum) *StateSync {
	s.maxServiceWindow = w
	return s
}

// Exec — StateSyncCommand dispatch (MockStateSyncExecutor parity).
func (s *StateSync) Exec(cmds []glue.StateSyncCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.StateSyncStartExecution:
			if s.startedExecution {
				panic("StateSyncCommand::StartExecution received twice")
			}
			s.startedExecution = true
		case glue.StateSyncExpandUpstreamPeers:
			added := false
			for _, p := range c.Peers {
				if !s.hasPeer(p) {
					s.peers = append(s.peers, p)
					added = true
				}
			}
			// New peers may be the first ones able to serve — re-emit the
			// outstanding request to them.
			if added && s.sync != nil {
				for _, p := range c.Peers {
					s.emitRequest(p)
				}
			}
		case glue.StateSyncRequestSync:
			s.requestSync(c.Header)
		case glue.StateSyncMessage:
			s.handleMessage(c.To, c.Message)
		}
	}
}

func (s *StateSync) hasPeer(p types.NodeId) bool {
	for _, q := range s.peers {
		if q == p {
			return true
		}
	}
	return false
}

func (s *StateSync) requestSync(header exec.FinalizedHeader) {
	target := header.SeqNum()
	if target == types.GENESIS_SEQ_NUM {
		s.events = append(s.events, glue.EvStateSyncDoneSync{SeqNum: types.GENESIS_SEQ_NUM})
		return
	}
	if s.startedExecution {
		panic("RequestSync after StartExecution")
	}
	if len(s.peers) == 0 {
		panic("RequestSync with no upstream peers")
	}
	fh, ok := header.(*EvmFinalizedHeader)
	if !ok {
		panic(fmt.Sprintf("bridge: statesync header %T is not *EvmFinalizedHeader", header))
	}
	from := s.app.committedHeight() + 1
	s.sync = &syncState{
		request: glue.StateSyncRequest{
			Version:     glue.StateSyncVersionSelf,
			Prefix:      prefixStatesyncBlocks,
			PrefixBytes: 8,
			Target:      target.Uint64(),
			From:        uint64(from),
			Until:       target.Uint64(),
		},
		target:  target,
		appHash: fh.AppHash,
		pending: map[types.SeqNum]*cstypes.ConsensusFullBlock{},
	}
	for _, p := range s.peers {
		s.emitRequest(p)
	}
}

func (s *StateSync) emitRequest(to types.NodeId) {
	s.events = append(s.events, glue.EvStateSyncOutbound{
		To: to,
		Message: glue.StateSyncNetworkMessage{
			Kind:    glue.SSNRequest,
			Request: s.sync.request,
		},
	})
}

func (s *StateSync) handleMessage(from types.NodeId, msg glue.StateSyncNetworkMessage) {
	switch msg.Kind {
	case glue.SSNRequest:
		s.serveRequest(from, msg.Request)
	case glue.SSNResponse:
		s.applyResponse(msg.Response)
	case glue.SSNBadVersion, glue.SSNCompletion, glue.SSNNotWhitelisted:
		// nop (MockStateSyncExecutor parity)
	}
}

// serveRequest — ship committed blocks [max(From,1)..min(Until,latest)] as
// Upsert{UpsertHeader} chunks. A partial range is served contiguously from
// From — the requester re-asks for the remainder from another peer.
func (s *StateSync) serveRequest(from types.NodeId, req glue.StateSyncRequest) {
	if !s.startedExecution {
		return
	}
	if req.Prefix != prefixStatesyncBlocks {
		return
	}
	latest := s.ledger.committedSeq()
	if window := s.maxServiceWindow.Uint64(); req.Target+window >= req.Target &&
		req.Target+window < latest.Uint64() {
		return // requested target outside the service window
	}
	if req.From > req.Until || req.From > latest.Uint64() {
		return
	}

	var ups []glue.Upsert
	var bytes, total int
	end := req.Until
	if end > latest.Uint64() {
		end = latest.Uint64()
	}
	index := uint32(0)
	emit := func() {
		if len(ups) == 0 {
			return
		}
		s.events = append(s.events, glue.EvStateSyncOutbound{
			To: from,
			Message: glue.StateSyncNetworkMessage{
				Kind: glue.SSNResponse,
				Response: glue.StateSyncResponse{
					Version:       glue.StateSyncVersionSelf,
					ResponseIndex: index,
					Request:       req,
					Response:      ups,
					ResponseN:     uint64(total),
				},
			},
		})
		index++
		ups = nil
		bytes = 0
	}
	for seq := req.From; seq <= end; seq++ {
		block := s.ledger.committedBlock(types.SeqNum(seq))
		if block == nil {
			break // contiguous prefix only — requester re-asks for the gap
		}
		data := block.EncodeRLP(nil)
		ups = append(ups, glue.Upsert{Type: glue.UpsertHeader, Data: data})
		bytes += len(data)
		total++
		if bytes >= statesyncMaxResponseBytes || len(ups) >= glue.MaxUpsertsPerResponse {
			emit()
		}
	}
	emit()
}

// applyResponse — buffer and replay synced blocks. Blocks apply in seq
// order from the app tip; a non-contiguous batch waits for the missing
// prefix. On reaching the target the replayed AppHash is checked against
// the requested finalized header before DoneSync.
func (s *StateSync) applyResponse(resp glue.StateSyncResponse) {
	if s.startedExecution || s.sync == nil || resp.Request != s.sync.request {
		return
	}
	for _, u := range resp.Response {
		if u.Type != glue.UpsertHeader {
			continue
		}
		block := &cstypes.ConsensusFullBlock{}
		if err := block.DecodeRLP(rlp.NewStream(u.Data), Evm); err != nil {
			continue // malformed peer payload — skip
		}
		seq := block.GetSeqNum()
		if seq > s.sync.target {
			continue
		}
		s.sync.pending[seq] = block
	}
	s.drain()
}

// drain — replay pending blocks contiguously from the app tip. On target
// completion: verify the AppHash, reset spec bookkeeping (the pre-sync
// lineage is stale — its entries would corrupt the store via the
// orphan-rewind path), and report DoneSync.
func (s *StateSync) drain() {
	for {
		next := s.app.committedHeight() + 1
		block := s.sync.pending[types.SeqNum(next)]
		if block == nil {
			break
		}
		delete(s.sync.pending, types.SeqNum(next))
		s.ledger.applySyncedBlock(block)
		if types.SeqNum(next) == s.sync.target {
			got := s.app.Result(next)
			if got == nil || string(got.AppHash) != string(s.sync.appHash) {
				panic(fmt.Sprintf("bridge: statesync apphash mismatch at seq %d: got %x want %x",
					next, got.AppHash, s.sync.appHash))
			}
			if s.spec != nil {
				s.spec.ResetToHeight(next, block.GetId())
			}
			s.events = append(s.events, glue.EvStateSyncDoneSync{SeqNum: s.sync.target})
			s.sync = nil
			return
		}
	}
	// Short of target: if the serving peer's contiguous prefix ran out, ask
	// for the remainder (upstream prefix-walk continuation).
	if s.sync != nil {
		next := uint64(s.app.committedHeight() + 1)
		if s.sync.request.From != next {
			s.sync.request.From = next
			for _, p := range s.peers {
				s.emitRequest(p)
			}
		}
	}
}

func (s *StateSync) Ready() bool { return len(s.events) > 0 }

func (s *StateSync) Next() glue.MonadEvent {
	if len(s.events) == 0 {
		return nil
	}
	ev := s.events[0]
	s.events = s.events[1:]
	return ev
}

// NopStateSync — a swarm.StateSync that drops commands (used where the
// bridge executor isn't wired, e.g. the mock-devnet binary uses
// MockStateSyncExecutor).
type NopStateSync struct{}

func (NopStateSync) Exec([]glue.StateSyncCommand) {}
func (NopStateSync) Ready() bool                  { return false }
func (NopStateSync) Next() glue.MonadEvent        { return nil }
