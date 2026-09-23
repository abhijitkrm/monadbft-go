package swarm

import (
	"encoding/json"

	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// MockStateSyncExecutor — port of monad-updaters::statesync::MockStateSyncExecutor.
//
// Serves/resolves StateSyncRequests against the shared InMemoryState. Sync
// target GENESIS_SEQ_NUM short-circuits to DoneSync; otherwise a Request is
// broadcast to upstream peers and the matching Response installs the committed
// block state.
type MockStateSyncExecutor struct {
	events    []glue.MonadEvent // queued StateSyncEvent
	stateRead *InMemoryState

	peers            []types.NodeId // upstream peers (set semantics)
	maxServiceWindow types.SeqNum
	startedExecution bool
	request          *glue.StateSyncRequest
}

var _ EventSource = (*MockStateSyncExecutor)(nil)

func NewMockStateSyncExecutor(stateRead *InMemoryState) *MockStateSyncExecutor {
	return &MockStateSyncExecutor{
		stateRead:        stateRead,
		maxServiceWindow: types.SeqNum(^uint64(0)), // SeqNum::MAX
	}
}

// WithMaxServiceWindow — Rust with_max_service_window.
func (s *MockStateSyncExecutor) WithMaxServiceWindow(w types.SeqNum) *MockStateSyncExecutor {
	s.maxServiceWindow = w
	return s
}

// Exec — Rust Executor::exec(StateSyncCommand).
func (s *MockStateSyncExecutor) Exec(cmds []glue.StateSyncCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.StateSyncStartExecution:
			if s.startedExecution {
				panic("StateSyncCommand::StartExecution received twice")
			}
			s.startedExecution = true
		case glue.StateSyncExpandUpstreamPeers:
			for _, p := range c.Peers {
				if !s.hasPeer(p) {
					s.peers = append(s.peers, p)
				}
			}
		case glue.StateSyncRequestSync:
			s.requestSync(c.Header.SeqNum())
		case glue.StateSyncMessage:
			s.handleMessage(c.To, c.Message)
		}
	}
}

func (s *MockStateSyncExecutor) hasPeer(p types.NodeId) bool {
	for _, q := range s.peers {
		if q == p {
			return true
		}
	}
	return false
}

func (s *MockStateSyncExecutor) requestSync(targetSeqNum types.SeqNum) {
	if targetSeqNum == types.GENESIS_SEQ_NUM {
		s.events = append(s.events, glue.EvStateSyncDoneSync{SeqNum: types.GENESIS_SEQ_NUM})
		return
	}
	if s.startedExecution {
		panic("RequestSync after StartExecution")
	}
	if len(s.peers) == 0 {
		panic("RequestSync with no upstream peers")
	}
	req := glue.StateSyncRequest{
		Version:     glue.StateSyncVersionSelf,
		Target:      targetSeqNum.Uint64(),
		PrefixBytes: 1,
	}
	s.request = &req
	for _, peer := range s.peers {
		r := req
		s.events = append(s.events, glue.EvStateSyncOutbound{
			To:      peer,
			Message: glue.StateSyncNetworkMessage{Kind: glue.SSNRequest, Request: r},
		})
	}
}

func (s *MockStateSyncExecutor) handleMessage(from types.NodeId, msg glue.StateSyncNetworkMessage) {
	switch msg.Kind {
	case glue.SSNRequest:
		s.serveRequest(from, msg.Request)
	case glue.SSNResponse:
		s.applyResponse(msg.Response)
	case glue.SSNBadVersion, glue.SSNCompletion, glue.SSNNotWhitelisted:
		// nop
	}
}

// serveRequest — Rust StateSyncNetworkMessage::Request arm.
func (s *MockStateSyncExecutor) serveRequest(from types.NodeId, req glue.StateSyncRequest) {
	if !s.startedExecution {
		return
	}
	if latest := s.stateRead.RawReadLatestFinalizedBlock(); latest != nil {
		window := s.maxServiceWindow.Uint64()
		sum := req.Target + window
		if sum < req.Target { // saturating_add
			sum = ^uint64(0)
		}
		if sum < latest.Uint64() {
			return
		}
	}
	state := s.stateRead.CommittedState(types.SeqNum(req.Target))
	if state == nil {
		return
	}
	serialized, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	resp := glue.StateSyncResponse{
		Version: glue.StateSyncVersionSelf,
		Request: req,
		Response: []glue.Upsert{{
			Type: glue.UpsertCode,
			Data: serialized,
		}},
		ResponseN: 1,
	}
	s.events = append(s.events, glue.EvStateSyncOutbound{
		To:      from,
		Message: glue.StateSyncNetworkMessage{Kind: glue.SSNResponse, Response: resp},
	})
}

// applyResponse — Rust StateSyncNetworkMessage::Response arm.
func (s *MockStateSyncExecutor) applyResponse(resp glue.StateSyncResponse) {
	if s.startedExecution || s.request == nil || *s.request != resp.Request {
		return
	}
	s.request = nil
	var state InMemoryBlockState
	if err := json.Unmarshal(resp.Response[0].Data, &state); err != nil {
		panic(err)
	}
	s.stateRead.ResetState(&state)
	s.events = append(s.events, glue.EvStateSyncDoneSync{SeqNum: types.SeqNum(resp.Request.Target)})
}

func (s *MockStateSyncExecutor) Ready() bool { return len(s.events) > 0 }

// Next — Rust Stream::next / MockableStateSync::pop.
func (s *MockStateSyncExecutor) Next() glue.MonadEvent {
	if len(s.events) == 0 {
		return nil
	}
	ev := s.events[0]
	s.events = s.events[1:]
	return ev
}
