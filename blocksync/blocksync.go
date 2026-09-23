package blocksync

import (
	crand "crypto/rand"
	"math/big"
	"math/rand/v2"
	"sort"

	"github.com/abhijitkrm/monadbft-go/blocktree"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/metrics"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// BLOCKSYNC_MAX_PAYLOAD_REQUESTS — Rust BLOCKSYNC_MAX_PAYLOAD_REQUESTS.
const maxPayloadRequests = 10

// Command — Rust BlockSyncCommand.
type Command interface{ isBlockSyncCommand() }

type cmdBase struct{}

func (cmdBase) isBlockSyncCommand() {}

// CmdSendRequest — SendRequest{to, request}.
type CmdSendRequest struct {
	cmdBase
	To      types.NodeId
	Request RequestMessage
}

// CmdScheduleTimeout — ScheduleTimeout(request).
type CmdScheduleTimeout struct {
	cmdBase
	Request RequestMessage
}

// CmdResetTimeout — ResetTimeout(request).
type CmdResetTimeout struct {
	cmdBase
	Request RequestMessage
}

// CmdSendResponse — SendResponse{to, response}.
type CmdSendResponse struct {
	cmdBase
	To       types.NodeId
	Response ResponseMessage
}

// CmdFetchHeaders — FetchHeaders(block_range): read from ledger.
type CmdFetchHeaders struct {
	cmdBase
	Range cstypes.BlockRange
}

// CmdFetchPayload — FetchPayload(payload_id): read from ledger.
type CmdFetchPayload struct {
	cmdBase
	PayloadID cstypes.ConsensusBlockBodyId
}

// CmdEmit — Emit(requester, (block_range, full_blocks)): deliver to self.
type CmdEmit struct {
	cmdBase
	Requester  SelfRequester
	Range      cstypes.BlockRange
	FullBlocks []cstypes.ConsensusFullBlock
}

// SelfRequest — Rust SelfRequest: tracks an in-flight self request.
type SelfRequest struct {
	Requester SelfRequester
	// nil == outstanding request is to self (ledger).
	To *types.NodeId
}

// selfCompletedHeader — Rust SelfCompletedHeader: headers fetched, awaiting
// payloads.
type selfCompletedHeader struct {
	requester SelfRequester
	// (header, payload-or-nil)
	blocks       []completedBlock
	payloadCache map[cstypes.ConsensusBlockBodyId]*cstypes.ConsensusBlockBody
}

type completedBlock struct {
	header  cstypes.ConsensusBlockHeader
	payload *cstypes.ConsensusBlockBody
}

// BlockSync — Rust BlockSync: tracks requests to peers and to self ledger.
type BlockSync struct {
	// Requests from peers: range -> (requester -> cached suffix from blocktree)
	headersRequests map[cstypes.BlockRange]map[types.NodeId][]cstypes.ConsensusBlockHeader
	// payload_id -> set of requesting peers
	payloadRequests map[cstypes.ConsensusBlockBodyId]map[types.NodeId]struct{}

	// Headers requests for self
	selfHeadersRequests map[cstypes.BlockRange]SelfRequest
	// Payload requests for self: nil = not yet initiated
	selfPayloadRequests         map[cstypes.ConsensusBlockBodyId]*SelfRequest
	selfPayloadRequestsInFlight int
	// headers fetched, awaiting payloads
	selfCompletedHeadersRequests map[cstypes.BlockRange]*selfCompletedHeader

	selfRequestMode SelfRequester

	// Excludes self
	overridePeers []types.NodeId

	selfNodeID types.NodeId

	rng *rand.ChaCha8
}

// New — Rust BlockSync::new.
func New(overridePeersIncSelf []types.NodeId, selfNodeID types.NodeId, rngSeed *uint64) *BlockSync {
	bs := &BlockSync{
		headersRequests:              make(map[cstypes.BlockRange]map[types.NodeId][]cstypes.ConsensusBlockHeader),
		payloadRequests:              make(map[cstypes.ConsensusBlockBodyId]map[types.NodeId]struct{}),
		selfHeadersRequests:          make(map[cstypes.BlockRange]SelfRequest),
		selfPayloadRequests:          make(map[cstypes.ConsensusBlockBodyId]*SelfRequest),
		selfCompletedHeadersRequests: make(map[cstypes.BlockRange]*selfCompletedHeader),
		selfRequestMode:              SelfRequesterStateSync,
		selfNodeID:                   selfNodeID,
		rng:                          newChaCha8(rngSeed),
	}
	bs.SetOverridePeers(overridePeersIncSelf)
	return bs
}

func newChaCha8(seed *uint64) *rand.ChaCha8 {
	var key [32]byte
	if seed != nil {
		// ChaCha8Rng::seed_from_u64: little-endian u64 into first 8 bytes.
		for i := 0; i < 8; i++ {
			key[i] = byte(*seed >> (8 * i))
		}
	} else {
		crand.Read(key[:])
	}
	return rand.NewChaCha8(key)
}

// SetOverridePeers — Rust set_override_peers.
func (b *BlockSync) SetOverridePeers(peersIncSelf []types.NodeId) {
	out := peersIncSelf[:0]
	for _, p := range peersIncSelf {
		if p != b.selfNodeID {
			out = append(out, p)
		}
	}
	b.overridePeers = append([]types.NodeId(nil), out...)
}

func (b *BlockSync) clearSelfRequests() {
	b.selfHeadersRequests = make(map[cstypes.BlockRange]SelfRequest)
	b.selfPayloadRequests = make(map[cstypes.ConsensusBlockBodyId]*SelfRequest)
	b.selfPayloadRequestsInFlight = 0
	b.selfCompletedHeadersRequests = make(map[cstypes.BlockRange]*selfCompletedHeader)
}

func (b *BlockSync) selfRequestExists(r cstypes.BlockRange) bool {
	if _, ok := b.selfHeadersRequests[r]; ok {
		return true
	}
	_, ok := b.selfCompletedHeadersRequests[r]
	return ok
}

// Cache — Rust BlockCache: the readable block source for serving peers.
type Cache struct {
	// exactly one of these is set
	BlockTree    *blocktree.BlockTree
	PayloadCache map[cstypes.ConsensusBlockBodyId]*cstypes.ConsensusBlockBody
}

// Wrapper — Rust BlockSyncWrapper: binds BlockSync to the block source +
// peer-selection inputs for a single event.
type Wrapper struct {
	BS *BlockSync

	Cache        Cache
	Metrics      *metrics.Metrics
	NodeID       types.NodeId
	CurrentEpoch types.Epoch
	EpochManager *validator.EpochManager
	ValEpochMap  *validator.ValidatorsEpochMapping
	// Secondary raptorcast peers (node -> expiry round); used by full nodes.
	SecondaryRaptorcastPeers map[types.NodeId]types.Round
}

// HandleSelfRequest — Rust handle_self_request.
func (w *Wrapper) HandleSelfRequest(requester SelfRequester, blockRange cstypes.BlockRange) []Command {
	if blockRange.NumBlocks == 0 {
		return nil
	}
	if requester != w.BS.selfRequestMode {
		w.BS.clearSelfRequests()
		w.BS.selfRequestMode = requester
	}
	if w.BS.selfRequestExists(blockRange) {
		return nil
	}
	w.BS.selfHeadersRequests[blockRange] = SelfRequest{Requester: requester}
	return []Command{&CmdFetchHeaders{Range: blockRange}}
}

// HandleSelfCancelRequest — Rust handle_self_cancel_request.
func (w *Wrapper) HandleSelfCancelRequest(requester SelfRequester, blockRange cstypes.BlockRange) {
	if r, ok := w.BS.selfHeadersRequests[blockRange]; ok && r.Requester == requester {
		delete(w.BS.selfHeadersRequests, blockRange)
	}
	if r, ok := w.BS.selfCompletedHeadersRequests[blockRange]; ok && r.requester == requester {
		delete(w.BS.selfCompletedHeadersRequests, blockRange)
	}
	// NB: payload requests not removed — may be needed by another range.
}

// HandlePeerRequest — Rust handle_peer_request.
func (w *Wrapper) HandlePeerRequest(sender types.NodeId, request RequestMessage) []Command {
	var cmds []Command
	if !request.IsPayload {
		blockRange := request.Range
		if blockRange.NumBlocks == 0 {
			return nil
		}
		w.Metrics.BlocksyncEvents.PeerHeadersRequest.Inc()

		var cached []cstypes.ConsensusBlockHeader
		if w.Cache.BlockTree != nil {
			chain := w.Cache.BlockTree.GetParentBlockChain(blockRange.LastBlockId)
			// chain is newest-first; take the last num_blocks, oldest-first.
			n := int(blockRange.NumBlocks)
			if len(chain) > n {
				chain = chain[:n]
			}
			for i := len(chain) - 1; i >= 0; i-- {
				cached = append(cached, chain[i].Header)
			}
		}

		if len(cached) == int(blockRange.NumBlocks) {
			cmds = append(cmds, &CmdSendResponse{
				To:       sender,
				Response: ResponseHeaders(blockRange, cached),
			})
		} else {
			lastFetch := blockRange.LastBlockId
			if len(cached) > 0 {
				lastFetch = cached[0].GetParentId()
			}
			fetchRange := cstypes.BlockRange{
				LastBlockId: lastFetch,
				NumBlocks:   blockRange.NumBlocks - types.SeqNum(len(cached)),
			}
			entry := w.BS.headersRequests[fetchRange]
			if entry == nil {
				entry = make(map[types.NodeId][]cstypes.ConsensusBlockHeader)
				w.BS.headersRequests[fetchRange] = entry
			}
			entry[sender] = cached
			cmds = append(cmds, &CmdFetchHeaders{Range: fetchRange})
		}
	} else {
		payloadID := request.PayloadID
		w.Metrics.BlocksyncEvents.PeerPayloadRequest.Inc()

		if cached := w.getCachedPayload(payloadID); cached != nil {
			cmds = append(cmds, &CmdSendResponse{
				To:       sender,
				Response: ResponsePayload(*cached),
			})
			return cmds
		}
		entry := w.BS.payloadRequests[payloadID]
		if entry == nil {
			entry = make(map[types.NodeId]struct{})
			w.BS.payloadRequests[payloadID] = entry
		}
		entry[sender] = struct{}{}
		cmds = append(cmds, &CmdFetchPayload{PayloadID: payloadID})
	}
	return cmds
}

func (w *Wrapper) getCachedPayload(id cstypes.ConsensusBlockBodyId) *cstypes.ConsensusBlockBody {
	if w.Cache.PayloadCache != nil {
		if p, ok := w.Cache.PayloadCache[id]; ok {
			return p
		}
	}
	if w.Cache.BlockTree != nil {
		if p := w.Cache.BlockTree.GetPayload(id); p != nil {
			return p
		}
	}
	for _, ch := range w.BS.selfCompletedHeadersRequests {
		if p, ok := ch.payloadCache[id]; ok {
			return p
		}
	}
	return nil
}

// pickPeer — Rust pick_peer: override > secondary raptorcast (full node) >
// stake-weighted validators.
func (w *Wrapper) pickPeer() *types.NodeId {
	if len(w.BS.overridePeers) > 0 {
		p := w.BS.overridePeers[int(w.BS.rng.Uint64()%uint64(len(w.BS.overridePeers)))]
		return &p
	}
	valSet, ok := w.ValEpochMap.GetValSet(w.CurrentEpoch)
	if !ok {
		panic("blocksync: current epoch validator set missing")
	}
	selfIsValidator := valSet.IsMember(w.NodeID)

	if !selfIsValidator {
		// random secondary raptorcast peer
		var candidates []types.NodeId
		for p := range w.SecondaryRaptorcastPeers {
			candidates = append(candidates, p)
		}
		if len(candidates) == 0 {
			return nil
		}
		p := candidates[int(w.BS.rng.Uint64()%uint64(len(candidates)))]
		return &p
	}
	// stake-weighted over validators excluding self
	var members []types.NodeId
	for _, m := range valSet.Members() {
		if m != w.NodeID {
			members = append(members, m)
		}
	}
	if len(members) == 0 {
		panic("blocksync: no nodes to blocksync from")
	}
	p := w.chooseWeighted(valSet, members)
	return &p
}

// chooseWeighted — Rust generate_random_validator_with_randomizer over
// randomize_256_with_rng.
func (w *Wrapper) chooseWeighted(vs *validator.ValidatorSet, members []types.NodeId) types.NodeId {
	total := big.NewInt(0)
	type bound struct {
		id types.NodeId
		up *big.Int
	}
	var bounds []bound
	for _, m := range members {
		stake, _ := vs.StakeOf(m)
		if stake.IsZero() {
			continue
		}
		total.Add(total, stake.Big())
		bounds = append(bounds, bound{id: m, up: new(big.Int).Set(total)})
	}
	if len(bounds) == 0 {
		panic("blocksync: no validator has positive stake")
	}
	r := randomize256(w.BS.rng, total)
	// first bound strictly greater than r
	i := sort.Search(len(bounds), func(i int) bool { return bounds[i].up.Cmp(r) > 0 })
	if i == len(bounds) {
		i = len(bounds) - 1
	}
	return bounds[i].id
}

// randomize256 — Rust randomize_256_with_rng: uniform in [0, m).
func randomize256(r *rand.ChaCha8, m *big.Int) *big.Int {
	max := new(big.Int).Sub(two256, m)
	max.Add(max, big.NewInt(1))
	max.Mod(max, m)
	max.Sub(two256, max) // U256::MAX - (U256::MAX - m + 1) % m
	for {
		b := chacha8Fill32(r)
		v := new(big.Int).SetBytes(reverse(b))
		if v.Cmp(max) <= 0 {
			return v.Mod(v, m)
		}
	}
}

var two256 = new(big.Int).Lsh(big.NewInt(1), 256)

func chacha8Fill32(r *rand.ChaCha8) []byte {
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		v := r.Uint64()
		for j := 0; j < 8; j++ {
			out[i*8+j] = byte(v >> (8 * j))
		}
	}
	return out
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, x := range b {
		out[len(b)-1-i] = x
	}
	return out
}

// verifyBlockHeaders — Rust verify_block_headers: range length + tip id +
// parent linkage.
func verifyBlockHeaders(blockRange cstypes.BlockRange, headers []cstypes.ConsensusBlockHeader) bool {
	if len(headers) != int(blockRange.NumBlocks) {
		return false
	}
	if blockRange.LastBlockId != headers[len(headers)-1].GetId() {
		return false
	}
	for i := 0; i+1 < len(headers); i++ {
		if headers[i].GetId() != headers[i+1].GetParentId() {
			return false
		}
	}
	return true
}

func (w *Wrapper) tryInitiatePayloadRequestsForSelf() []Command {
	var cmds []Command

	// hydrate from cache first
	for payloadID, req := range w.BS.selfPayloadRequests {
		if p := w.getCachedPayload(payloadID); p != nil {
			if req != nil {
				// already initiated — decrement in-flight
				w.BS.selfPayloadRequestsInFlight--
				w.Metrics.BlocksyncEvents.SelfPayloadRequestsInFlight.Set(uint64(w.BS.selfPayloadRequestsInFlight))
				if req.To != nil {
					cmds = append(cmds, &CmdResetTimeout{Request: RequestPayload(payloadID)})
				}
			}
			for _, ch := range w.BS.selfCompletedHeadersRequests {
				for i := range ch.blocks {
					if ch.blocks[i].header.BlockBodyId == payloadID && ch.blocks[i].payload == nil {
						cp := *p
						ch.blocks[i].payload = &cp
						ch.payloadCache[payloadID] = &cp
						w.Metrics.BlocksyncEvents.SelfPayloadResponseSuccessful.Inc()
					}
				}
			}
			delete(w.BS.selfPayloadRequests, payloadID)
		}
	}

	for w.BS.selfPayloadRequestsInFlight < maxPayloadRequests {
		var target cstypes.ConsensusBlockBodyId
		found := false
		for payloadID, req := range w.BS.selfPayloadRequests {
			if req == nil {
				target, found = payloadID, true
				break
			}
		}
		if !found {
			break
		}
		cmds = append(cmds, &CmdFetchPayload{PayloadID: target})
		w.BS.selfPayloadRequests[target] = &SelfRequest{Requester: w.BS.selfRequestMode}
		w.BS.selfPayloadRequestsInFlight++
		w.Metrics.BlocksyncEvents.SelfPayloadRequestsInFlight.Set(uint64(w.BS.selfPayloadRequestsInFlight))
	}

	cmds = append(cmds, w.handleCompletedRanges()...)
	return cmds
}

func (w *Wrapper) handleHeadersResponseForSelf(sender *types.NodeId, hr HeadersResponse) []Command {
	var cmds []Command
	blockRange := hr.GetBlockRange()
	req, ok := w.BS.selfHeadersRequests[blockRange]
	if !ok {
		return cmds
	}
	if (req.To == nil) != (sender == nil) || (req.To != nil && sender != nil && *req.To != *sender) {
		w.Metrics.BlocksyncEvents.HeadersResponseUnexpected.Inc()
	}

	if hr.Found {
		if verifyBlockHeaders(blockRange, hr.Headers) {
			delete(w.BS.selfHeadersRequests, blockRange)
			if sender != nil {
				w.Metrics.BlocksyncEvents.HeadersResponseSuccessful.Inc()
				cmds = append(cmds, &CmdResetTimeout{Request: RequestHeaders(blockRange)})
			} else {
				w.Metrics.BlocksyncEvents.SelfHeadersResponseSuccessful.Inc()
			}
			w.Metrics.BlocksyncEvents.NumHeadersReceived.Add(uint64(len(hr.Headers)))

			for _, h := range hr.Headers {
				if _, exists := w.BS.selfPayloadRequests[h.BlockBodyId]; !exists {
					w.BS.selfPayloadRequests[h.BlockBodyId] = nil
				}
			}
			ch := &selfCompletedHeader{
				requester:    w.BS.selfRequestMode,
				payloadCache: make(map[cstypes.ConsensusBlockBodyId]*cstypes.ConsensusBlockBody),
			}
			for _, h := range hr.Headers {
				ch.blocks = append(ch.blocks, completedBlock{header: h})
			}
			w.BS.selfCompletedHeadersRequests[blockRange] = ch
		} else {
			// verification failed; only peer responses can fail
			w.Metrics.BlocksyncEvents.HeadersValidationFailed.Inc()
		}
	} else {
		// NotAvailable
		if sender != nil {
			w.Metrics.BlocksyncEvents.HeadersResponseFailed.Inc()
		} else if req.To == nil {
			w.Metrics.BlocksyncEvents.SelfHeadersResponseFailed.Inc()
			maybeTo := w.pickPeer()
			req.To = maybeTo
			w.BS.selfHeadersRequests[blockRange] = req
			if maybeTo != nil {
				w.Metrics.BlocksyncEvents.SelfHeadersRequest.Inc()
				cmds = append(cmds, &CmdSendRequest{To: *maybeTo, Request: RequestHeaders(blockRange)})
			} else {
				w.Metrics.BlocksyncEvents.RequestFailedNoPeers.Inc()
			}
			cmds = append(cmds, &CmdScheduleTimeout{Request: RequestHeaders(blockRange)})
		}
	}

	cmds = append(cmds, w.tryInitiatePayloadRequestsForSelf()...)
	return cmds
}

func (w *Wrapper) handlePayloadResponseForSelf(sender *types.NodeId, pr BodyResponse) []Command {
	var cmds []Command
	payloadID := pr.GetPayloadID()

	req, ok := w.BS.selfPayloadRequests[payloadID]
	if !ok {
		return cmds
	}
	if req == nil {
		w.Metrics.BlocksyncEvents.PayloadResponseUnexpected.Inc()
		return cmds
	}
	if (req.To == nil) != (sender == nil) || (req.To != nil && sender != nil && *req.To != *sender) {
		w.Metrics.BlocksyncEvents.PayloadResponseUnexpected.Inc()
	}

	if pr.Found {
		w.BS.selfPayloadRequestsInFlight--
		w.Metrics.BlocksyncEvents.SelfPayloadRequestsInFlight.Set(uint64(w.BS.selfPayloadRequestsInFlight))
		if sender != nil {
			cmds = append(cmds, &CmdResetTimeout{Request: RequestPayload(payloadID)})
			w.Metrics.BlocksyncEvents.PayloadResponseSuccessful.Inc()
		} else {
			w.Metrics.BlocksyncEvents.SelfPayloadResponseSuccessful.Inc()
		}
		delete(w.BS.selfPayloadRequests, payloadID)

		for _, ch := range w.BS.selfCompletedHeadersRequests {
			for i := range ch.blocks {
				if ch.blocks[i].header.BlockBodyId == payloadID && ch.blocks[i].payload == nil {
					cp := pr.Body
					ch.blocks[i].payload = &cp
					ch.payloadCache[payloadID] = &cp
				}
			}
		}
	} else {
		// NotAvailable
		if sender != nil {
			w.Metrics.BlocksyncEvents.PayloadResponseFailed.Inc()
		} else if req.To == nil {
			w.Metrics.BlocksyncEvents.SelfPayloadResponseFailed.Inc()
			maybeTo := w.pickPeer()
			req.To = maybeTo
			if maybeTo != nil {
				w.Metrics.BlocksyncEvents.SelfPayloadRequest.Inc()
				cmds = append(cmds, &CmdSendRequest{To: *maybeTo, Request: RequestPayload(payloadID)})
			} else {
				w.Metrics.BlocksyncEvents.RequestFailedNoPeers.Inc()
			}
			cmds = append(cmds, &CmdScheduleTimeout{Request: RequestPayload(payloadID)})
		}
	}

	cmds = append(cmds, w.handleCompletedRanges()...)
	cmds = append(cmds, w.tryInitiatePayloadRequestsForSelf()...)
	return cmds
}

func (w *Wrapper) handleCompletedRanges() []Command {
	var cmds []Command
	var completed []cstypes.BlockRange
	for r, ch := range w.BS.selfCompletedHeadersRequests {
		all := true
		for _, b := range ch.blocks {
			if b.payload == nil {
				all = false
				break
			}
		}
		if all {
			completed = append(completed, r)
		}
	}
	for _, r := range completed {
		ch := w.BS.selfCompletedHeadersRequests[r]
		delete(w.BS.selfCompletedHeadersRequests, r)
		var full []cstypes.ConsensusFullBlock
		for _, b := range ch.blocks {
			fb, err := cstypes.NewFullBlock(b.header, *b.payload)
			if err != nil {
				panic("blocksync: block_body_id mismatch")
			}
			full = append(full, fb)
		}
		cmds = append(cmds, &CmdEmit{Requester: ch.requester, Range: r, FullBlocks: full})
	}
	return cmds
}

// HandleLedgerResponse — Rust handle_ledger_response (response from own DB).
func (w *Wrapper) HandleLedgerResponse(response ResponseMessage) []Command {
	var cmds []Command
	if response.IsPayload {
		pr := response.Body
		payloadID := pr.GetPayloadID()
		if pr.Found {
			w.Metrics.BlocksyncEvents.PeerPayloadRequestSuccessful.Inc()
		} else {
			w.Metrics.BlocksyncEvents.PeerPayloadRequestFailed.Inc()
		}
		requesters := w.BS.payloadRequests[payloadID]
		delete(w.BS.payloadRequests, payloadID)
		for requester := range requesters {
			cmds = append(cmds, &CmdSendResponse{
				To:       requester,
				Response: ResponseMessage{IsPayload: true, Body: pr},
			})
		}
		var sender *types.NodeId
		cmds = append(cmds, w.handlePayloadResponseForSelf(sender, pr)...)
		return cmds
	}

	hr := response.Headers
	blockRange := hr.GetBlockRange()
	requesters := w.BS.headersRequests[blockRange]
	delete(w.BS.headersRequests, blockRange)
	for requester, cachedBlocks := range requesters {
		lastID := blockRange.LastBlockId
		if len(cachedBlocks) > 0 {
			lastID = cachedBlocks[len(cachedBlocks)-1].GetId()
		}
		reqRange := cstypes.BlockRange{
			LastBlockId: lastID,
			NumBlocks:   blockRange.NumBlocks + types.SeqNum(len(cachedBlocks)),
		}
		var out HeadersResponse
		if hr.Found {
			blocks := append(append([]cstypes.ConsensusBlockHeader(nil), hr.Headers...), cachedBlocks...)
			w.Metrics.BlocksyncEvents.PeerHeadersRequestSuccessful.Inc()
			out = HeadersResponse{Found: true, Range: reqRange, Headers: blocks}
		} else {
			w.Metrics.BlocksyncEvents.PeerHeadersRequestFailed.Inc()
			out = HeadersResponse{Found: false, Range: reqRange}
		}
		cmds = append(cmds, &CmdSendResponse{
			To:       requester,
			Response: ResponseMessage{Headers: out},
		})
	}
	var sender *types.NodeId
	cmds = append(cmds, w.handleHeadersResponseForSelf(sender, hr)...)
	return cmds
}

// HandlePeerResponse — Rust handle_peer_response.
func (w *Wrapper) HandlePeerResponse(sender types.NodeId, response ResponseMessage) []Command {
	if response.IsPayload {
		return w.handlePayloadResponseForSelf(&sender, response.Body)
	}
	return w.handleHeadersResponseForSelf(&sender, response.Headers)
}

// HandleTimeout — Rust handle_timeout: re-request from a new peer.
func (w *Wrapper) HandleTimeout(request RequestMessage) []Command {
	w.Metrics.BlocksyncEvents.RequestTimeout.Inc()
	var cmds []Command
	if !request.IsPayload {
		blockRange := request.Range
		if req, ok := w.BS.selfHeadersRequests[blockRange]; ok {
			maybeTo := w.pickPeer()
			req.To = maybeTo
			w.BS.selfHeadersRequests[blockRange] = req
			if maybeTo != nil {
				cmds = append(cmds, &CmdSendRequest{To: *maybeTo, Request: RequestHeaders(blockRange)})
			} else {
				w.Metrics.BlocksyncEvents.RequestFailedNoPeers.Inc()
			}
			cmds = append(cmds, &CmdScheduleTimeout{Request: RequestHeaders(blockRange)})
		}
	} else {
		payloadID := request.PayloadID
		if req, ok := w.BS.selfPayloadRequests[payloadID]; ok {
			if req == nil {
				return cmds
			}
			maybeTo := w.pickPeer()
			req.To = maybeTo
			if maybeTo != nil {
				cmds = append(cmds, &CmdSendRequest{To: *maybeTo, Request: RequestPayload(payloadID)})
			} else {
				w.Metrics.BlocksyncEvents.RequestFailedNoPeers.Inc()
			}
			cmds = append(cmds, &CmdScheduleTimeout{Request: RequestPayload(payloadID)})
		}
	}
	return cmds
}
