package peerdisc

// Ported from monad-bft/monad-peer-discovery/src/discovery.rs +
// ipv4_validation.rs + the PeerDiscTimers/emit layer of driver.rs.
// The state machine is pure (events in → commands out); the embedder
// executes RouterCommand/PingPongCommand/TimerCommand.

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"sort"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

const (
	numLookupPeers        = 3
	numUpstreamValidators = 3
	lookupRateLimitPerSec = 10 // governor: per_second(10).allow_burst(10)
)

// PeerDiscoveryRole — Rust PeerDiscoveryRole.
type PeerDiscoveryRole int

const (
	RoleValidatorNone PeerDiscoveryRole = iota
	RoleValidatorPublisher
	RoleFullNodeNone
	RoleFullNodeClient
)

// ConnectionInfo — pending-queue entry (Rust ConnectionInfo).
type ConnectionInfo struct {
	LastPing          Ping
	UnresponsivePings uint32
	NameRecord        MonadNameRecord
}

type SecondaryRaptorcastStatus int

const (
	SecondaryStatusNone SecondaryRaptorcastStatus = iota
	SecondaryStatusPending
	SecondaryStatusConnected
)

// SecondaryRaptorcastInfo — Rust SecondaryRaptorcastInfo.
type SecondaryRaptorcastInfo struct {
	Status     SecondaryRaptorcastStatus
	NumRetries uint32
	LastActive types.Round
}

// LookupInfo — Rust LookupInfo.
type LookupInfo struct {
	NumRetries    uint32
	Receiver      types.NodeId
	OpenDiscovery bool
}

// PeerSource — Rust PeerSource { id, addr }.
type PeerSource struct {
	ID   types.NodeId
	Addr netip.AddrPort
}

// --- events & commands (Rust PeerDiscoveryEvent/Command) ---

type TimerKind uint8

const (
	TimerSendPing TimerKind = iota
	TimerPingTimeout
	TimerRetryPeerLookup
	TimerRefresh
	TimerFullNodeRaptorcastRequest
)

// PeerDiscoveryEvent — the tagged event union. Populate exactly one variant.
type PeerDiscoveryEvent struct {
	Kind eventKind

	// SendPing / PingRequest / PongResponse / PingTimeout
	To         types.NodeId
	NameRecord NameRecord
	Ping       Ping
	Pong       Pong
	PingID     uint32

	// lookups
	From           PeerSource
	Target         types.NodeId
	OpenDiscovery  bool
	LookupRequest  PeerLookupRequest
	LookupResponse PeerLookupResponse
	LookupID       uint32

	// round/validator-set/peers updates
	Round      types.Round
	Epoch      types.Epoch
	Validators []types.NodeId
	// UpdatePeers: self-signed peer entries (Rust Vec<PeerEntry>).
	Peers                []glue.PeerEntry
	DedicatedFullNodes   []types.NodeId
	PrioritizedFullNodes []types.NodeId
	EndRound             types.Round
	ConfirmGroupPeers    []types.NodeId
}

type eventKind int

const (
	evSendPing eventKind = iota
	evPingRequest
	evPongResponse
	evPingTimeout
	evSendPeerLookup
	evPeerLookupRequest
	evPeerLookupResponse
	evPeerLookupTimeout
	evSendFullNodeRaptorcastRequest
	evFullNodeRaptorcastRequest
	evFullNodeRaptorcastResponse
	evUpdateCurrentRound
	evUpdateValidatorSet
	evUpdatePeers
	evUpdatePinnedNodes
	evUpdateConfirmGroup
	evRefresh
)

// --- public event constructors (event kinds stay package-private; callers
// build events through these, mirroring the Rust enum variants) ---

// InboundEvent — Rust PeerDiscoveryMessage::event_with_source: a decoded
// discovery message plus the transport-level source (author, src socket).
func InboundEvent(from PeerSource, m PeerDiscoveryMessage) (PeerDiscoveryEvent, bool) {
	switch m.Kind {
	case msgKindPing:
		return PeerDiscoveryEvent{Kind: evPingRequest, From: from, Ping: *m.Ping}, true
	case msgKindPong:
		return PeerDiscoveryEvent{Kind: evPongResponse, From: from, Pong: *m.Pong}, true
	case msgKindPeerLookupRequest:
		return PeerDiscoveryEvent{Kind: evPeerLookupRequest, From: from, LookupRequest: *m.LookupRequest}, true
	case msgKindPeerLookupResponse:
		return PeerDiscoveryEvent{Kind: evPeerLookupResponse, From: from, LookupResponse: *m.LookupResponse}, true
	case msgKindFullNodeRaptorcastRequest:
		return PeerDiscoveryEvent{Kind: evFullNodeRaptorcastRequest, From: from}, true
	case msgKindFullNodeRaptorcastResponse:
		return PeerDiscoveryEvent{Kind: evFullNodeRaptorcastResponse, From: from}, true
	}
	return PeerDiscoveryEvent{}, false
}

// UpdateValidatorSetEvent — Rust PeerDiscoveryEvent::UpdateValidatorSet.
func UpdateValidatorSetEvent(epoch types.Epoch, validators []types.NodeId) PeerDiscoveryEvent {
	return PeerDiscoveryEvent{Kind: evUpdateValidatorSet, Epoch: epoch, Validators: validators}
}

// UpdateCurrentRoundEvent — Rust PeerDiscoveryEvent::UpdateCurrentRound.
func UpdateCurrentRoundEvent(epoch types.Epoch, round types.Round) PeerDiscoveryEvent {
	return PeerDiscoveryEvent{Kind: evUpdateCurrentRound, Epoch: epoch, Round: round}
}

// UpdatePeersEvent — Rust PeerDiscoveryEvent::UpdatePeers.
func UpdatePeersEvent(peers []glue.PeerEntry) PeerDiscoveryEvent {
	return PeerDiscoveryEvent{Kind: evUpdatePeers, Peers: peers}
}

// UpdatePinnedNodesEvent — Rust PeerDiscoveryEvent::UpdatePinnedNodes.
func UpdatePinnedNodesEvent(dedicated, prioritized []types.NodeId) PeerDiscoveryEvent {
	return PeerDiscoveryEvent{Kind: evUpdatePinnedNodes, DedicatedFullNodes: dedicated, PrioritizedFullNodes: prioritized}
}

// TimerCommand — Schedule or ScheduleReset.
type TimerCommand struct {
	Reset     bool // true = ScheduleReset
	NodeID    types.NodeId
	Kind      TimerKind
	Duration  time.Duration
	OnTimeout PeerDiscoveryEvent
}

// CommandKind for PeerDiscoveryCommand.
type CommandKind int

const (
	CmdRouter CommandKind = iota
	CmdPingPong
	CmdTimer
)

// PeerDiscoveryCommand — Rust PeerDiscoveryCommand.
type PeerDiscoveryCommand struct {
	Kind       CommandKind
	Target     types.NodeId
	NameRecord NameRecord // PingPongCommand only
	Message    PeerDiscoveryMessage
	Timer      TimerCommand
}

func timerSchedule(nodeID types.NodeId, kind TimerKind, d time.Duration, ev PeerDiscoveryEvent) PeerDiscoveryCommand {
	return PeerDiscoveryCommand{
		Kind:  CmdTimer,
		Timer: TimerCommand{NodeID: nodeID, Kind: kind, Duration: d, OnTimeout: ev},
	}
}

func timerReset(nodeID types.NodeId, kind TimerKind) PeerDiscoveryCommand {
	return PeerDiscoveryCommand{
		Kind:  CmdTimer,
		Timer: TimerCommand{Reset: true, NodeID: nodeID, Kind: kind},
	}
}

// --- rate limiter (governor direct, per_second(N).allow_burst(N)) ---

type tokenBucket struct {
	rps, burst float64
	tokens     float64
	last       time.Time
	now        func() time.Time
}

func newTokenBucket(rps uint32) *tokenBucket {
	return &tokenBucket{
		rps: float64(rps), burst: float64(rps), tokens: float64(rps),
		last: time.Now(), now: time.Now,
	}
}

func (t *tokenBucket) check() bool {
	now := t.now()
	t.tokens += now.Sub(t.last).Seconds() * t.rps
	t.last = now
	if t.tokens > t.burst {
		t.tokens = t.burst
	}
	if t.tokens >= 1 {
		t.tokens--
		return true
	}
	return false
}

// --- the algorithm ---

type PeerDiscovery struct {
	SelfID     types.NodeId
	SelfRecord MonadNameRecord
	SelfRole   PeerDiscoveryRole

	CurrentRound types.Round
	CurrentEpoch types.Epoch

	EpochValidators       map[types.Epoch]map[types.NodeId]struct{}
	InitialBootstrapPeers map[types.NodeId]struct{}
	bootstrapRecords      map[types.NodeId]MonadNameRecord
	PrioritizedFullNodes  map[types.NodeId]struct{}
	PinnedFullNodes       map[types.NodeId]struct{}

	RoutingInfo       map[types.NodeId]MonadNameRecord
	ParticipationInfo map[types.NodeId]*SecondaryRaptorcastInfo
	PendingQueue      map[types.NodeId]*ConnectionInfo
	SocketToID        map[netip.AddrPort]types.NodeId

	OutstandingLookupRequests map[uint32]LookupInfo

	RefreshPeriod                   time.Duration
	RequestTimeout                  time.Duration
	UnresponsivePruneThreshold      uint32
	LastParticipationPruneThreshold types.Round
	MinNumPeers, MaxNumPeers        int
	MaxGroupSize                    int
	EnablePublisher, EnableClient   bool

	Rng *rand.Rand

	PersistedPeersPath string

	pingLimiter       *tokenBucket
	peerLookupLimiter *tokenBucket
}

// PeerDiscoveryBuilder mirrors PeerDiscoveryBuilder.
type PeerDiscoveryBuilder struct {
	SelfID                          types.NodeId
	SelfRecord                      MonadNameRecord
	CurrentRound                    types.Round
	CurrentEpoch                    types.Epoch
	EpochValidators                 map[types.Epoch]map[types.NodeId]struct{}
	BootstrapPeers                  map[types.NodeId]MonadNameRecord
	PrioritizedFullNodes            map[types.NodeId]struct{}
	PinnedFullNodes                 map[types.NodeId]struct{}
	RefreshPeriod                   time.Duration
	RequestTimeout                  time.Duration
	UnresponsivePruneThreshold      uint32
	LastParticipationPruneThreshold types.Round
	MinNumPeers, MaxNumPeers        int
	MaxGroupSize                    int
	EnablePublisher, EnableClient   bool
	PingRateLimitPerSecond          uint32
	RngSeed                         uint64
	PersistedPeersPath              string
}

// Build — Rust PeerDiscoveryAlgoBuilder::build.
func (b PeerDiscoveryBuilder) Build() (*PeerDiscovery, []PeerDiscoveryCommand) {
	if b.MaxNumPeers <= b.MinNumPeers {
		panic("peerdisc: max_num_peers must exceed min_num_peers")
	}
	isValidator := b.EpochValidators[b.CurrentEpoch] != nil &&
		mapHas(b.EpochValidators[b.CurrentEpoch], b.SelfID)
	var role PeerDiscoveryRole
	switch {
	case isValidator && b.EnablePublisher:
		role = RoleValidatorPublisher
	case isValidator:
		role = RoleValidatorNone
	case b.EnableClient:
		role = RoleFullNodeClient
	default:
		role = RoleFullNodeNone
	}

	var seed [32]byte
	seed[0] = byte(b.RngSeed)
	seed[1] = byte(b.RngSeed >> 8)
	seed[2] = byte(b.RngSeed >> 16)
	seed[3] = byte(b.RngSeed >> 24)
	seed[4] = byte(b.RngSeed >> 32)
	seed[5] = byte(b.RngSeed >> 40)
	seed[6] = byte(b.RngSeed >> 48)
	seed[7] = byte(b.RngSeed >> 56)

	state := &PeerDiscovery{
		SelfID:                          b.SelfID,
		SelfRecord:                      b.SelfRecord,
		SelfRole:                        role,
		CurrentRound:                    b.CurrentRound,
		CurrentEpoch:                    b.CurrentEpoch,
		EpochValidators:                 b.EpochValidators,
		PinnedFullNodes:                 b.PinnedFullNodes,
		PrioritizedFullNodes:            b.PrioritizedFullNodes,
		RoutingInfo:                     map[types.NodeId]MonadNameRecord{},
		ParticipationInfo:               map[types.NodeId]*SecondaryRaptorcastInfo{},
		PendingQueue:                    map[types.NodeId]*ConnectionInfo{},
		SocketToID:                      map[netip.AddrPort]types.NodeId{},
		OutstandingLookupRequests:       map[uint32]LookupInfo{},
		RefreshPeriod:                   b.RefreshPeriod,
		RequestTimeout:                  b.RequestTimeout,
		UnresponsivePruneThreshold:      b.UnresponsivePruneThreshold,
		LastParticipationPruneThreshold: b.LastParticipationPruneThreshold,
		MinNumPeers:                     b.MinNumPeers,
		MaxNumPeers:                     b.MaxNumPeers,
		MaxGroupSize:                    b.MaxGroupSize,
		EnablePublisher:                 b.EnablePublisher,
		EnableClient:                    b.EnableClient,
		Rng:                             rand.New(rand.NewChaCha8(seed)),
		PersistedPeersPath:              b.PersistedPeersPath,
		pingLimiter:                     newTokenBucket(b.PingRateLimitPerSecond),
		peerLookupLimiter:               newTokenBucket(lookupRateLimitPerSec),
	}
	state.InitialBootstrapPeers = map[types.NodeId]struct{}{}
	state.bootstrapRecords = map[types.NodeId]MonadNameRecord{}
	for id, nr := range b.BootstrapPeers {
		state.InitialBootstrapPeers[id] = struct{}{}
		state.bootstrapRecords[id] = nr
	}
	if state.EpochValidators == nil {
		state.EpochValidators = map[types.Epoch]map[types.NodeId]struct{}{}
	}

	var cmds []PeerDiscoveryCommand
	// sorted for deterministic bootstrap order (Rust BTreeMap iteration)
	for _, id := range sortedKeys(b.BootstrapPeers) {
		if c, err := state.insertPeerToPending(id, b.BootstrapPeers[id]); err == nil {
			cmds = append(cmds, c...)
		}
	}
	cmds = append(cmds, state.readPeersFromFile()...)
	cmds = append(cmds, state.refresh()...)
	return state, cmds
}

func mapHas(m map[types.NodeId]struct{}, id types.NodeId) bool {
	_, ok := m[id]
	return ok
}

func sortedKeys(m map[types.NodeId]MonadNameRecord) []types.NodeId {
	ids := make([]types.NodeId, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Cmp(ids[j]) < 0 })
	return ids
}

func sortedIDSet(m map[types.NodeId]struct{}) []types.NodeId {
	ids := make([]types.NodeId, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].Cmp(ids[j]) < 0 })
	return ids
}

// chooseMultiple — Rust's choose_multiple (random sample without replacement).
func chooseMultiple(r *rand.Rand, in []types.NodeId, n int) []types.NodeId {
	if len(in) <= n {
		return in
	}
	perm := r.Perm(len(in))
	out := make([]types.NodeId, 0, n)
	for _, idx := range perm[:n] {
		out = append(out, in[idx])
	}
	return out
}

func (d *PeerDiscovery) schedulePingTimeout(peer types.NodeId, pingID uint32) []PeerDiscoveryCommand {
	ev := PeerDiscoveryEvent{Kind: evPingTimeout, To: peer, PingID: pingID}
	return []PeerDiscoveryCommand{timerSchedule(peer, TimerPingTimeout, d.RequestTimeout, ev)}
}

func (d *PeerDiscovery) clearPingTimeout(peer types.NodeId) []PeerDiscoveryCommand {
	return []PeerDiscoveryCommand{timerReset(peer, TimerPingTimeout)}
}

func (d *PeerDiscovery) resetRefreshTimer() []PeerDiscoveryCommand {
	return []PeerDiscoveryCommand{
		timerReset(d.SelfID, TimerRefresh),
		timerSchedule(d.SelfID, TimerRefresh, d.RefreshPeriod,
			PeerDiscoveryEvent{Kind: evRefresh}),
	}
}

func (d *PeerDiscovery) scheduleFullNodeRaptorcastTimeout(to types.NodeId) []PeerDiscoveryCommand {
	return []PeerDiscoveryCommand{
		timerReset(to, TimerFullNodeRaptorcastRequest),
		timerSchedule(to, TimerFullNodeRaptorcastRequest, d.RequestTimeout,
			PeerDiscoveryEvent{Kind: evSendFullNodeRaptorcastRequest, To: to}),
	}
}

func (d *PeerDiscovery) scheduleLookupTimeout(to, target types.NodeId, lookupID uint32) []PeerDiscoveryCommand {
	return []PeerDiscoveryCommand{timerSchedule(to, TimerRetryPeerLookup, d.RequestTimeout,
		PeerDiscoveryEvent{Kind: evPeerLookupTimeout, To: to, Target: target, LookupID: lookupID})}
}

func (d *PeerDiscovery) clearConnectionInfo() {
	for _, info := range d.ParticipationInfo {
		info.Status = SecondaryStatusNone
	}
}

// insertPeerToPending — Rust insert_peer_to_pending.
func (d *PeerDiscovery) insertPeerToPending(peerID types.NodeId, nr MonadNameRecord) ([]PeerDiscoveryCommand, error) {
	if peerID == d.SelfID {
		return nil, nil
	}
	if err := validateSocketIPv4Address(nr.AuthUDPSocket(), d.SelfRecord.AuthUDPSocket()); err != nil {
		return nil, err
	}
	if cur, ok := d.RoutingInfo[peerID]; ok && nr.Seq() <= cur.Seq() {
		return nil, nil
	}
	if info, ok := d.PendingQueue[peerID]; ok && nr.Seq() <= info.NameRecord.Seq() {
		return nil, nil
	}
	ping := Ping{ID: d.Rng.Uint32(), LocalNameRecord: d.SelfRecord}
	d.PendingQueue[peerID] = &ConnectionInfo{
		LastPing:   ping,
		NameRecord: nr,
	}
	return d.SendPing(peerID, nr.NameRecord, ping), nil
}

func (d *PeerDiscovery) removePeerFromPending(peerID types.NodeId) []PeerDiscoveryCommand {
	delete(d.PendingQueue, peerID)
	return d.clearPingTimeout(peerID)
}

func (d *PeerDiscovery) promotePeerToRoutingInfo(peer types.NodeId, nr MonadNameRecord) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	old, had := d.RoutingInfo[peer]
	d.RoutingInfo[peer] = nr
	if info, ok := d.ParticipationInfo[peer]; ok {
		if info.LastActive < d.CurrentRound {
			info.LastActive = d.CurrentRound
		}
	} else {
		d.ParticipationInfo[peer] = &SecondaryRaptorcastInfo{
			Status:     SecondaryStatusNone,
			LastActive: d.CurrentRound,
		}
	}
	cmds = append(cmds, d.removePeerFromPending(peer)...)
	if had {
		for _, s := range old.AllUDPSockets() {
			delete(d.SocketToID, s)
		}
	}
	for _, s := range nr.AllUDPSockets() {
		d.SocketToID[s] = peer
	}
	if d.SelfRole == RoleFullNodeClient {
		cmds = append(cmds, d.lookForUpstreamValidators()...)
	}
	return cmds
}

func (d *PeerDiscovery) lookForUpstreamValidators() []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	// drop stale Connected upstreams
	for id, info := range d.ParticipationInfo {
		if info.Status == SecondaryStatusConnected &&
			maxRound(d.CurrentRound, info.LastActive)-info.LastActive >= d.LastParticipationPruneThreshold {
			info.Status = SecondaryStatusNone
		}
		_ = id
	}
	connected := map[types.NodeId]struct{}{}
	for id, info := range d.ParticipationInfo {
		if info.Status != SecondaryStatusNone {
			connected[id] = struct{}{}
		}
	}
	slots := numUpstreamValidators - len(connected)
	if slots <= 0 {
		return cmds
	}
	var avail []types.NodeId
	for id := range d.RoutingInfo {
		if mapHas(connected, id) || !d.checkCurrentEpochValidator(id) || id == d.SelfID {
			continue
		}
		avail = append(avail, id)
	}
	sortIDs(avail)
	for _, v := range chooseMultiple(d.Rng, avail, slots) {
		cmds = append(cmds, PeerDiscoveryCommand{
			Kind:   CmdRouter,
			Target: v,
			Message: PingMessage(Ping{
				ID:              d.Rng.Uint32(),
				LocalNameRecord: d.SelfRecord,
			}),
		})
		cmds = append(cmds, d.SendFullNodeRaptorcastRequest(v)...)
	}
	return cmds
}

func (d *PeerDiscovery) selectPeersToLookupFrom() []types.NodeId {
	switch d.SelfRole {
	case RoleValidatorNone, RoleValidatorPublisher:
		return chooseMultiple(d.Rng, keysOf(d.RoutingInfo), numLookupPeers)
	case RoleFullNodeClient:
		var conns []types.NodeId
		for id, info := range d.ParticipationInfo {
			if info.Status == SecondaryStatusConnected {
				conns = append(conns, id)
			}
		}
		sortIDs(conns)
		selected := chooseMultiple(d.Rng, conns, numLookupPeers)
		if len(selected) < numLookupPeers {
			sel := map[types.NodeId]struct{}{}
			for _, id := range selected {
				sel[id] = struct{}{}
			}
			var rest []types.NodeId
			for id := range d.RoutingInfo {
				if !mapHas(sel, id) {
					rest = append(rest, id)
				}
			}
			sortIDs(rest)
			selected = append(selected,
				chooseMultiple(d.Rng, rest, numLookupPeers-len(selected))...)
		}
		return selected
	default: // FullNodeNone
		return chooseMultiple(d.Rng, sortedIDSet(d.InitialBootstrapPeers), numLookupPeers)
	}
}

func (d *PeerDiscovery) checkCurrentEpochValidator(id types.NodeId) bool {
	return mapHas(d.EpochValidators[d.CurrentEpoch], id)
}

func (d *PeerDiscovery) checkNextEpochValidator(id types.NodeId) bool {
	return mapHas(d.EpochValidators[d.CurrentEpoch+1], id)
}

func (d *PeerDiscovery) checkValidatorMembership(id types.NodeId) bool {
	return d.checkCurrentEpochValidator(id) || d.checkNextEpochValidator(id)
}

func (d *PeerDiscovery) isPinnedNode(id types.NodeId) bool {
	return d.checkValidatorMembership(id) || mapHas(d.PinnedFullNodes, id)
}

func (d *PeerDiscovery) checkSocketAvailability(from types.NodeId, socket netip.AddrPort) bool {
	if expected, ok := d.SocketToID[socket]; ok && expected != from {
		return false
	}
	return true
}

// --- public handlers (Rust PeerDiscoveryAlgo) ---

func (d *PeerDiscovery) SendPing(to types.NodeId, nr NameRecord, ping Ping) []PeerDiscoveryCommand {
	cmds := d.schedulePingTimeout(to, ping.ID)
	return append(cmds, PeerDiscoveryCommand{
		Kind: CmdPingPong, Target: to, NameRecord: nr,
		Message: PingMessage(ping),
	})
}

func (d *PeerDiscovery) HandlePing(from PeerSource, ping Ping) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	if expected := ping.LocalNameRecord.NameRecord.IP; from.Addr.Addr() != expected {
		return nil // source IP must match name record IP
	}
	fromID := from.ID
	if !d.pingLimiter.check() {
		return nil
	}
	peerNR := ping.LocalNameRecord
	for _, socket := range peerNR.AllUDPSockets() {
		if !d.checkSocketAvailability(fromID, socket) {
			return nil
		}
	}
	recovered, err := peerNR.RecoverPubKey()
	if err != nil || recovered != fromID {
		return nil
	}

	peerListFull := false
	if len(d.RoutingInfo)+len(d.PendingQueue) >= d.MaxNumPeers &&
		!d.isPinnedNode(fromID) {
		if _, ok := d.RoutingInfo[fromID]; !ok {
			peerListFull = true
		}
	}
	if !peerListFull {
		if cur, ok := d.RoutingInfo[fromID]; !ok || peerNR.Seq() > cur.Seq() {
			c, err := d.insertPeerToPending(fromID, peerNR)
			if err != nil {
				return cmds
			}
			cmds = append(cmds, c...)
		} else if peerNR.Seq() < cur.Seq() || (peerNR.Seq() == cur.Seq() && !peerNR.Equal(cur)) {
			// seq went backwards, or same seq with different record
			return cmds
		}
	}
	pong := Pong{PingID: ping.ID, LocalRecordSeq: d.SelfRecord.Seq()}
	return append(cmds, PeerDiscoveryCommand{
		Kind: CmdPingPong, Target: fromID,
		NameRecord: ping.LocalNameRecord.NameRecord,
		Message:    PongMessage(pong),
	})
}

func (d *PeerDiscovery) HandlePong(from PeerSource, pong Pong) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	info, ok := d.PendingQueue[from.ID]
	if !ok {
		return nil
	}
	if expected := info.NameRecord.NameRecord.IP; from.Addr.Addr() != expected {
		return nil
	}
	if info.LastPing.ID == pong.PingID {
		cmds = append(cmds, d.promotePeerToRoutingInfo(from.ID, info.NameRecord)...)
	}
	return cmds
}

func (d *PeerDiscovery) HandlePingTimeout(to types.NodeId, pingID uint32) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	info, ok := d.PendingQueue[to]
	if !ok || info.LastPing.ID != pingID {
		return cmds
	}
	info.UnresponsivePings++
	if info.UnresponsivePings >= d.UnresponsivePruneThreshold {
		return append(cmds, d.removePeerFromPending(to)...)
	}
	nr := info.NameRecord.NameRecord
	ping := Ping{ID: d.Rng.Uint32(), LocalNameRecord: d.SelfRecord}
	info.LastPing = ping
	return append(cmds, d.SendPing(to, nr, ping)...)
}

func (d *PeerDiscovery) SendPeerLookupRequest(to, target types.NodeId, openDiscovery bool) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	lookupID := d.Rng.Uint32()
	for {
		if _, taken := d.OutstandingLookupRequests[lookupID]; !taken {
			break
		}
		lookupID = d.Rng.Uint32()
	}
	d.OutstandingLookupRequests[lookupID] = LookupInfo{Receiver: to, OpenDiscovery: openDiscovery}
	req := PeerLookupRequest{LookupID: lookupID, Target: target, OpenDiscovery: openDiscovery}
	cmds = append(cmds, d.scheduleLookupTimeout(to, target, lookupID)...)
	return append(cmds, PeerDiscoveryCommand{
		Kind: CmdRouter, Target: to,
		Message: PeerLookupRequestMessage(req),
	})
}

func (d *PeerDiscovery) HandlePeerLookupRequest(from PeerSource, req PeerLookupRequest) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	if !d.peerLookupLimiter.check() {
		return nil
	}
	fromID := from.ID
	var records []MonadNameRecord
	if req.Target == d.SelfID {
		records = append(records, d.SelfRecord)
	} else if nr, ok := d.RoutingInfo[req.Target]; ok {
		records = append(records, nr)
	}
	if req.OpenDiscovery {
		var validators []types.NodeId
		for id := range d.RoutingInfo {
			if d.checkValidatorMembership(id) {
				validators = append(validators, id)
			}
		}
		sortIDs(validators)
		for _, id := range chooseMultiple(d.Rng, validators, maxPeersInResponse-len(records)) {
			records = append(records, d.RoutingInfo[id])
		}
	}
	resp := PeerLookupResponse{LookupID: req.LookupID, Target: req.Target, NameRecords: records}
	return append(cmds, PeerDiscoveryCommand{
		Kind: CmdRouter, Target: fromID,
		Message: PeerLookupResponseMessage(resp),
	})
}

func (d *PeerDiscovery) HandlePeerLookupResponse(from PeerSource, resp PeerLookupResponse) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	info, ok := d.OutstandingLookupRequests[resp.LookupID]
	if !ok || info.Receiver != from.ID {
		return nil
	}
	if len(resp.NameRecords) > maxPeersInResponse {
		return nil
	}
	for _, nr := range resp.NameRecords {
		nodeID, err := nr.RecoverPubKey()
		if err != nil {
			continue
		}
		if c, err := d.insertPeerToPending(nodeID, nr); err == nil {
			cmds = append(cmds, c...)
		}
	}
	delete(d.OutstandingLookupRequests, resp.LookupID)
	return cmds
}

func (d *PeerDiscovery) HandlePeerLookupTimeout(to, target types.NodeId, lookupID uint32) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	info, ok := d.OutstandingLookupRequests[lookupID]
	if !ok {
		return nil
	}
	if info.NumRetries >= d.UnresponsivePruneThreshold {
		delete(d.OutstandingLookupRequests, lookupID)
		return nil
	}
	openDiscovery := info.OpenDiscovery
	numRetries := info.NumRetries + 1
	delete(d.OutstandingLookupRequests, lookupID)

	newID := d.Rng.Uint32()
	for {
		if _, taken := d.OutstandingLookupRequests[newID]; !taken {
			break
		}
		newID = d.Rng.Uint32()
	}
	d.OutstandingLookupRequests[newID] = LookupInfo{
		NumRetries: numRetries, Receiver: to, OpenDiscovery: openDiscovery,
	}
	req := PeerLookupRequest{LookupID: newID, Target: target, OpenDiscovery: openDiscovery}
	cmds = append(cmds, d.scheduleLookupTimeout(to, target, newID)...)
	return append(cmds, PeerDiscoveryCommand{
		Kind: CmdRouter, Target: to,
		Message: PeerLookupRequestMessage(req),
	})
}

func (d *PeerDiscovery) SendFullNodeRaptorcastRequest(to types.NodeId) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	if d.SelfRole != RoleFullNodeClient {
		return nil
	}
	info, ok := d.ParticipationInfo[to]
	if !ok {
		return nil
	}
	switch info.Status {
	case SecondaryStatusNone:
		info.Status = SecondaryStatusPending
		info.NumRetries = 0
	case SecondaryStatusPending:
		info.NumRetries++
		if info.NumRetries >= d.UnresponsivePruneThreshold {
			info.Status = SecondaryStatusNone
			info.NumRetries = 0
			return append(cmds, d.lookForUpstreamValidators()...)
		}
	case SecondaryStatusConnected:
		return nil
	}
	cmds = append(cmds, PeerDiscoveryCommand{
		Kind: CmdRouter, Target: to,
		Message: FullNodeRaptorcastRequestMessage,
	})
	return append(cmds, d.scheduleFullNodeRaptorcastTimeout(to)...)
}

func (d *PeerDiscovery) HandleFullNodeRaptorcastRequest(from PeerSource) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	if d.SelfRole != RoleValidatorPublisher {
		return nil
	}
	if !mapHas(d.PrioritizedFullNodes, from.ID) {
		connectedPublic := 0
		for id, info := range d.ParticipationInfo {
			if info.Status == SecondaryStatusConnected && !mapHas(d.PrioritizedFullNodes, id) {
				connectedPublic++
			}
		}
		if connectedPublic+len(d.PrioritizedFullNodes) >= d.MaxGroupSize {
			return nil
		}
	}
	info, ok := d.ParticipationInfo[from.ID]
	if !ok {
		return nil
	}
	info.Status = SecondaryStatusConnected
	return append(cmds, PeerDiscoveryCommand{
		Kind: CmdRouter, Target: from.ID,
		Message: FullNodeRaptorcastResponseMessage,
	})
}

func (d *PeerDiscovery) HandleFullNodeRaptorcastResponse(from PeerSource) []PeerDiscoveryCommand {
	if d.SelfRole != RoleFullNodeClient {
		return nil
	}
	if info, ok := d.ParticipationInfo[from.ID]; ok && info.Status == SecondaryStatusPending {
		info.Status = SecondaryStatusConnected
		info.NumRetries = 0
	}
	return nil
}

// Refresh — Rust refresh(): prune non-participating, cap peers, lookup missing.
func (d *PeerDiscovery) refresh() []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand

	// prune nodes that haven't participated beyond threshold
	var nonParticipating []types.NodeId
	for id, info := range d.ParticipationInfo {
		if maxRound(d.CurrentRound, info.LastActive)-info.LastActive >= d.LastParticipationPruneThreshold {
			nonParticipating = append(nonParticipating, id)
		}
	}
	sortIDs(nonParticipating)
	for _, id := range nonParticipating {
		if d.isPinnedNode(id) {
			if info, ok := d.ParticipationInfo[id]; ok {
				info.Status = SecondaryStatusNone
			}
			continue
		}
		delete(d.ParticipationInfo, id)
		if old, ok := d.RoutingInfo[id]; ok {
			delete(d.RoutingInfo, id)
			for _, s := range old.AllUDPSockets() {
				delete(d.SocketToID, s)
			}
		}
	}

	// cap routing_info at max_num_peers (never prune validators/pinned)
	if len(d.RoutingInfo) > d.MaxNumPeers {
		var excess []types.NodeId
		for id := range d.RoutingInfo {
			if !d.isPinnedNode(id) {
				excess = append(excess, id)
			}
		}
		sortIDs(excess)
		for _, id := range chooseMultiple(d.Rng, excess, len(d.RoutingInfo)-d.MaxNumPeers) {
			delete(d.ParticipationInfo, id)
			if old, ok := d.RoutingInfo[id]; ok {
				delete(d.RoutingInfo, id)
				for _, s := range old.AllUDPSockets() {
					delete(d.SocketToID, s)
				}
			}
		}
	}

	// re-ping bootstrap peers that never connected — without this a node
	// whose initial pings were lost (peer not yet listening) is stranded
	// permanently once pending entries are evicted.
	for _, id := range sortedIDSet(d.InitialBootstrapPeers) {
		if _, ok := d.RoutingInfo[id]; ok {
			continue
		}
		if _, ok := d.PendingQueue[id]; ok {
			continue
		}
		if nr, ok := d.bootstrapRecords[id]; ok {
			if c, err := d.insertPeerToPending(id, nr); err == nil {
				cmds = append(cmds, c...)
			}
		}
	}

	// missing validators in current/next epoch
	seen := map[types.NodeId]struct{}{}
	var missing []types.NodeId
	for _, ep := range []types.Epoch{d.CurrentEpoch, d.CurrentEpoch + 1} {
		for id := range d.EpochValidators[ep] {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			if _, known := d.RoutingInfo[id]; !known && id != d.SelfID {
				missing = append(missing, id)
			}
		}
	}
	sortIDs(missing)
	missing = chooseMultiple(d.Rng, missing, numLookupPeers)
	chosen := d.selectPeersToLookupFrom()

	if len(d.RoutingInfo) < d.MinNumPeers {
		for i := range missing {
			if i >= len(chosen) {
				break
			}
			cmds = append(cmds, d.SendPeerLookupRequest(chosen[i], missing[i], true)...)
		}
	} else {
		for i := range missing {
			if i >= len(chosen) {
				break
			}
			cmds = append(cmds, d.SendPeerLookupRequest(chosen[i], missing[i], false)...)
		}
	}

	// full nodes: open discovery to a random validator each refresh
	if (d.SelfRole == RoleFullNodeNone || d.SelfRole == RoleFullNodeClient) && len(chosen) > 0 {
		if validators := d.EpochValidators[d.CurrentEpoch]; len(validators) > 0 {
			vs := sortedIDSet(validators)
			rv := vs[d.Rng.IntN(len(vs))]
			cmds = append(cmds,
				d.SendPeerLookupRequest(chosen[len(chosen)-1], rv, true)...)
		}
	}

	if d.SelfRole == RoleFullNodeClient {
		cmds = append(cmds, d.lookForUpstreamValidators()...)
	}

	d.writePeersToFile()
	return append(cmds, d.resetRefreshTimer()...)
}

// UpdateCurrentRound — Rust update_current_round.
func (d *PeerDiscovery) UpdateCurrentRound(round types.Round, epoch types.Epoch) []PeerDiscoveryCommand {
	if round > d.CurrentRound {
		d.CurrentRound = round
	}
	if epoch > d.CurrentEpoch {
		d.CurrentEpoch = epoch
		if (d.SelfRole == RoleFullNodeNone || d.SelfRole == RoleFullNodeClient) &&
			d.checkCurrentEpochValidator(d.SelfID) {
			if d.EnablePublisher {
				d.SelfRole = RoleValidatorPublisher
			} else {
				d.SelfRole = RoleValidatorNone
			}
			d.clearConnectionInfo()
		}
	}
	for ep := range d.EpochValidators {
		if ep+1 < d.CurrentEpoch {
			delete(d.EpochValidators, ep)
		}
	}
	return nil
}

// UpdateValidatorSet — Rust update_validator_set.
func (d *PeerDiscovery) UpdateValidatorSet(epoch types.Epoch, validators []types.NodeId) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	set := map[types.NodeId]struct{}{}
	for _, v := range validators {
		set[v] = struct{}{}
	}
	d.EpochValidators[epoch] = set

	if epoch == d.CurrentEpoch+1 {
		isNextValidator := mapHas(set, d.SelfID)
		if (d.SelfRole == RoleFullNodeClient || d.SelfRole == RoleFullNodeNone) && isNextValidator {
			for _, v := range sortedIDSet(set) {
				if _, ok := d.RoutingInfo[v]; ok {
					cmds = append(cmds, PeerDiscoveryCommand{
						Kind: CmdRouter, Target: v,
						Message: PingMessage(Ping{
							ID:              d.Rng.Uint32(),
							LocalNameRecord: d.SelfRecord,
						}),
					})
				}
			}
		} else if (d.SelfRole == RoleValidatorNone || d.SelfRole == RoleValidatorPublisher) && !isNextValidator {
			if d.EnableClient {
				d.SelfRole = RoleFullNodeClient
				d.clearConnectionInfo()
				cmds = append(cmds, d.lookForUpstreamValidators()...)
			} else {
				d.SelfRole = RoleFullNodeNone
				d.clearConnectionInfo()
			}
		}
	}
	return cmds
}

// MonadNameRecordFromPeerEntry — Rust MonadNameRecord::try_from(&PeerEntry):
// rebuilds the record and verifies the self-signature under DomainNameRecord.
func MonadNameRecordFromPeerEntry(e glue.PeerEntry) (MonadNameRecord, error) {
	nr := NewNameRecordWithPorts(e.Addr, e.TCPPort, e.UDPPort, e.AuthPort,
		e.DirectUDPPort, e.EncryptedTCPPort, e.RecordSeqNum)
	if err := nr.validate(); err != nil {
		return MonadNameRecord{}, err
	}
	if !e.Signature.Verify(crypto.DomainNameRecord, rlp.Encode(nr), e.Pubkey.PubKey) {
		return MonadNameRecord{}, errors.New("peerdisc: peer entry signature invalid")
	}
	return MonadNameRecord{NameRecord: nr, Signature: e.Signature}, nil
}

// PeerEntry — Rust PeerEntry::try_from(&MonadNameRecord) (recover pubkey).
func (m MonadNameRecord) PeerEntry() (glue.PeerEntry, error) {
	id, err := m.RecoverPubKey()
	if err != nil {
		return glue.PeerEntry{}, err
	}
	udp, _ := m.NameRecord.UDPSocket()
	direct, _ := m.NameRecord.DirectUDPSocket()
	return glue.PeerEntry{
		Pubkey:           id,
		Addr:             m.NameRecord.IP,
		TCPPort:          m.NameRecord.TCPPort(),
		UDPPort:          udp.Port(),
		Signature:        m.Signature,
		RecordSeqNum:     m.NameRecord.Seq,
		AuthPort:         m.NameRecord.AuthUDPPort(),
		DirectUDPPort:    direct.Port(),
		EncryptedTCPPort: m.NameRecord.EncryptedTCPPort(),
	}, nil
}

// UpdatePeers — Rust update_peers (PeerEntry → validated MonadNameRecord).
func (d *PeerDiscovery) UpdatePeers(peers []glue.PeerEntry) []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	for _, e := range peers {
		nr, err := MonadNameRecordFromPeerEntry(e)
		if err != nil {
			continue
		}
		nodeID := e.Pubkey
		ok := true
		for _, s := range nr.AllUDPSockets() {
			if !d.checkSocketAvailability(nodeID, s) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if c, err := d.insertPeerToPending(nodeID, nr); err == nil {
			cmds = append(cmds, c...)
		}
	}
	return cmds
}

// UpdatePinnedNodes — Rust update_pinned_nodes.
func (d *PeerDiscovery) UpdatePinnedNodes(dedicated, prioritized []types.NodeId) []PeerDiscoveryCommand {
	d.PinnedFullNodes = map[types.NodeId]struct{}{}
	for _, id := range dedicated {
		d.PinnedFullNodes[id] = struct{}{}
	}
	d.PrioritizedFullNodes = map[types.NodeId]struct{}{}
	for _, id := range prioritized {
		d.PinnedFullNodes[id] = struct{}{}
		d.PrioritizedFullNodes[id] = struct{}{}
	}
	return nil
}

// UpdatePeerParticipation — Rust update_peer_participation.
func (d *PeerDiscovery) UpdatePeerParticipation(round types.Round, peers []types.NodeId) []PeerDiscoveryCommand {
	for _, p := range peers {
		if p == d.SelfID {
			continue
		}
		if info, ok := d.ParticipationInfo[p]; ok {
			if info.LastActive < round {
				info.LastActive = round
			}
		} else {
			d.ParticipationInfo[p] = &SecondaryRaptorcastInfo{
				Status:     SecondaryStatusNone,
				LastActive: round,
			}
		}
	}
	return nil
}

// --- address lookups (Rust get_*_by_id) ---

func (d *PeerDiscovery) GetPendingUDPAddrByID(id types.NodeId) (netip.AddrPort, bool) {
	info, ok := d.PendingQueue[id]
	if !ok {
		return netip.AddrPort{}, false
	}
	return info.NameRecord.UDPSocket()
}

func (d *PeerDiscovery) GetUDPAddrByID(id types.NodeId) (netip.AddrPort, bool) {
	nr, ok := d.RoutingInfo[id]
	if !ok {
		return netip.AddrPort{}, false
	}
	return nr.UDPSocket()
}

func (d *PeerDiscovery) GetTCPAddrByID(id types.NodeId) (netip.AddrPort, bool) {
	nr, ok := d.RoutingInfo[id]
	if !ok {
		return netip.AddrPort{}, false
	}
	return nr.TCPSocket(), true
}

func (d *PeerDiscovery) GetIPByID(id types.NodeId) (netip.Addr, bool) {
	nr, ok := d.RoutingInfo[id]
	if !ok {
		return netip.Addr{}, false
	}
	return nr.NameRecord.IP, true
}

// GetKnownAuthUDPAddrs — Rust get_known_auth_udp_addrs.
func (d *PeerDiscovery) GetKnownAuthUDPAddrs() map[types.NodeId]netip.AddrPort {
	out := map[types.NodeId]netip.AddrPort{}
	for id, nr := range d.RoutingInfo {
		out[id] = nr.AuthUDPSocket()
	}
	return out
}

// GetSecondaryFullNodes — Rust get_secondary_fullnodes (Connected status).
func (d *PeerDiscovery) GetSecondaryFullNodes() []types.NodeId {
	var out []types.NodeId
	for id := range d.RoutingInfo {
		if info, ok := d.ParticipationInfo[id]; ok && info.Status == SecondaryStatusConnected {
			out = append(out, id)
		}
	}
	sortIDs(out)
	return out
}

func (d *PeerDiscovery) GetNameRecords() map[types.NodeId]MonadNameRecord {
	out := make(map[types.NodeId]MonadNameRecord, len(d.RoutingInfo))
	for id, nr := range d.RoutingInfo {
		out[id] = nr
	}
	return out
}

func (d *PeerDiscovery) GetNameRecord(id types.NodeId) (MonadNameRecord, bool) {
	nr, ok := d.RoutingInfo[id]
	return nr, ok
}

// --- peers file (RLP-encoded records; upstream uses TOML — same function) ---

func (d *PeerDiscovery) writePeersToFile() {
	if d.PersistedPeersPath == "" {
		return
	}
	var ids []types.NodeId
	for id := range d.RoutingInfo {
		ids = append(ids, id)
	}
	for id := range d.PendingQueue {
		ids = append(ids, id)
	}
	sortIDs(ids)
	encoded := rlp.AppendList(nil, func(b []byte) []byte {
		for _, id := range ids {
			var nr MonadNameRecord
			if r, ok := d.RoutingInfo[id]; ok {
				nr = r
			} else {
				nr = d.PendingQueue[id].NameRecord
			}
			b = nr.EncodeRLP(b)
		}
		return b
	})
	_ = os.WriteFile(d.PersistedPeersPath, encoded, 0o600)
}

func (d *PeerDiscovery) readPeersFromFile() []PeerDiscoveryCommand {
	var cmds []PeerDiscoveryCommand
	if d.PersistedPeersPath == "" {
		return nil
	}
	data, err := os.ReadFile(d.PersistedPeersPath)
	if err != nil {
		return nil
	}
	s := rlp.NewStream(data)
	l, err := s.List()
	if err != nil {
		return nil
	}
	for l.Remaining() > 0 {
		var nr MonadNameRecord
		if err := nr.DecodeRLP(l); err != nil {
			break
		}
		nodeID, err := nr.RecoverPubKey()
		if err != nil {
			continue
		}
		if c, err := d.insertPeerToPending(nodeID, nr); err == nil {
			cmds = append(cmds, c...)
		}
	}
	return cmds
}

// Update dispatches an event to the appropriate handler (driver.rs update()).
func (d *PeerDiscovery) Update(ev PeerDiscoveryEvent) []PeerDiscoveryCommand {
	switch ev.Kind {
	case evSendPing:
		return d.SendPing(ev.To, ev.NameRecord, ev.Ping)
	case evPingRequest:
		return d.HandlePing(ev.From, ev.Ping)
	case evPongResponse:
		return d.HandlePong(ev.From, ev.Pong)
	case evPingTimeout:
		return d.HandlePingTimeout(ev.To, ev.PingID)
	case evSendPeerLookup:
		return d.SendPeerLookupRequest(ev.To, ev.Target, ev.OpenDiscovery)
	case evPeerLookupRequest:
		return d.HandlePeerLookupRequest(ev.From, ev.LookupRequest)
	case evPeerLookupResponse:
		return d.HandlePeerLookupResponse(ev.From, ev.LookupResponse)
	case evPeerLookupTimeout:
		return d.HandlePeerLookupTimeout(ev.To, ev.Target, ev.LookupID)
	case evSendFullNodeRaptorcastRequest:
		return d.SendFullNodeRaptorcastRequest(ev.To)
	case evFullNodeRaptorcastRequest:
		return d.HandleFullNodeRaptorcastRequest(ev.From)
	case evFullNodeRaptorcastResponse:
		return d.HandleFullNodeRaptorcastResponse(ev.From)
	case evUpdateCurrentRound:
		return d.UpdateCurrentRound(ev.Round, ev.Epoch)
	case evUpdateValidatorSet:
		return d.UpdateValidatorSet(ev.Epoch, ev.Validators)
	case evUpdatePeers:
		return d.UpdatePeers(ev.Peers)
	case evUpdatePinnedNodes:
		return d.UpdatePinnedNodes(ev.DedicatedFullNodes, ev.PrioritizedFullNodes)
	case evUpdateConfirmGroup:
		return d.UpdatePeerParticipation(ev.EndRound, ev.ConfirmGroupPeers)
	case evRefresh:
		return d.refresh()
	}
	return nil
}

func sortIDs(ids []types.NodeId) {
	sort.Slice(ids, func(i, j int) bool { return ids[i].Cmp(ids[j]) < 0 })
}

func keysOf(m map[types.NodeId]MonadNameRecord) []types.NodeId {
	out := make([]types.NodeId, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sortIDs(out)
	return out
}

func maxRound(a, b types.Round) types.Round {
	if a > b {
		return a
	}
	return b
}
