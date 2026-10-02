package raptorcast

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

// Raptorcast is the node-facing transport driver — the Go analogue of
// upstream's RaptorCast executor (lib.rs handle_publish + handle_message).
// It satisfies node.Transport: Send dispatches RouterTargets into
// raptorcast/broadcast/point-to-point UDP writes, and inbound datagrams are
// decoded and delivered to the registered handler as (author, app message).

// UDPSink abstracts the dataplane UDP writer (Rust DualUdpPacketSender sink).
type UDPSink interface {
	WriteUnicastWithPriority(msg UDPSendBatch, priority int)
}

// UDPSendBatch is one or more payloads sharing a stride.
type UDPSendBatch struct {
	Items  []UDPSendItem
	Stride uint16
}

type UDPSendItem struct {
	Recipient types.NodeId   // intended receiver (chunk/broadcast target)
	Dst       netip.AddrPort // resolved authenticated UDP addr (sink may re-resolve)
	Payload   []byte
}

// PeerAddrSource resolves a peer's UDP address (authenticated socket
// preferred — mirrors upstream write_to_name_record).
type PeerAddrSource interface {
	LookupUDPAddr(id types.NodeId) (netip.AddrPort, bool)
}

// UDP send priorities — values match dataplane.UdpPriority so transports can
// forward them unchanged (upstream UdpPriority: High drains first).
const (
	UdpPriorityHigh    = 0
	UdpPriorityRegular = 1
)

// Options — the RaptorCastConfig knobs the primary path uses.
type Options struct {
	Redundancy      Redundancy
	SegmentSize     int
	MerkleTreeDepth int
	MaxAgeMs        uint64
	SigRatePerSec   uint32
}

func DefaultOptions() Options {
	return Options{
		Redundancy:      DefaultPrimaryRedundancy,
		SegmentSize:     DefaultSegmentLength,
		MerkleTreeDepth: DefaultMerkleTreeDepth,
		MaxAgeMs:        10_000,
		SigRatePerSec:   signatureVerificationRateDefault,
	}
}

// Raptorcast transport driver.
type Raptorcast struct {
	selfID types.NodeId
	key    *crypto.SecpKeyPair
	opts   Options

	mu          sync.Mutex
	valSets     map[types.Epoch]*validator.ValidatorSet
	addrs       PeerAddrSource
	sink        UDPSink
	handler     func(from types.NodeId, payload []byte)
	pdHandler   func(author types.NodeId, srcAddr netip.AddrPort, payload []byte)
	state       *udpState
	published   *publishedRounds
	curEpoch    types.Epoch
	hasCurEpoch bool
}

func New(selfID types.NodeId, key *crypto.SecpKeyPair, addrs PeerAddrSource, sink UDPSink, opts Options) *Raptorcast {
	return &Raptorcast{
		selfID:    selfID,
		key:       key,
		opts:      opts,
		valSets:   make(map[types.Epoch]*validator.ValidatorSet),
		addrs:     addrs,
		sink:      sink,
		state:     newUDPState(selfID, opts.MaxAgeMs, opts.SigRatePerSec),
		published: newPublishedRounds(),
	}
}

func (r *Raptorcast) SetHandler(h func(from types.NodeId, payload []byte)) {
	r.mu.Lock()
	r.handler = h
	r.mu.Unlock()
}

// SetPeerDiscHandler — decoded type-2 (PeerDiscoveryMessage) envelopes are
// routed here instead of the app handler (Rust: pd_driver.update on rx).
// srcAddr is the datagram's source socket for PeerSource.
func (r *Raptorcast) SetPeerDiscHandler(h func(author types.NodeId, srcAddr netip.AddrPort, payload []byte)) {
	r.mu.Lock()
	r.pdHandler = h
	r.mu.Unlock()
}

// UpdateCurrentRound — Rust RouterCommand::UpdateCurrentRound: tracks the
// current epoch for point-to-point builds and prunes expired epoch valsets.
func (r *Raptorcast) UpdateCurrentRound(epoch types.Epoch, _ types.Round) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if epoch > r.curEpoch {
		r.curEpoch = epoch
		r.hasCurEpoch = true
		for e := range r.valSets { // upstream retains epoch >= current-1
			if e+1 < epoch {
				delete(r.valSets, e)
			}
		}
	}
}

// AddEpochValidatorSet — RouterCommand::AddEpochValidatorSet.
func (r *Raptorcast) AddEpochValidatorSet(epoch types.Epoch, vs *validator.ValidatorSet) {
	r.mu.Lock()
	r.valSets[epoch] = vs
	r.mu.Unlock()
}

// RemoveEpochValidatorSet — RouterCommand::RemoveEpochValidatorSet.
func (r *Raptorcast) RemoveEpochValidatorSet(epoch types.Epoch) {
	r.mu.Lock()
	delete(r.valSets, epoch)
	r.mu.Unlock()
}

// Send — RouterCommand::Publish{target, message} (handle_publish).
// appMsg is the serialized inner MonadMessage bytes.
func (r *Raptorcast) Send(target types.RouterTarget, appMsg []byte) error {
	return r.sendWithPriority(target, appMsg, 0)
}

func (r *Raptorcast) SendWithPriority(target types.RouterTarget, appMsg []byte, priority int) error {
	return r.sendWithPriority(target, appMsg, priority)
}

func (r *Raptorcast) sendWithPriority(target types.RouterTarget, appMsg []byte, priority int) error {
	envelope, err := encodeAppMessageEnvelope(appMsg)
	if err != nil {
		return err
	}

	switch target.Kind {
	case types.RouterBroadcast, types.RouterRaptorcast:
		r.mu.Lock()
		vs := r.valSets[target.Epoch]
		if vs == nil {
			r.mu.Unlock()
			return fmt.Errorf("%w: epoch %d", ErrGroupNotFound, target.Epoch)
		}
		if !vs.IsMember(r.selfID) {
			r.mu.Unlock()
			return ErrInvalidAuthor
		}
		if target.Kind == types.RouterRaptorcast {
			if !r.published.tryClaim(target.Round) {
				r.mu.Unlock()
				return fmt.Errorf("duplicate primary raptorcast publish for round %d", target.Round)
			}
		}
		r.mu.Unlock()

		r.deliverToSelf(appMsg)

		bt := &buildTarget{
			epoch: target.Epoch,
			group: &validatorGroupView{
				epoch:   target.Epoch,
				author:  r.selfID,
				members: vs.Members(),
				stakeOf: func(id types.NodeId) types.Stake {
					s, _ := vs.StakeOf(id)
					return s
				},
			},
		}
		if target.Kind == types.RouterRaptorcast {
			bt.mode = BroadcastPrimary
		} else {
			bt.mode = BroadcastUnspecified
		}
		return r.buildAndSend(envelope, bt, priority)

	case types.RouterPointToPoint, types.RouterDirectPointToPoint:
		if target.To == r.selfID {
			r.deliverToSelf(appMsg)
			return nil
		}
		bt := &buildTarget{
			mode:      BroadcastUnspecified,
			epoch:     r.currentEpoch(),
			recipient: target.To,
		}
		return r.buildAndSend(envelope, bt, priority)

	default:
		return errors.New("unsupported router target kind")
	}
}

// currentEpoch — the tracked round epoch (upstream self.current_epoch),
// falling back to the newest installed valset when no UpdateCurrentRound has
// arrived yet (single-node/devnet bring-up).
func (r *Raptorcast) currentEpoch() types.Epoch {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hasCurEpoch {
		return r.curEpoch
	}
	var epoch types.Epoch
	for e := range r.valSets {
		if e > epoch {
			epoch = e
		}
	}
	return epoch
}

// SendPeerDiscovery — Rust send_peer_disc_msg: wrap a serialized
// PeerDiscoveryMessage in a type-2 envelope and unicast it to the target
// through the regular p2p chunk path.
func (r *Raptorcast) SendPeerDiscovery(to types.NodeId, msgRLP []byte, priority int) error {
	env, err := encodePeerDiscoveryEnvelope(msgRLP)
	if err != nil {
		return err
	}
	bt := &buildTarget{mode: BroadcastUnspecified, epoch: r.currentEpoch(), recipient: to}
	return r.buildAndSend(env, bt, priority)
}

// SendToNode — RouterCommand::PublishToFullNodes inner loop: app envelope
// unicasted to one node under the command's epoch.
func (r *Raptorcast) SendToNode(epoch types.Epoch, to types.NodeId, appMsg []byte, priority int) error {
	env, err := encodeAppMessageEnvelope(appMsg)
	if err != nil {
		return err
	}
	bt := &buildTarget{mode: BroadcastUnspecified, epoch: epoch, recipient: to}
	return r.buildAndSend(env, bt, priority)
}

func (r *Raptorcast) deliverToSelf(appMsg []byte) {
	r.mu.Lock()
	h := r.handler
	r.mu.Unlock()
	if h != nil {
		h(r.selfID, appMsg)
	}
}

// buildAndSend builds chunks and pushes them to the UDP sink.
func (r *Raptorcast) buildAndSend(envelope []byte, bt *buildTarget, priority int) error {
	layout := newPacketLayoutV0(r.opts.SegmentSize, r.opts.MerkleTreeDepth)
	if r.opts.SegmentSize < calcSegmentLen(minChunkLength, r.opts.MerkleTreeDepth) {
		return ErrSegmentTooSmall
	}
	if r.opts.SegmentSize > maxSegmentLength {
		return ErrSegmentTooLarge
	}
	if r.opts.Redundancy > MaxRedundancy {
		return ErrRedundancyTooHigh
	}

	// collect chunks per destination — upstream's sink receives
	// UdpMessage{recipient, payload} and resolves the name record inside; we
	// keep the resolved auth addr on the item for simple sinks.
	perDst := make(map[netip.AddrPort][]UDPSendItem)
	order := make([]netip.AddrPort, 0)
	err := buildInto(r.key, layout, r.opts.Redundancy, unixTsMsNow(), envelope, bt, func(m udpMessage) {
		dst, ok := r.addrs.LookupUDPAddr(m.recipient)
		if !ok {
			return // unknown name record — drop (upstream logs and skips)
		}
		if _, seen := perDst[dst]; !seen {
			order = append(order, dst)
		}
		perDst[dst] = append(perDst[dst], UDPSendItem{Recipient: m.recipient, Dst: dst, Payload: m.payload})
	})
	if err != nil {
		return err
	}
	for _, dst := range order {
		r.sink.WriteUnicastWithPriority(UDPSendBatch{Items: perDst[dst], Stride: uint16(r.opts.SegmentSize)}, priority)
	}
	return nil
}

// HandleDatagram processes an inbound UDP datagram (the dataplane read path
// calls this for each RecvUdpMsg).
func (r *Raptorcast) HandleDatagram(srcAddr netip.AddrPort, sender *types.NodeId, payload []byte, stride uint16) {
	r.mu.Lock()
	valSets := make(map[types.Epoch]*validator.ValidatorSet, len(r.valSets))
	for e, vs := range r.valSets {
		valSets[e] = vs
	}
	r.mu.Unlock()

	m := recvUDPMessage{
		srcAddr: srcAddr.String(),
		sender:  sender,
		stride:  int(stride),
		payload: payload,
	}
	decoded := r.state.handleMessage(valSets, m, func(req rebroadcastRequest) {
		r.rebroadcast(req)
	})
	for _, dm := range decoded {
		env, err := decodeRouterEnvelope(dm.Payload)
		if err != nil {
			continue
		}
		switch env.kind {
		case messageTypeApp:
			r.mu.Lock()
			h := r.handler
			r.mu.Unlock()
			if h != nil {
				h(dm.Author, env.payload)
			}
		case messageTypePeerDisc:
			r.mu.Lock()
			h := r.pdHandler
			r.mu.Unlock()
			if h != nil {
				h(dm.Author, srcAddr, env.payload)
			}
		default:
			// type-3 FullNodesGroup messages are secondary/full-node scope
			// (Track B B5) — dropped on the primary path.
		}
	}
}

// rebroadcast forwards a received chunk's wire bytes to its targets — Rust
// rebroadcast_packet: one write_to_name_record per target at High priority.
func (r *Raptorcast) rebroadcast(req rebroadcastRequest) {
	batch := UDPSendBatch{Stride: req.stride}
	for _, id := range req.targets {
		addr, ok := r.addrs.LookupUDPAddr(id)
		if !ok {
			continue
		}
		batch.Items = append(batch.Items, UDPSendItem{Recipient: id, Dst: addr, Payload: req.payload})
	}
	if len(batch.Items) == 0 {
		return
	}
	r.sink.WriteUnicastWithPriority(batch, UdpPriorityHigh)
}

// publishedRounds — Rust PublishedRounds: bounded set of claimed primary
// rounds; the oldest evicted round becomes claimable again.
const publishedRoundsCacheSize = 100

type publishedRounds struct {
	set      map[types.Round]struct{}
	minRound types.Round // smallest round present
}

func newPublishedRounds() *publishedRounds {
	return &publishedRounds{set: make(map[types.Round]struct{})}
}

func (p *publishedRounds) tryClaim(r types.Round) bool {
	if _, dup := p.set[r]; dup {
		return false
	}
	if len(p.set) == 0 || r < p.minRound {
		p.minRound = r
	}
	p.set[r] = struct{}{}
	for len(p.set) > publishedRoundsCacheSize {
		delete(p.set, p.minRound)
		// recompute min
		var min types.Round
		first := true
		for rr := range p.set {
			if first || rr < min {
				min = rr
				first = false
			}
		}
		p.minRound = min
	}
	return true
}

var _ = glue.PeerEntry{}
