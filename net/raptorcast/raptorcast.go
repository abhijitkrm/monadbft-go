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

// UDPSink abstracts the dataplane UDP writer.
type UDPSink interface {
	WriteUnicastWithPriority(msg UDPSendBatch, priority int)
	WriteBroadcastWithPriority(targets []netip.AddrPort, payload []byte, stride uint16, priority int)
}

// UDPSendBatch is one or more payloads sharing a stride.
type UDPSendBatch struct {
	Items  []UDPSendItem
	Stride uint16
}

type UDPSendItem struct {
	Dst     netip.AddrPort
	Payload []byte
}

// PeerAddrSource resolves a peer's UDP address (authenticated socket
// preferred — mirrors upstream write_to_name_record).
type PeerAddrSource interface {
	LookupUDPAddr(id types.NodeId) (netip.AddrPort, bool)
}

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

	mu        sync.Mutex
	valSets   map[types.Epoch]*validator.ValidatorSet
	addrs     PeerAddrSource
	sink      UDPSink
	handler   func(from types.NodeId, payload []byte)
	state     *udpState
	published *publishedRounds
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
		r.mu.Lock()
		// P2P group id: current epoch — upstream uses current_epoch.
		var epoch types.Epoch
		for e := range r.valSets {
			if e > epoch {
				epoch = e
			}
		}
		r.mu.Unlock()
		bt := &buildTarget{
			mode:      BroadcastUnspecified,
			epoch:     epoch,
			recipient: target.To,
		}
		return r.buildAndSend(envelope, bt, priority)

	default:
		return errors.New("unsupported router target kind")
	}
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

	// collect chunks per destination
	perDst := make(map[netip.AddrPort][][]byte)
	order := make([]netip.AddrPort, 0)
	err := buildInto(r.key, layout, r.opts.Redundancy, unixTsMsNow(), envelope, bt, func(m udpMessage) {
		dst, ok := r.addrs.LookupUDPAddr(m.recipient)
		if !ok {
			return // unknown name record — drop (upstream logs and skips)
		}
		if _, seen := perDst[dst]; !seen {
			order = append(order, dst)
		}
		perDst[dst] = append(perDst[dst], m.payload)
	})
	if err != nil {
		return err
	}
	for _, dst := range order {
		payloads := perDst[dst]
		items := make([]UDPSendItem, len(payloads))
		for i, p := range payloads {
			items[i] = UDPSendItem{Dst: dst, Payload: p}
		}
		r.sink.WriteUnicastWithPriority(UDPSendBatch{Items: items, Stride: uint16(r.opts.SegmentSize)}, priority)
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
		r.mu.Lock()
		h := r.handler
		r.mu.Unlock()
		if h != nil {
			h(dm.Author, env.payload)
		}
	}
}

// rebroadcast forwards a received chunk's wire bytes to its targets.
func (r *Raptorcast) rebroadcast(req rebroadcastRequest) {
	var targets []netip.AddrPort
	for _, id := range req.targets {
		if addr, ok := r.addrs.LookupUDPAddr(id); ok {
			targets = append(targets, addr)
		}
	}
	if len(targets) == 0 {
		return
	}
	r.sink.WriteBroadcastWithPriority(targets, req.payload, req.stride, 0)
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
