package swarm

import (
	"math/rand/v2"
	"sort"
	"time"

	"github.com/abhijitkrm/monadbft-go/types"
)

// Port of monad-transformer: LinkMessage/ID, the Transformer + Pipeline
// interfaces, and the standard transformer set (Latency, XorLatency,
// RandLatency, Partition, Drop, Periodic, Replay). Transport is the swarm's
// concrete []byte (BytesSwarm).

// UniqueID — Rust UNIQUE_ID: the identifier of a non-twin node id.
const UniqueID = 0

// ID — Rust ID(usize, NodeId): wraps a NodeId with a uniqueness identifier so
// twin tests can run duplicate identities.
type ID struct {
	Identifier int
	PeerID     types.NodeId
}

func NewID(peerID types.NodeId) ID { return ID{Identifier: UniqueID, PeerID: peerID} }

// AsNonUnique — Rust as_non_unique.
func (i ID) AsNonUnique(identifier int) ID {
	if identifier == UniqueID {
		panic("identifier must be non-unique")
	}
	i.Identifier = identifier
	return i
}

func (i ID) IsUnique() bool { return i.Identifier == UniqueID }

// LinkMessage — Rust LinkMessage: a transport message in flight between peers.
type LinkMessage struct {
	From    ID
	To      ID
	Message []byte

	// FromTick — absolute send time.
	FromTick time.Duration
	Nonce    int
}

// StreamMessage — (delay, message) pair emitted by a transformer.
type StreamMessage struct {
	Delay   time.Duration
	Message LinkMessage
}

// TransformerStream — Rust TransformerStream: Continue (feeds the next layer)
// or Complete (emitted as-is, no further processing).
type TransformerStream struct {
	Complete bool
	Msgs     []StreamMessage
}

func Continue(msgs ...StreamMessage) TransformerStream {
	return TransformerStream{Msgs: msgs}
}
func Complete(msgs ...StreamMessage) TransformerStream {
	return TransformerStream{Complete: true, Msgs: msgs}
}

// Transformer — Rust Transformer<Bytes>.
type Transformer interface {
	// Transform — returns the delay-tagged messages to Continue/Complete with.
	Transform(message LinkMessage) TransformerStream
	// MinExternalDelay — nil if this layer imposes no lower bound.
	MinExternalDelay() *time.Duration
	// IsOutboundBlocked — nil tri-state: unknown.
	IsOutboundBlocked(tick time.Duration, node types.NodeId) *bool
}

// Pipeline — Rust Pipeline<Bytes>: an ordered list of transformers.
type Pipeline interface {
	Process(message LinkMessage) []StreamMessage
	Len() int
	MinExternalDelay() time.Duration
	IsOutboundBlocked(tick time.Duration, node types.NodeId) bool
}

// TransformerPipeline — Rust `impl Pipeline for Vec<Transformer>`.
type TransformerPipeline []Transformer

var _ Pipeline = TransformerPipeline(nil)

func (p TransformerPipeline) Process(message LinkMessage) []StreamMessage {
	var complete []StreamMessage
	remain := []StreamMessage{{Delay: 0, Message: message}}
	for _, layer := range p {
		var next []StreamMessage
		for _, sm := range remain {
			out := layer.Transform(sm.Message)
			for _, m := range out.Msgs {
				m.Delay += sm.Delay
			}
			if out.Complete {
				complete = append(complete, out.Msgs...)
			} else {
				next = append(next, out.Msgs...)
			}
		}
		remain = next
	}
	return append(complete, remain...)
}

func (p TransformerPipeline) Len() int { return len(p) }

// MinExternalDelay — Rust: sum of min delays until the first unbounded layer;
// must be > 0 (batch stepping depends on it).
func (p TransformerPipeline) MinExternalDelay() time.Duration {
	var delay time.Duration
	for _, t := range p {
		d := t.MinExternalDelay()
		if d == nil {
			break
		}
		delay += *d
	}
	if delay <= 0 {
		panic("min_external_delay must be > 0")
	}
	return delay
}

func (p TransformerPipeline) IsOutboundBlocked(tick time.Duration, node types.NodeId) bool {
	for _, t := range p {
		if b := t.IsOutboundBlocked(tick, node); b != nil {
			return *b
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Transformers
// ---------------------------------------------------------------------------

type transformerBase struct{}

func (transformerBase) MinExternalDelay() *time.Duration                    { return nil }
func (transformerBase) IsOutboundBlocked(time.Duration, types.NodeId) *bool { return nil }

// LatencyTransformer — constant latency.
type LatencyTransformer struct {
	transformerBase
	Latency time.Duration
}

func NewLatencyTransformer(d time.Duration) *LatencyTransformer {
	return &LatencyTransformer{Latency: d}
}

func (t *LatencyTransformer) Transform(m LinkMessage) TransformerStream {
	return Continue(StreamMessage{Delay: t.Latency, Message: m})
}

func (t *LatencyTransformer) MinExternalDelay() *time.Duration { return &t.Latency }

// XorLatencyTransformer — latency = max * (xor(from,to) pubkey bytes / 255).
type XorLatencyTransformer struct {
	transformerBase
	MaxLatency time.Duration
}

func NewXorLatencyTransformer(max time.Duration) *XorLatencyTransformer {
	return &XorLatencyTransformer{MaxLatency: max}
}

func (t *XorLatencyTransformer) Transform(m LinkMessage) TransformerStream {
	var ck byte
	for _, b := range m.From.PeerID.PubKey.Bytes() {
		ck ^= b
	}
	for _, b := range m.To.PeerID.PubKey.Bytes() {
		ck ^= b
	}
	d := time.Duration(float64(t.MaxLatency) * float64(ck) / float64(^uint8(0)))
	return Continue(StreamMessage{Delay: d, Message: m})
}

// RandLatencyTransformer — uniform latency in [1ms, max) per message.
type RandLatencyTransformer struct {
	transformerBase
	gen        *rand.ChaCha8
	maxLatency time.Duration
}

func NewRandLatencyTransformer(seed [32]byte, max time.Duration) *RandLatencyTransformer {
	return &RandLatencyTransformer{gen: rand.NewChaCha8(seed), maxLatency: max}
}

func (t *RandLatencyTransformer) nextLatency() time.Duration {
	maxMs := t.maxLatency.Milliseconds()
	var s uint64
	if maxMs > 1 {
		s = t.gen.Uint64()%uint64(maxMs-1) + 1 // gen_range(1..max)
	} else {
		s = 1
	}
	return time.Duration(s) * time.Millisecond
}

func (t *RandLatencyTransformer) Transform(m LinkMessage) TransformerStream {
	return Continue(StreamMessage{Delay: t.nextLatency(), Message: m})
}

// PartitionTransformer — messages not involving a partitioned peer are
// delivered immediately (Complete, zero delay); messages to/from a partitioned
// peer continue down the pipeline (typically into Drop).
type PartitionTransformer struct {
	transformerBase
	peers map[ID]struct{}
}

func NewPartitionTransformer(peers ...ID) *PartitionTransformer {
	s := make(map[ID]struct{}, len(peers))
	for _, p := range peers {
		s[p] = struct{}{}
	}
	return &PartitionTransformer{peers: s}
}

func (t *PartitionTransformer) Transform(m LinkMessage) TransformerStream {
	_, fromOk := t.peers[m.From]
	_, toOk := t.peers[m.To]
	if fromOk || toOk {
		return Continue(StreamMessage{Delay: 0, Message: m})
	}
	return Complete(StreamMessage{Delay: 0, Message: m})
}

// IsOutboundBlocked — Rust: Some(false) when `node` is NOT partitioned.
func (t *PartitionTransformer) IsOutboundBlocked(_ time.Duration, node types.NodeId) *bool {
	id := NewID(node)
	if _, ok := t.peers[id]; ok {
		return nil
	}
	b := false
	return &b
}

// DropTransformer — drops all messages (optionally only those from a peer).
type DropTransformer struct {
	dropOnlyFrom *types.NodeId
}

func NewDropTransformer() *DropTransformer { return &DropTransformer{} }

// DropOnlyFrom — Rust drop_only_from.
func (t *DropTransformer) DropOnlyFrom(from types.NodeId) *DropTransformer {
	t.dropOnlyFrom = &from
	return t
}

func (t *DropTransformer) Transform(m LinkMessage) TransformerStream {
	if t.dropOnlyFrom != nil {
		if *t.dropOnlyFrom == m.From.PeerID {
			return Complete()
		}
		return Continue(StreamMessage{Message: m})
	}
	return Complete()
}

func (t *DropTransformer) MinExternalDelay() *time.Duration { return nil }

func (t *DropTransformer) IsOutboundBlocked(_ time.Duration, node types.NodeId) *bool {
	if t.dropOnlyFrom != nil && *t.dropOnlyFrom == node {
		b := true
		return &b
	}
	return nil
}

// PeriodicTransformer — only passes messages sent in [start, end).
type PeriodicTransformer struct {
	transformerBase
	Start time.Duration
	End   time.Duration
}

func NewPeriodicTransformer(start, end time.Duration) *PeriodicTransformer {
	if start > end {
		panic("start must be <= end")
	}
	return &PeriodicTransformer{Start: start, End: end}
}

func (t *PeriodicTransformer) Transform(m LinkMessage) TransformerStream {
	if m.FromTick < t.Start || m.FromTick >= t.End {
		return Complete(StreamMessage{Message: m})
	}
	return Continue(StreamMessage{Message: m})
}

func (t *PeriodicTransformer) IsOutboundBlocked(tick time.Duration, _ types.NodeId) *bool {
	if tick < t.Start || tick >= t.End {
		b := false
		return &b
	}
	return nil
}

// ReplayOrder — Rust TransformerReplayOrder.
type ReplayOrder uint8

const (
	ReplayForward ReplayOrder = iota
	ReplayReverse
	ReplayRandom
)

// ReplayTransformer — buffers messages until `end`, then replays them all.
type ReplayTransformer struct {
	filtered []LinkMessage
	end      time.Duration
	order    ReplayOrder
	seed     [32]byte
}

func NewReplayTransformer(end time.Duration, order ReplayOrder, seed [32]byte) *ReplayTransformer {
	return &ReplayTransformer{end: end, order: order, seed: seed}
}

func (t *ReplayTransformer) Transform(m LinkMessage) TransformerStream {
	if m.FromTick >= t.end {
		if len(t.filtered) == 0 {
			return Continue(StreamMessage{Message: m})
		}
		t.filtered = append(t.filtered, m)
		msgs := t.filtered
		t.filtered = nil
		switch t.order {
		case ReplayReverse:
			for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
				msgs[i], msgs[j] = msgs[j], msgs[i]
			}
		case ReplayRandom:
			gen := rand.NewChaCha8(t.seed)
			for i := len(msgs) - 1; i > 0; i-- {
				j := int(gen.Uint64() % uint64(i+1))
				msgs[i], msgs[j] = msgs[j], msgs[i]
			}
		}
		out := make([]StreamMessage, len(msgs))
		for i, mm := range msgs {
			out[i] = StreamMessage{Message: mm}
		}
		return Continue(out...)
	}
	t.filtered = append(t.filtered, m)
	return Continue()
}

func (t *ReplayTransformer) MinExternalDelay() *time.Duration { return nil }
func (t *ReplayTransformer) IsOutboundBlocked(time.Duration, types.NodeId) *bool {
	return nil
}

// SortIDs — deterministic ordering helper for ID-keyed maps.
func SortIDs(ids []ID) {
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].Identifier != ids[j].Identifier {
			return ids[i].Identifier < ids[j].Identifier
		}
		return ids[i].PeerID.Cmp(ids[j].PeerID) < 0
	})
}

// IDCmp — total order on ID: (identifier, node_id).
func IDCmp(a, b ID) int {
	if a.Identifier != b.Identifier {
		if a.Identifier < b.Identifier {
			return -1
		}
		return 1
	}
	return a.PeerID.Cmp(b.PeerID)
}
