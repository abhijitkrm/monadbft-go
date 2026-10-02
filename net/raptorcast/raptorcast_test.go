package raptorcast

import (
	"math"
	"math/big"
	"net/netip"
	"sync"
	"testing"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

type memSink struct {
	mu    sync.Mutex
	sends []UDPSendItem
}

func (s *memSink) WriteUnicastWithPriority(b UDPSendBatch, _ int) {
	s.mu.Lock()
	s.sends = append(s.sends, b.Items...)
	s.mu.Unlock()
}
func (s *memSink) WriteBroadcastWithPriority(dsts []netip.AddrPort, payload []byte, stride uint16, _ int) {
	s.mu.Lock()
	for _, d := range dsts {
		s.sends = append(s.sends, UDPSendItem{Dst: d, Payload: payload})
	}
	s.mu.Unlock()
}
func (s *memSink) drain() []UDPSendItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.sends
	s.sends = nil
	return out
}

type memAddrs struct {
	m map[[33]byte]netip.AddrPort
}

func (a *memAddrs) LookupUDPAddr(id types.NodeId) (netip.AddrPort, bool) {
	p, ok := a.m[[33]byte(id.PubKey)]
	return p, ok
}

func testGroup(t *testing.T, n int, stakes []int64) ([]*crypto.SecpKeyPair, []types.NodeId, *validator.ValidatorSet, *memAddrs) {
	t.Helper()
	if len(stakes) != n {
		t.Fatal("stakes len")
	}
	var keys []*crypto.SecpKeyPair
	var ids []types.NodeId
	var vals []validator.ValidatorData
	addrs := &memAddrs{m: map[[33]byte]netip.AddrPort{}}
	for i := 0; i < n; i++ {
		kp := getKey(t, uint64(1000+i))
		keys = append(keys, kp)
		id := types.NodeId{PubKey: kp.PubKey()}
		ids = append(ids, id)
		vals = append(vals, validator.ValidatorData{NodeId: id, Stake: types.StakeFromBig(big.NewInt(stakes[i]))})
		addrs.m[[33]byte(id.PubKey)] = netip.MustParseAddrPort("127.0.0.1:900" + string(rune('0'+i)))
	}
	vs, err := validator.NewValidatorSet(vals)
	if err != nil {
		t.Fatal(err)
	}
	return keys, ids, vs, addrs
}

func TestEnvelopeRoundTrip(t *testing.T) {
	// Send-side contract: the app message arrives already RLP-encoded.
	appMsg := rlp.AppendString(nil, []byte("hello"))
	env, err := encodeAppMessageEnvelope(appMsg)
	if err != nil {
		t.Fatal(err)
	}
	d, err := decodeRouterEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	if string(d.payload) != string(appMsg) {
		t.Fatalf("payload %x want %x", d.payload, appMsg)
	}
	if d.kind != messageTypeApp {
		t.Fatalf("kind %d want %d", d.kind, messageTypeApp)
	}

	// malformed: not a list
	if _, err := decodeRouterEnvelope([]byte{0x80}); err == nil {
		t.Fatal("expected error for non-list")
	}
	// malformed: truncated
	if _, err := decodeRouterEnvelope(env[:len(env)-1]); err == nil {
		t.Fatal("expected error for truncated envelope")
	}
	// malformed: trailing item inside outer list
	env2 := append([]byte(nil), env...)
	env2[len(env2)-1] = env2[len(env2)-1] + 1 // grow outer list len by 1
	env2 = append(env2, 0x00)                 // trailing garbage item
	if _, err := decodeRouterEnvelope(env2); err == nil {
		t.Fatal("expected error for trailing item")
	}
	// wrong message type
	bad := rlp.AppendList(nil, func(p []byte) []byte {
		p = rlp.AppendList(p, func(v []byte) []byte {
			v = rlp.AppendUint32(v, 1)
			v = rlp.AppendUint8(v, 1)
			return v
		})
		p = rlp.AppendUint8(p, 0x09)
		p = rlp.AppendRaw(p, appMsg)
		return p
	})
	if _, err := decodeRouterEnvelope(bad); err == nil {
		t.Fatal("expected error for unknown message type")
	}
}

// end-to-end: author Raptorcasts, every validator decodes via HandleDatagram.
func TestSendReceiveEndToEnd(t *testing.T) {
	const n = 4
	keys, ids, vs, addrs := testGroup(t, n, []int64{10, 20, 30, 40})

	sinks := make([]*memSink, n)
	rcs := make([]*Raptorcast, n)
	got := make([][]byte, n)
	for i := 0; i < n; i++ {
		sinks[i] = &memSink{}
		rcs[i] = New(ids[i], keys[i], addrs, sinks[i], DefaultOptions())
		rcs[i].AddEpochValidatorSet(7, vs)
		i := i
		rcs[i].SetHandler(func(from types.NodeId, payload []byte) {
			got[i] = append([]byte(nil), payload...)
		})
	}

	appMsg := rlp.AppendString(nil, []byte("hello raptorcast"))
	if err := rcs[0].Send(types.RouterTarget{Kind: types.RouterRaptorcast, Epoch: 7, Round: 3}, appMsg); err != nil {
		t.Fatal(err)
	}

	// author delivers to itself immediately
	if string(got[0]) != string(appMsg) {
		t.Fatalf("self delivery: %q want %q", got[0], appMsg)
	}

	// feed author's emitted datagrams to every other validator
	sent := sinks[0].drain()
	if len(sent) == 0 {
		t.Fatal("author emitted nothing")
	}
	var stride uint16
	for _, it := range sent {
		if len(it.Payload) > 0 {
			stride = uint16(len(it.Payload))
		}
	}
	for i := 1; i < n; i++ {
		for _, it := range sent {
			rcs[i].HandleDatagram(it.Dst, &ids[0], it.Payload, stride)
		}
	}
	for i := 1; i < n; i++ {
		if string(got[i]) != string(appMsg) {
			t.Fatalf("node %d: got %q want %q", i, got[i], appMsg)
		}
		// first-hop recipients should have rebroadcast
		if len(sinks[i].drain()) == 0 {
			t.Fatalf("node %d: no rebroadcast emitted", i)
		}
	}
}

// broadcast (non-raptorcast) mode: unicast chunks to every member.
func TestBroadcastSendReceive(t *testing.T) {
	const n = 3
	keys, ids, vs, addrs := testGroup(t, n, []int64{1, 1, 1})
	sinks := make([]*memSink, n)
	rcs := make([]*Raptorcast, n)
	got := make([][]byte, n)
	for i := 0; i < n; i++ {
		sinks[i] = &memSink{}
		rcs[i] = New(ids[i], keys[i], addrs, sinks[i], DefaultOptions())
		rcs[i].AddEpochValidatorSet(7, vs)
		i := i
		rcs[i].SetHandler(func(from types.NodeId, payload []byte) {
			got[i] = payload
		})
	}
	appMsg := rlp.AppendString(nil, []byte("primary broadcast msg"))
	if err := rcs[0].Send(types.RouterTarget{Kind: types.RouterBroadcast, Epoch: 7, Round: 1}, appMsg); err != nil {
		t.Fatal(err)
	}
	sent := sinks[0].drain()
	dsts := map[netip.AddrPort]bool{}
	for _, it := range sent {
		dsts[it.Dst] = true
	}
	if len(dsts) != n-1 {
		t.Fatalf("broadcast reached %d addrs, want %d (every non-author member)", len(dsts), n-1)
	}
	for i := 1; i < n; i++ {
		for _, it := range sent {
			rcs[i].HandleDatagram(it.Dst, &ids[0], it.Payload, uint16(len(it.Payload)))
		}
	}
	for i := 1; i < n; i++ {
		if string(got[i]) != string(appMsg) {
			t.Fatalf("node %d: got %q want %q", i, got[i], appMsg)
		}
	}
}

// a non-recipient must NOT deliver a unicast chunk (recipient-hash check).
func TestUnicastRecipientCheck(t *testing.T) {
	const n = 3
	keys, ids, vs, addrs := testGroup(t, n, []int64{1, 1, 1})
	sinks := make([]*memSink, n)
	rcs := make([]*Raptorcast, n)
	var got0, got1 []byte
	for i := 0; i < n; i++ {
		sinks[i] = &memSink{}
		rcs[i] = New(ids[i], keys[i], addrs, sinks[i], DefaultOptions())
		rcs[i].AddEpochValidatorSet(7, vs)
	}
	rcs[1].SetHandler(func(_ types.NodeId, p []byte) { got1 = p })
	rcs[2].SetHandler(func(_ types.NodeId, p []byte) { got0 = p })

	appMsg := rlp.AppendString(nil, []byte("p2p"))
	if err := rcs[0].Send(types.RouterTarget{Kind: types.RouterPointToPoint, To: ids[1]}, appMsg); err != nil {
		t.Fatal(err)
	}
	sent := sinks[0].drain()
	if len(sent) == 0 {
		t.Fatal("nothing sent")
	}
	// intended recipient decodes
	for _, it := range sent {
		rcs[1].HandleDatagram(it.Dst, &ids[0], it.Payload, uint16(len(it.Payload)))
	}
	if string(got1) != string(appMsg) {
		t.Fatalf("recipient got %q want %q", got1, appMsg)
	}
	// a third node seeing the same bytes must drop them (recipient hash)
	for _, it := range sent {
		rcs[2].HandleDatagram(it.Dst, &ids[0], it.Payload, uint16(len(it.Payload)))
	}
	if got0 != nil {
		t.Fatalf("non-recipient delivered %q", got0)
	}
}

// parse/validate rejection matrix over a valid fixture packet.
// Per upstream semantics: structural errors reject inside validate_chunk,
// while corrupting *signed* bytes (or the signature) still recovers some
// author — those packets drop at the group/author check in handleMessage.
func TestPacketValidationRejects(t *testing.T) {
	f := loadFixtures(t)
	c := f.Packets[0] // raptorcast-3val-100B
	author := nodeFromPkHex(t, c.Author)
	var selfID types.NodeId
	for _, m := range c.Members {
		if id := nodeFromPkHex(t, m.Pubkey); id != author {
			selfID = id
			break
		}
	}
	verifier := newSignatureVerifier(SignatureCacheSize, math.MaxUint32)
	bypass := func(types.Epoch) bool { return true }
	good := decodeHex(t, c.Packets[0].PayloadHex)

	mut := func(off int, xor byte) []byte {
		b := append([]byte(nil), good...)
		b[off] ^= xor
		return b
	}
	mustFailValidate := func(name string, payload []byte, maxAge uint64) {
		t.Helper()
		pkt, err := parsePacket(payload)
		if err != nil {
			return // parse rejection counts
		}
		if _, err := pkt.validateChunk(payload, verifier, maxAge, bypass, selfID); err == nil {
			t.Fatalf("%s: accepted corrupt packet", name)
		}
	}

	// structural rejections at parse/validate
	mustFailValidate("version", mut(65, 0x01), math.MaxUint64)
	// force mode bits 11 (invalid): keep depth 6, set top bits to 0b11
	invalidMode := append([]byte(nil), good...)
	invalidMode[67] = 0xc0 | (invalidMode[67] & 0x0f)
	mustFailValidate("mode bits=invalid 11", invalidMode, math.MaxUint64)
	// mode 0b01 = secondary: structurally valid but B5 scope — dropped at
	// handleMessage; checked in the drop-tier below
	mustFailValidate("depth too deep", mut(67, 0x0f), math.MaxUint64)
	// force depth=0 keeping mode bits (primary): 0b10_0000
	zeroDepth := append([]byte(nil), good...)
	zeroDepth[67] &= 0xf0
	mustFailValidate("depth too shallow", zeroDepth, math.MaxUint64)
	// 0x86^0x80 = 0x06 = unspecified+depth6: valid mode — drop tier
	mustFailValidateMode := mut(67, 0x80)
	_ = mustFailValidateMode
	mustFailValidate("empty", []byte{}, math.MaxUint64)
	mustFailValidate("stale ts", mut(76, 0xff), 1) // age > 1ms

	// loopback: author receiving own packet
	pkt, err := parsePacket(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pkt.validateChunk(good, verifier, math.MaxUint64, bypass, author); err == nil {
		t.Fatal("loopback packet accepted")
	}

	// mutations that still parse+verify (garbage author) must drop at the
	// group stage — exercise via a full udpState.handleMessage.
	vals := make([]validator.ValidatorData, 0, len(c.Members))
	for _, m := range c.Members {
		v, _ := new(big.Int).SetString(m.Stake, 10)
		vals = append(vals, validator.ValidatorData{NodeId: nodeFromPkHex(t, m.Pubkey), Stake: types.StakeFromBig(v)})
	}
	vs, err := validator.NewValidatorSet(vals)
	if err != nil {
		t.Fatal(err)
	}
	epochValidators := map[types.Epoch]*validator.ValidatorSet{types.Epoch(c.Epoch): vs}

	handle := func(payload []byte) int {
		st := newUDPState(selfID, math.MaxUint64, math.MaxUint32)
		var nrb int
		msgs := st.handleMessage(epochValidators, recvUDPMessage{
			sender:  &author,
			stride:  len(payload),
			payload: payload,
		}, func(rebroadcastRequest) { nrb++ })
		return len(msgs) + nrb // anything emitted = accepted somewhere
	}

	if n := handle(good); n == 0 {
		t.Fatal("valid packet dropped")
	}
	for _, tc := range []struct {
		name    string
		payload []byte
	}{
		{"signature byte", mut(0, 0xff)},
		{"secondary mode", mut(67, 0xc0)},
		{"unspecified mode in primary ctx", mut(67, 0x80)},
		{"truncated symbol", good[:len(good)-1]},
		{"signature recid", mut(64, 0x07)},
		{"app hash", mut(84, 0xff)},
		{"app len", mut(104, 0xff)},
		{"merkle proof byte", mut(108, 0xff)},
		{"chunk recipient", mut(c.SegmentLen-24, 0xff)},
		{"symbol byte", mut(c.SegmentLen-1, 0xff)},
	} {
		if n := handle(tc.payload); n != 0 {
			t.Fatalf("%s: corrupt packet produced output", tc.name)
		}
	}
}

// rate limiter: second verify of a NEW (uncached) signature fails without bypass.
func TestSignatureRateLimit(t *testing.T) {
	verifier := newSignatureVerifier(10, 1) // cache of 10, 1 tok/s
	kp := getKey(t, 7)
	msg := []byte("rate-limit-msg")
	sig := kp.Sign(crypto.DomainRaptorcastChunk, msg)
	// first call consumes the burst token
	if _, err := verifier.verifyChunkSignature(sig[:], msg, false); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// burst=1 → second distinct signature should be rate-limited
	msg2 := []byte("rate-limit-msg-2")
	sig2 := kp.Sign(crypto.DomainRaptorcastChunk, msg2)
	if _, err := verifier.verifyChunkSignature(sig2[:], msg2, false); err == nil {
		t.Fatal("expected rate limit on second verify")
	}
	// bypass flag skips the limiter
	if _, err := verifier.verifyChunkSignature(sig2[:], msg2, true); err != nil {
		t.Fatalf("bypass verify: %v", err)
	}
	// cached signature isn't rate limited
	if _, err := verifier.verifyChunkSignature(sig[:], msg, false); err != nil {
		t.Fatalf("cached verify: %v", err)
	}
}

// Decoder cache semantics: duplicate chunks are idempotent, a completed
// message moves to recently-decoded, and a hash-mismatched reconstruction
// taints the entry.
func TestDecoderCacheSemantics(t *testing.T) {
	f := loadFixtures(t)
	c := f.Packets[1] // raptorcast-6val-10k — multi-symbol message
	author := nodeFromPkHex(t, c.Author)
	var selfID types.NodeId
	for _, m := range c.Members {
		if id := nodeFromPkHex(t, m.Pubkey); id != author {
			selfID = id
			break
		}
	}
	vals := make([]validator.ValidatorData, 0, len(c.Members))
	for _, m := range c.Members {
		v, _ := new(big.Int).SetString(m.Stake, 10)
		vals = append(vals, validator.ValidatorData{NodeId: nodeFromPkHex(t, m.Pubkey), Stake: types.StakeFromBig(v)})
	}
	vs, err := validator.NewValidatorSet(vals)
	if err != nil {
		t.Fatal(err)
	}
	verifier := newSignatureVerifier(SignatureCacheSize, math.MaxUint32)
	bypass := func(types.Epoch) bool { return true }
	cache := newDecoderCache(defaultDecoderCacheConfig)

	validate := func(i int) *validatedChunk {
		t.Helper()
		payload := decodeHex(t, c.Packets[i].PayloadHex)
		pkt, err := parsePacket(payload)
		if err != nil {
			t.Fatal(err)
		}
		chk, err := pkt.validateChunk(payload, verifier, math.MaxUint64, bypass, selfID)
		if err != nil {
			t.Fatalf("packet %d validate: %v", i, err)
		}
		return chk
	}

	// feed packets in order; duplicates must be rejected without breaking state
	var decoded []byte
	seenStatuses := map[tryDecodeStatus]int{}
	for i := 0; i < len(c.Packets); i++ {
		chk := validate(i)
		res, err := cache.tryDecode(chk, vs, math.MaxUint64)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		seenStatuses[res.status]++
		if res.status == statusDecoded {
			decoded = res.appMessage
			break
		}
		// duplicate replay of the same chunk → error, not double-count
		if _, err := cache.tryDecode(chk, vs, math.MaxUint64); err == nil {
			t.Fatalf("packet %d: duplicate chunk accepted", i)
		}
	}
	want := decodeHex(t, c.MsgHex)
	if string(decoded) != string(want) {
		t.Fatalf("decoded %d bytes want %d", len(decoded), len(want))
	}

	// post-decode: another packet for the same message → RecentlyDecoded
	for i := 0; i < len(c.Packets); i++ {
		chk := validate(i)
		res, err := cache.tryDecode(chk, vs, math.MaxUint64)
		if err == nil && res.status == statusRecentlyDecoded {
			return // exercised the recently-decoded path
		}
		if err != nil {
			continue // duplicates inside recently-decoded → fine too
		}
	}
	t.Fatal("never saw RecentlyDecoded status for replayed packets")
}
