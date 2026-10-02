package peerdisc

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zeebo/blake3"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

// getKey reproduces monad-testutil get_key(seed): KeyPair::from_bytes(blake3(le64(seed))).
func getKey(t *testing.T, seed uint64) *crypto.SecpKeyPair {
	t.Helper()
	var sb [8]byte
	binary.LittleEndian.PutUint64(sb[:], seed)
	digest := blake3.Sum256(sb[:])
	kp, err := crypto.SecpKeyPairFromBytes(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func snapHex(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name + ".snap")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	// insta snap: last quoted line is the hex payload
	start := strings.LastIndex(s, `"`)
	end := strings.LastIndex(s[:start], `"`)
	return s[end+1 : start]
}

func TestNameRecordEncodingFixture(t *testing.T) {
	nr := NewNameRecord(netip.MustParseAddr("192.168.50.100"), 9000, 9001, 9002, 15, 42)
	enc := rlp.Encode(nr)
	if got := hex.EncodeToString(enc); got != snapHex(t, "monad_peer_discovery__tests__name_record_encoded") {
		t.Fatalf("name record encoding mismatch:\n got %s", got)
	}
	// round trip
	var dec NameRecord
	if err := dec.DecodeRLP(rlp.NewStream(enc)); err != nil {
		t.Fatal(err)
	}
	if dec.TCPPort() != 9000 || dec.UDPPort() != 9001 || dec.AuthUDPPort() != 9002 ||
		dec.Capabilities != 15 || dec.Seq != 42 {
		t.Fatalf("decoded mismatch: %+v", dec)
	}
	if re := rlp.Encode(dec); string(re) != string(enc) {
		t.Fatal("re-encode mismatch")
	}
}

func TestAuthNameRecordEncodingFixture(t *testing.T) {
	nr := NewNameRecord(netip.MustParseAddr("10.0.0.42"), 9000, 9001, 9002, 0, 100)
	if got := hex.EncodeToString(rlp.Encode(nr)); got != snapHex(t, "monad_peer_discovery__tests__auth_encoded") {
		t.Fatalf("auth record encoding mismatch:\n got %s", got)
	}
}

func TestPingEncodingFixture(t *testing.T) {
	key := getKey(t, 37)
	ping := Ping{
		ID: 257,
		LocalNameRecord: NewMonadNameRecord(
			NewNameRecord(netip.MustParseAddr("127.0.0.1"), 8000, 8000, 8000, 0, 2), key),
	}
	enc := rlp.Encode(PingMessage(ping))
	if got := hex.EncodeToString(enc); got != snapHex(t, "monad_peer_discovery__message__test__peer_discovery_message_ping_encoding") {
		t.Fatalf("ping encoding mismatch:\n got %s", got)
	}
	var dec PeerDiscoveryMessage
	if err := dec.DecodeRLP(rlp.NewStream(enc)); err != nil {
		t.Fatal(err)
	}
	if dec.Ping == nil || dec.Ping.ID != 257 {
		t.Fatal("decode mismatch")
	}
}

func TestPongEncodingFixture(t *testing.T) {
	enc := rlp.Encode(PongMessage(Pong{PingID: 123, LocalRecordSeq: 456}))
	if got := hex.EncodeToString(enc); got != snapHex(t, "monad_peer_discovery__message__test__peer_discovery_message_pong_encoding") {
		t.Fatalf("pong encoding mismatch:\n got %s", got)
	}
}

func TestLookupRequestEncodingFixture(t *testing.T) {
	key := getKey(t, 42)
	req := PeerLookupRequest{LookupID: 789, Target: types.NewNodeId(key.PubKey()), OpenDiscovery: true}
	enc := rlp.Encode(PeerLookupRequestMessage(req))
	if got := hex.EncodeToString(enc); got != snapHex(t, "monad_peer_discovery__message__test__peer_discovery_message_peer_lookup_request_encoding") {
		t.Fatalf("lookup request encoding mismatch:\n got %s", got)
	}
	var dec PeerDiscoveryMessage
	if err := dec.DecodeRLP(rlp.NewStream(enc)); err != nil {
		t.Fatal(err)
	}
	if dec.LookupRequest == nil || dec.LookupRequest.LookupID != 789 || !dec.LookupRequest.OpenDiscovery {
		t.Fatal("decode mismatch")
	}
}

func TestLookupResponseEncodingFixture(t *testing.T) {
	target := getKey(t, 100)
	mkRec := func(ip string, port, seq uint16, keySeed uint64) MonadNameRecord {
		return NewMonadNameRecord(
			NewNameRecord(netip.MustParseAddr(ip), port, port, port, 0, uint64(seq)),
			getKey(t, keySeed))
	}
	resp := PeerLookupResponse{
		LookupID: 999,
		Target:   types.NewNodeId(target.PubKey()),
		NameRecords: []MonadNameRecord{
			mkRec("192.168.1.1", 8000, 1, 37),
			mkRec("192.168.1.2", 8001, 2, 42),
			mkRec("192.168.1.3", 8002, 3, 55),
		},
	}
	enc := rlp.Encode(PeerLookupResponseMessage(resp))
	if got := hex.EncodeToString(enc); got != snapHex(t, "monad_peer_discovery__message__test__peer_discovery_message_peer_lookup_response_encoding") {
		t.Fatalf("lookup response encoding mismatch:\n got %s", got)
	}
	var dec PeerDiscoveryMessage
	if err := dec.DecodeRLP(rlp.NewStream(enc)); err != nil {
		t.Fatal(err)
	}
	if dec.LookupResponse == nil || len(dec.LookupResponse.NameRecords) != 3 {
		t.Fatal("decode mismatch")
	}
}

func TestFullNodeRaptorcastFixtures(t *testing.T) {
	if got := hex.EncodeToString(rlp.Encode(FullNodeRaptorcastRequestMessage)); got != snapHex(t, "monad_peer_discovery__message__test__peer_discovery_message_full_node_raptorcast_request_encoding") {
		t.Fatalf("request encoding mismatch: %s", got)
	}
	if got := hex.EncodeToString(rlp.Encode(FullNodeRaptorcastResponseMessage)); got != snapHex(t, "monad_peer_discovery__message__test__peer_discovery_message_full_node_raptorcast_response_encoding") {
		t.Fatalf("response encoding mismatch: %s", got)
	}
}

// --- ipv4 validation cases (mirrors upstream rstest table) ---

func TestValidateIPv4(t *testing.T) {
	cases := []struct {
		self, peer string
		want       error
	}{
		{"45.22.13.14", "0.0.0.0", ErrUnspecifiedIP},
		{"45.22.13.14", "224.0.0.1", ErrSpecialIP},
		{"45.22.13.14", "255.255.255.255", ErrSpecialIP},
		{"45.22.13.14", "198.51.100.1", ErrSpecialIP},
		{"45.22.13.14", "127.0.0.1", ErrLoopbackIP},
		{"127.0.0.2", "127.0.0.1", nil},
		{"45.22.13.14", "10.0.0.1", ErrPrivateIP},
		{"127.0.0.2", "127.0.0.1", nil},
		{"45.22.13.14", "169.254.1.1", ErrLinkLocalIP},
		{"169.254.1.2", "169.254.1.1", nil},
		{"45.22.13.14", "45.22.13.15", nil},
	}
	for _, c := range cases {
		self := netip.AddrPortFrom(netip.MustParseAddr(c.self), 8080)
		peer := netip.AddrPortFrom(netip.MustParseAddr(c.peer), 8080)
		if got := validateSocketIPv4Address(peer, self); got != c.want {
			t.Errorf("self=%s peer=%s: got %v want %v", c.self, c.peer, got, c.want)
		}
	}
}

// --- state machine tests ---

func testRecord(key *crypto.SecpKeyPair, ip string, port uint16, seq uint64) MonadNameRecord {
	return NewMonadNameRecord(
		NewNameRecord(netip.MustParseAddr(ip), port, port, port, 0, seq), key)
}

func testDiscovery(t *testing.T, selfKey *crypto.SecpKeyPair, bootstrap map[types.NodeId]MonadNameRecord) (*PeerDiscovery, []PeerDiscoveryCommand) {
	t.Helper()
	self := types.NewNodeId(selfKey.PubKey())
	b := PeerDiscoveryBuilder{
		SelfID:       self,
		SelfRecord:   testRecord(selfKey, "127.0.0.1", 8000, 1),
		CurrentRound: 0,
		CurrentEpoch: 1,
		EpochValidators: map[types.Epoch]map[types.NodeId]struct{}{
			1: {self: {}, types.NewNodeId(getKey(t, 2).PubKey()): {}},
		},
		BootstrapPeers:             bootstrap,
		RefreshPeriod:              time.Minute,
		RequestTimeout:             time.Second,
		UnresponsivePruneThreshold: 3,
		MinNumPeers:                5,
		MaxNumPeers:                50,
		MaxGroupSize:               20,
		PingRateLimitPerSecond:     1000,
		RngSeed:                    123456,
	}
	return b.Build()
}

// findEmit pulls the first PingPong emit from a command list (driver-style).
func cmdPings(cmds []PeerDiscoveryCommand) []PeerDiscoveryCommand {
	var out []PeerDiscoveryCommand
	for _, c := range cmds {
		if c.Kind == CmdPingPong {
			out = append(out, c)
		}
	}
	return out
}

func TestPingPongPromotion(t *testing.T) {
	selfKey := getKey(t, 1)
	peerKey := getKey(t, 2)
	peer := types.NewNodeId(peerKey.PubKey())

	pd, initCmds := testDiscovery(t, selfKey, map[types.NodeId]MonadNameRecord{
		peer: testRecord(peerKey, "127.0.0.2", 9000, 1),
	})

	// bootstrap peer goes pending + emits a ping
	if len(pd.PendingQueue) != 1 {
		t.Fatalf("pending queue %d", len(pd.PendingQueue))
	}
	pings := cmdPings(initCmds)
	if len(pings) != 1 || pings[0].Message.Kind != msgKindPing {
		t.Fatalf("bootstrap should emit ping, got %+v", initCmds)
	}
	pingID := pings[0].Message.Ping.ID

	// peer pongs → promoted to routing info
	cmds := pd.HandlePong(PeerSource{
		ID:   peer,
		Addr: netip.MustParseAddrPort("127.0.0.2:9000"),
	}, Pong{PingID: pingID, LocalRecordSeq: 1})
	if _, ok := pd.RoutingInfo[peer]; !ok {
		t.Fatal("peer should be promoted to routing info")
	}
	if len(pd.PendingQueue) != 0 {
		t.Fatal("pending queue should be empty")
	}
	// promotion emits a ping-timeout reset (clear_ping_timeout)
	var sawReset bool
	for _, c := range cmds {
		if c.Kind == CmdTimer && c.Timer.Reset && c.Timer.Kind == TimerPingTimeout {
			sawReset = true
		}
	}
	if !sawReset {
		t.Fatal("expected ping-timeout reset on promotion")
	}
}

func TestPingIPMismatchDropped(t *testing.T) {
	selfKey := getKey(t, 1)
	peerKey := getKey(t, 2)
	peer := types.NewNodeId(peerKey.PubKey())
	pd, _ := testDiscovery(t, selfKey, nil)

	// ping claims 127.0.0.2 in record but arrives from 9.9.9.9 — dropped
	cmds := pd.HandlePing(PeerSource{
		ID:   peer,
		Addr: netip.MustParseAddrPort("9.9.9.9:9000"),
	}, Ping{ID: 7, LocalNameRecord: testRecord(peerKey, "127.0.0.2", 9000, 1)})
	if len(cmds) != 0 {
		t.Fatal("mismatched source IP ping should be dropped silently")
	}
	if len(pd.PendingQueue) != 0 {
		t.Fatal("no pending entry should be created")
	}
}

func TestPingRespondsPong(t *testing.T) {
	selfKey := getKey(t, 1)
	peerKey := getKey(t, 3)
	peer := types.NewNodeId(peerKey.PubKey())
	pd, _ := testDiscovery(t, selfKey, nil)

	cmds := pd.HandlePing(PeerSource{
		ID:   peer,
		Addr: netip.MustParseAddrPort("127.0.0.3:9000"),
	}, Ping{ID: 42, LocalNameRecord: testRecord(peerKey, "127.0.0.3", 9000, 1)})
	pongs := cmdPings(cmds)
	// first cmd is our ping to them (insert pending), second is the pong reply
	var sawPong bool
	for _, c := range cmds {
		if c.Kind == CmdPingPong && c.Message.Kind == msgKindPong {
			sawPong = true
			if c.Message.Pong.PingID != 42 {
				t.Fatal("pong should echo ping id")
			}
			if c.Message.Pong.LocalRecordSeq != 1 {
				t.Fatal("pong should carry self record seq")
			}
		}
	}
	if !sawPong || len(pongs) == 0 {
		t.Fatal("expected a pong emit")
	}
	if _, ok := pd.PendingQueue[peer]; !ok {
		t.Fatal("peer should be in pending queue after valid ping")
	}
}

func TestLookupRequestResponseRoundTrip(t *testing.T) {
	selfKey := getKey(t, 1)
	askerKey := getKey(t, 2)
	targetKey := getKey(t, 9)
	target := types.NewNodeId(targetKey.PubKey())
	asker := types.NewNodeId(askerKey.PubKey())

	pd, _ := testDiscovery(t, selfKey, nil)
	// put target in routing info directly
	pd.RoutingInfo[target] = testRecord(targetKey, "127.0.0.9", 9000, 1)

	// asker sends lookup for target
	cmds := pd.HandlePeerLookupRequest(PeerSource{
		ID:   asker,
		Addr: netip.MustParseAddrPort("127.0.0.2:9000"),
	}, PeerLookupRequest{LookupID: 77, Target: target, OpenDiscovery: false})
	if len(cmds) != 1 || cmds[0].Kind != CmdRouter {
		t.Fatalf("expected RouterCommand response, got %+v", cmds)
	}
	resp := cmds[0].Message.LookupResponse
	if resp == nil || resp.LookupID != 77 || len(resp.NameRecords) != 1 {
		t.Fatalf("bad response: %+v", cmds[0].Message)
	}
	if resp.NameRecords[0].Seq() != 1 {
		t.Fatal("response should carry target's record")
	}
}

func TestLookupResponseInsertsPending(t *testing.T) {
	selfKey := getKey(t, 1)
	peerKey := getKey(t, 2)
	foundKey := getKey(t, 5)
	found := types.NewNodeId(foundKey.PubKey())
	peer := types.NewNodeId(peerKey.PubKey())

	pd, _ := testDiscovery(t, selfKey, nil)

	// send a lookup so there's an outstanding request
	cmds := pd.SendPeerLookupRequest(peer, found, true)
	if len(pd.OutstandingLookupRequests) != 1 {
		t.Fatal("request should be outstanding")
	}
	var lookupID uint32
	for id := range pd.OutstandingLookupRequests {
		lookupID = id
	}
	if len(cmds) < 2 {
		t.Fatal("expected timeout schedule + router emit")
	}

	// response arrives with found's record → inserted pending, request cleared
	cmds = pd.HandlePeerLookupResponse(PeerSource{
		ID:   peer,
		Addr: netip.MustParseAddrPort("127.0.0.2:9000"),
	}, PeerLookupResponse{
		LookupID:    lookupID,
		Target:      found,
		NameRecords: []MonadNameRecord{testRecord(foundKey, "127.0.0.5", 9000, 1)},
	})
	if len(pd.OutstandingLookupRequests) != 0 {
		t.Fatal("request should be cleared")
	}
	if _, ok := pd.PendingQueue[found]; !ok {
		t.Fatal("found peer should enter pending queue")
	}
}

func TestLookupResponseUnknownIDDropped(t *testing.T) {
	selfKey := getKey(t, 1)
	pd, _ := testDiscovery(t, selfKey, nil)
	peer := types.NewNodeId(getKey(t, 2).PubKey())
	if cmds := pd.HandlePeerLookupResponse(PeerSource{
		ID:   peer,
		Addr: netip.MustParseAddrPort("127.0.0.2:9000"),
	}, PeerLookupResponse{LookupID: 999}); len(cmds) != 0 {
		t.Fatal("unknown lookup id must be dropped")
	}
}

func TestPingTimeoutRetriesThenDrops(t *testing.T) {
	selfKey := getKey(t, 1)
	peerKey := getKey(t, 2)
	peer := types.NewNodeId(peerKey.PubKey())
	pd, _ := testDiscovery(t, selfKey, map[types.NodeId]MonadNameRecord{
		peer: testRecord(peerKey, "127.0.0.2", 9000, 1),
	})
	pingID := pd.PendingQueue[peer].LastPing.ID

	// threshold is 3: timeouts 1,2 retry; 3rd drops
	for i := uint32(1); i <= 2; i++ {
		cmds := pd.HandlePingTimeout(peer, pingID)
		if _, ok := pd.PendingQueue[peer]; !ok {
			t.Fatalf("peer dropped after %d timeouts", i)
		}
		pingID = pd.PendingQueue[peer].LastPing.ID // new ping id each retry
		_ = cmds
	}
	pd.HandlePingTimeout(peer, pingID)
	if _, ok := pd.PendingQueue[peer]; ok {
		t.Fatal("peer should be dropped at prune threshold")
	}
}

func TestRefreshPrunesAndSchedules(t *testing.T) {
	selfKey := getKey(t, 1)
	pd, _ := testDiscovery(t, selfKey, nil)
	pd.LastParticipationPruneThreshold = 10
	pd.CurrentRound = 100

	// a stale peer in participation_info + routing_info gets pruned
	stale := types.NewNodeId(getKey(t, 3).PubKey())
	pd.ParticipationInfo[stale] = &SecondaryRaptorcastInfo{LastActive: 50}
	pd.RoutingInfo[stale] = testRecord(getKey(t, 3), "127.0.0.3", 9000, 1)

	cmds := pd.refresh()
	if _, ok := deref(pd, stale); ok {
		t.Fatal("stale peer should be pruned")
	}
	var sawRefresh bool
	for _, c := range cmds {
		if c.Kind == CmdTimer && !c.Timer.Reset && c.Timer.Kind == TimerRefresh {
			sawRefresh = true
		}
	}
	if !sawRefresh {
		t.Fatal("refresh must reschedule itself")
	}
}

func deref(pd *PeerDiscovery, id types.NodeId) (*MonadNameRecord, bool) {
	nr, ok := pd.RoutingInfo[id]
	return &nr, ok
}

func TestValidatorSetUpdatePromotes(t *testing.T) {
	selfKey := getKey(t, 1)
	self := types.NewNodeId(selfKey.PubKey())
	pd, _ := testDiscovery(t, selfKey, nil)
	// start as non-validator full node
	pd.SelfRole = RoleFullNodeNone
	pd.EnablePublisher = true
	delete(pd.EpochValidators[1], self)

	// epoch 2 includes self → promote to ValidatorPublisher on round update
	pd.UpdateValidatorSet(2, []types.NodeId{self})
	pd.UpdateCurrentRound(10, 2)
	if pd.SelfRole != RoleValidatorPublisher {
		t.Fatalf("want ValidatorPublisher, got %v", pd.SelfRole)
	}
}

func TestSocketCollisionRejected(t *testing.T) {
	selfKey := getKey(t, 1)
	pd, _ := testDiscovery(t, selfKey, nil)
	a := types.NewNodeId(getKey(t, 2).PubKey())
	b := types.NewNodeId(getKey(t, 4).PubKey())
	socket := netip.MustParseAddrPort("127.0.0.7:9000")
	pd.SocketToID[socket] = a
	if pd.checkSocketAvailability(b, socket) {
		t.Fatal("socket bound to another node must be unavailable")
	}
	if !pd.checkSocketAvailability(a, socket) {
		t.Fatal("same node re-binding is allowed")
	}
}

func TestPeersFileRoundTrip(t *testing.T) {
	selfKey := getKey(t, 1)
	peerKey := getKey(t, 2)
	path := t.TempDir() + "/peers.rlp"
	self := types.NewNodeId(selfKey.PubKey())
	peer := types.NewNodeId(peerKey.PubKey())

	b := PeerDiscoveryBuilder{
		SelfID:     self,
		SelfRecord: testRecord(selfKey, "127.0.0.1", 8000, 1),
		BootstrapPeers: map[types.NodeId]MonadNameRecord{
			peer: testRecord(peerKey, "127.0.0.2", 9000, 3),
		},
		RefreshPeriod:              time.Minute,
		RequestTimeout:             time.Second,
		UnresponsivePruneThreshold: 3,
		MinNumPeers:                1,
		MaxNumPeers:                50,
		PingRateLimitPerSecond:     1000,
		RngSeed:                    1,
		PersistedPeersPath:         path,
	}
	pd, _ := b.Build()
	if len(pd.PendingQueue) != 1 {
		t.Fatal("bootstrap peer should be pending")
	}

	// new node reads persisted peers file → pending again
	pd2, cmds := b.Build()
	if _, ok := pd2.PendingQueue[peer]; !ok {
		t.Fatal("persisted peer not reloaded")
	}
	if len(cmdPings(cmds)) == 0 {
		t.Fatal("reload should emit pings")
	}
}
