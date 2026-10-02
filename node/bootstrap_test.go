package node

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/testutil"
	"github.com/abhijitkrm/monadbft-go/types"
)

func bpc(addr string, tcp, udp uint16) BootstrapPeerConfig {
	k := testutil.GetKey(1)
	sig := k.Sign(crypto.DomainNameRecord, []byte("x"))
	return BootstrapPeerConfig{
		Address:         addr,
		TCPPort:         tcp,
		UDPPort:         udp,
		RecordSeqNum:    1,
		Secp256k1Pubkey: hex.EncodeToString(k.PubKey().Bytes()),
		NameRecordSig:   hex.EncodeToString(sig.Serialize()),
		AuthPort:        8001,
	}
}

// Upstream parse_address_fields reject matrix.
func TestBootstrapAddressFieldValidation(t *testing.T) {
	ok := func(p BootstrapPeerConfig) bool { _, err := p.PeerEntry(); return err == nil }

	if !ok(bpc("1.2.3.4", 8000, 8001)) {
		t.Fatal("valid host + split ports rejected")
	}
	if !ok(bpc("1.2.3.4:8000", 0, 0)) {
		t.Fatal("valid host:port (no split fields) rejected")
	}
	if ok(bpc("1.2.3.4:8000", 8000, 8001)) {
		t.Fatal("host:port + split tcp_port must reject")
	}
	if !ok(bpc("1.2.3.4", 8000, 0)) {
		t.Fatal("split form without udp_port is valid upstream (auth-only peer)")
	}
	if ok(bpc("1.2.3.4", 0, 8001)) {
		t.Fatal("udp_port without tcp_port must reject")
	}
	if ok(bpc("1.2.3.4", 0, 0)) {
		t.Fatal("no ports at all must reject")
	}
	if ok(bpc("", 8000, 8001)) {
		t.Fatal("empty host must reject")
	}
	if ok(bpc("1.2.3.4:0", 0, 0)) {
		t.Fatal("zero embedded port must reject")
	}
	if ok(bpc("[::1]", 8000, 8001)) {
		t.Fatal("non-IPv4 address must reject")
	}
}

// Self record → peers file → verified roundtrip, as the devnet flows it.
func TestBootstrapRoundTrip(t *testing.T) {
	keyA, keyB := testutil.GetKey(1), testutil.GetKey(2)
	ip := netip.MustParseAddr("127.0.0.1")

	a := SelfBootstrapPeer(keyA, ip, 9000, 9001, 9002, 0, 0, 7)
	b := SelfBootstrapPeer(keyB, ip, 9100, 9101, 9102, 0, 0, 7)

	path := filepath.Join(t.TempDir(), "peers.json")
	data, _ := json.Marshal([]BootstrapPeerConfig{a, b})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	peers, err := LoadBootstrapPeersFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("want 2 peers, got %d", len(peers))
	}

	selfID := types.NewNodeId(keyA.PubKey())
	recs := BootstrapRecords(peers, selfID)
	if len(recs) != 1 {
		t.Fatalf("self must be filtered: %d records", len(recs))
	}
	rec, ok := recs[types.NewNodeId(keyB.PubKey())]
	if !ok {
		t.Fatal("B's record missing")
	}
	nr := rec.NameRecord
	if nr.TCPPort() != 9100 || nr.UDPPort() != 9101 || nr.AuthUDPPort() != 9102 {
		t.Fatalf("ports wrong: %+v", nr.Ports)
	}
	if nr.Seq != 7 || nr.IP.String() != "127.0.0.1" {
		t.Fatalf("record fields wrong: %+v", nr)
	}
}

// Tampered signature must not survive BootstrapRecords.
func TestBootstrapRejectsBadSig(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	good := SelfBootstrapPeer(testutil.GetKey(1), ip, 9000, 9001, 9002, 0, 0, 7)
	bad := good
	bad.TCPPort = 9999 // tamper after signing
	recs := BootstrapRecords([]BootstrapPeerConfig{good, bad}, types.NewNodeId(testutil.GetKey(2).PubKey()))
	if len(recs) != 1 {
		t.Fatalf("tampered record must drop: %d", len(recs))
	}
}
