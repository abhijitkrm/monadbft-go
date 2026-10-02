package wireauth

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/abhijitkrm/monadbft-go/crypto"
)

func apiAddrPort(ip string, port uint16) netip.AddrPort {
	return netip.MustParseAddrPort(ip + ":" + itoa(port))
}

func itoa(v uint16) string {
	if v == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

type testPair struct {
	a, b       *API
	aCtx, bCtx *TestContext
	aAddr      netip.AddrPort
	bAddr      netip.AddrPort
	aKey, bKey *crypto.SecpKeyPair
}

func newTestPair(t *testing.T) *testPair {
	t.Helper()
	cfg := DefaultConfig()
	cfg.KeepaliveInterval = 3 * time.Second
	cfg.KeepaliveJitter = 0
	cfg.SessionTimeout = 10 * time.Second
	cfg.SessionTimeoutJitter = 0

	aKey, err := crypto.GenerateSecpKeyPair(newStdRng(1))
	if err != nil {
		t.Fatal(err)
	}
	bKey, err := crypto.GenerateSecpKeyPair(newStdRng(2))
	if err != nil {
		t.Fatal(err)
	}
	p := &testPair{
		aCtx:  NewTestContext(newStdRng(11)),
		bCtx:  NewTestContext(newStdRng(22)),
		aAddr: apiAddrPort("10.0.0.1", 9000),
		bAddr: apiAddrPort("10.0.0.2", 9000),
		aKey:  aKey,
		bKey:  bKey,
	}
	p.a = NewAPI(cfg, aKey, p.aCtx)
	p.b = NewAPI(cfg, bKey, p.bCtx)
	return p
}

// relay moves every queued packet from src to dst's DispatchControl/Decrypt.
func relay(t *testing.T, src, dst *API, dstAddr, srcAddr netip.AddrPort) {
	t.Helper()
	for {
		addr, pkt, ok := src.NextPacket()
		if !ok {
			return
		}
		_ = addr
		ctrl, data, err := parsePacket(pkt)
		if err != nil {
			t.Fatalf("parsePacket: %v", err)
		}
		if ctrl != nil {
			if err := dst.DispatchControl(ctrl, srcAddr); err != nil {
				t.Fatalf("dispatch: %v", err)
			}
		} else {
			if _, _, err := dst.Decrypt(*data, srcAddr); err != nil {
				t.Fatalf("decrypt: %v", err)
			}
		}
	}
}

func (p *testPair) handshake(t *testing.T) {
	t.Helper()
	if err := p.a.Connect(p.bKey.PubKey(), p.bAddr, DefaultRetryAttempts); err != nil {
		t.Fatalf("connect: %v", err)
	}
	relay(t, p.a, p.b, p.aAddr, p.aAddr) // a's packets go to b, sourced at aAddr
	relay(t, p.b, p.a, p.bAddr, p.bAddr)
	relay(t, p.a, p.b, p.aAddr, p.aAddr)
}

func TestAPIHandshakeRoundTrip(t *testing.T) {
	p := newTestPair(t)
	p.handshake(t)

	if !p.a.IsConnectedPublicKey(p.bKey.PubKey()) {
		t.Fatal("a not connected to b")
	}
	if !p.b.IsConnectedSocketAndPublicKey(p.aAddr, p.aKey.PubKey()) {
		t.Fatal("b not connected to a")
	}

	// a -> b data
	msg := []byte("hello responder")
	hdr, err := p.a.EncryptByPublicKey(p.bKey.PubKey(), msg)
	if err != nil {
		t.Fatal(err)
	}
	wire := append(hdr.marshal(), msg...)
	ctrl, data, err := parsePacket(wire)
	if err != nil {
		t.Fatal(err)
	}
	if ctrl != nil {
		t.Fatal("data packet parsed as control")
	}
	pt, pub, err := p.b.Decrypt(*data, p.aAddr)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != "hello responder" {
		t.Fatalf("plaintext mismatch: %q", pt)
	}
	if pub != p.aKey.PubKey() {
		t.Fatal("wrong remote public key")
	}

	// b -> a data
	msg2 := []byte("hello initiator")
	hdr2, err := p.b.EncryptByPublicKey(p.aKey.PubKey(), msg2)
	if err != nil {
		t.Fatal(err)
	}
	wire2 := append(hdr2.marshal(), msg2...)
	_, data2, err := parsePacket(wire2)
	if err != nil {
		t.Fatal(err)
	}
	pt2, _, err := p.a.Decrypt(*data2, p.bAddr)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt2) != "hello initiator" {
		t.Fatalf("plaintext mismatch: %q", pt2)
	}
}

func TestAPIBufferedMessagesFlush(t *testing.T) {
	p := newTestPair(t)
	if err := p.a.Connect(p.bKey.PubKey(), p.bAddr, DefaultRetryAttempts); err != nil {
		t.Fatal(err)
	}
	if err := p.a.BufferMessage(p.bKey.PubKey(), []byte("queued1")); err != nil {
		t.Fatal(err)
	}
	if err := p.a.BufferMessage(p.bKey.PubKey(), []byte("queued2")); err != nil {
		t.Fatal(err)
	}
	relay(t, p.a, p.b, p.aAddr, p.aAddr)
	relay(t, p.b, p.a, p.bAddr, p.bAddr)

	// completing the handshake flushed the buffered messages into a's queue —
	// deliver them to b manually.
	if !p.a.IsConnectedPublicKey(p.bKey.PubKey()) {
		t.Fatal("not connected")
	}
	// buffered msgs arrive as data packets; decrypt them on b
	var got [][]byte
	for {
		_, pkt, ok := p.a.NextPacket()
		if !ok {
			break
		}
		_, data, err := parsePacket(pkt)
		if err != nil {
			t.Fatal(err)
		}
		if data == nil {
			continue
		}
		pt, _, err := p.b.Decrypt(*data, p.aAddr)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, append([]byte{}, pt...))
	}
	if len(got) != 2 || string(got[0]) != "queued1" || string(got[1]) != "queued2" {
		t.Fatalf("buffered flush wrong: %q", got)
	}
}

func TestAPISessionTimeoutRekey(t *testing.T) {
	p := newTestPair(t)
	p.handshake(t)

	// advance both sides past session timeout without traffic → initiator rekeys
	p.aCtx.AdvanceTime(11 * time.Second)
	p.bCtx.AdvanceTime(11 * time.Second)
	p.a.Tick()
	p.b.Tick()

	// a should have queued a fresh handshake init (rekey)
	addr, pkt, ok := p.a.NextPacket()
	if !ok {
		t.Fatal("no rekey packet from a")
	}
	if pkt[0] != msgTypeHandshakeInitiation {
		t.Fatalf("expected handshake init, got type %d", pkt[0])
	}
	if addr != p.bAddr {
		t.Fatal("rekey sent to wrong addr")
	}
}

func TestAPIReplayRejected(t *testing.T) {
	p := newTestPair(t)
	p.handshake(t)

	msg := []byte("once")
	hdr, err := p.a.EncryptByPublicKey(p.bKey.PubKey(), msg)
	if err != nil {
		t.Fatal(err)
	}
	wire := append(hdr.marshal(), msg...)
	_, data, _ := parsePacket(wire)
	if _, _, err := p.b.Decrypt(*data, p.aAddr); err != nil {
		t.Fatal(err)
	}
	// replay the same packet — must fail as duplicate nonce
	_, data2, _ := parsePacket(append([]byte{}, wire...))
	if _, _, err := p.b.Decrypt(*data2, p.aAddr); err == nil {
		t.Fatal("replayed packet accepted")
	}
}

func TestAPITamperedCiphertextRejected(t *testing.T) {
	p := newTestPair(t)
	p.handshake(t)

	msg := []byte("integrity")
	hdr, err := p.a.EncryptByPublicKey(p.bKey.PubKey(), msg)
	if err != nil {
		t.Fatal(err)
	}
	wire := append(hdr.marshal(), msg...)
	wire[len(wire)-1] ^= 0xff // tamper
	_, data, _ := parsePacket(wire)
	if _, _, err := p.b.Decrypt(*data, p.aAddr); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}

func TestAPIDisconnect(t *testing.T) {
	p := newTestPair(t)
	p.handshake(t)
	p.a.Disconnect(p.bKey.PubKey())
	if p.a.HasAnySessionByPublicKey(p.bKey.PubKey()) {
		t.Fatal("session not removed")
	}
	if _, err := p.a.EncryptByPublicKey(p.bKey.PubKey(), []byte("x")); err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound, got %v", err)
	}
}

var _ = bytes.Equal

// Cookie challenge flow: with LowWatermarkSessions=0, every unverified init
// gets a cookie reply; the initiator rekeys with mac2 set once its session
// timeout fires, and the responder then accepts.
func TestAPICookieChallengeFlow(t *testing.T) {
	p := newTestPair(t)
	// reload b with a demanding filter: low watermark 0 -> always challenge
	cfg := DefaultConfig()
	cfg.LowWatermarkSessions = 0
	cfg.HandshakeRateResetInterval = time.Hour // don't let counters reset mid-test
	cfg.SessionTimeout = 10 * time.Second
	cfg.SessionTimeoutJitter = 0
	p.b = NewAPI(cfg, p.bKey, p.bCtx)

	if err := p.a.Connect(p.bKey.PubKey(), p.bAddr, DefaultRetryAttempts); err != nil {
		t.Fatal(err)
	}
	// a -> b: init without cookie
	_, pkt, ok := p.a.NextPacket()
	if !ok || pkt[0] != msgTypeHandshakeInitiation {
		t.Fatalf("expected init, got %v %v", ok, pkt)
	}
	ctrl, _, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.b.DispatchControl(ctrl, p.aAddr); err != nil {
		t.Fatalf("b rejected init: %v", err)
	}
	// b -> a: cookie reply (not a handshake response)
	_, pkt2, ok := p.b.NextPacket()
	if !ok || pkt2[0] != msgTypeCookieReply {
		t.Fatalf("expected cookie reply, got %v %x", ok, pkt2)
	}
	ctrl2, _, err := parsePacket(pkt2)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.a.DispatchControl(ctrl2, p.bAddr); err != nil {
		t.Fatalf("a rejected cookie: %v", err)
	}

	// a's initiator session now holds stored_cookie; when its session timeout
	// fires, rekey sends init with mac2 populated.
	p.aCtx.AdvanceTime(11 * time.Second)
	p.a.Tick()
	_, pkt3, ok := p.a.NextPacket()
	if !ok || pkt3[0] != msgTypeHandshakeInitiation {
		t.Fatalf("expected rekey init, got %v %x", ok, pkt3)
	}
	m3, err := parseHandshakeInitiation(pkt3)
	if err != nil {
		t.Fatal(err)
	}
	if m3.mac2 == (macTag{}) {
		t.Fatal("rekey init has zero mac2 (cookie not attached)")
	}
	ctrl3, _, err := parsePacket(pkt3)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.b.DispatchControl(ctrl3, p.aAddr); err != nil {
		t.Fatalf("b rejected cookie'd init: %v", err)
	}
	// b -> a: real handshake response this time
	_, pkt4, ok := p.b.NextPacket()
	if !ok || pkt4[0] != msgTypeHandshakeResponse {
		t.Fatalf("expected handshake response, got %x", pkt4)
	}
}

// Timestamp replay: a second init at the same timestamp must be rejected once
// the responder recorded a newer one.
func TestAPITimestampReplay(t *testing.T) {
	p := newTestPair(t)
	p.handshake(t)

	// craft a fresh init at the same timestamp using a new API on the same key
	a2 := NewAPI(DefaultConfig(), p.aKey, p.aCtx)
	if err := a2.Connect(p.bKey.PubKey(), p.bAddr, 0); err != nil {
		t.Fatal(err)
	}
	_, pkt, ok := a2.NextPacket()
	if !ok {
		t.Fatal("no init from a2")
	}
	ctrl, _, err := parsePacket(pkt)
	if err != nil {
		t.Fatal(err)
	}
	err = p.b.DispatchControl(ctrl, p.aAddr)
	if err != ErrTimestampReplay {
		t.Fatalf("expected ErrTimestampReplay, got %v", err)
	}
}

// Far-future nonce must be rejected as outside the window.
func TestAPINonceOutsideWindow(t *testing.T) {
	p := newTestPair(t)
	p.handshake(t)

	msg := []byte("x")
	hdr, err := p.a.EncryptByPublicKey(p.bKey.PubKey(), msg)
	if err != nil {
		t.Fatal(err)
	}
	hdr.nonce += replayWindowBits + 100
	hdr.tag = [16]byte{} // tag invalid anyway; check order: replay first
	wire := append(hdr.marshal(), msg...)
	_, data, _ := parsePacket(wire)
	_, _, err = p.b.Decrypt(*data, p.aAddr)
	if err == nil || !errors.Is(err, ErrInvalidMac) {
		// replay check precedes mac; far-future nonce passes check, fails MAC —
		// and poisons the window forward. Upstream behaves the same.
		if err == nil {
			t.Fatal("expected failure")
		}
		t.Fatalf("expected mac failure, got %v", err)
	}
}
