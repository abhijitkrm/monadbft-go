package wireauth

// Snapshot conformance: replays upstream monad-wireauth insta fixtures
// byte-for-byte, including ChaCha12 StdRng key derivation.

import (
	"encoding/hex"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// --- minimal .snap (YAML subset) parser ---

type snapDoc map[string]any // string | map[string]string | []map[string]any

func parseSnap(t *testing.T, path string) snapDoc {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")
	// strip --- front matter --- header
	i := 0
	for i < len(lines) {
		if strings.HasPrefix(lines[i], "---") {
			i++
			for i < len(lines) && !strings.HasPrefix(lines[i], "---") {
				i++
			}
			i++
			break
		}
		i++
	}
	doc := snapDoc{}
	var curSection string
	var curList []map[string]any
	var inList bool
	flushList := func() {
		if inList && curList != nil {
			doc["_list"] = curList
			curList = nil
			inList = false
		}
	}
	for ; i < len(lines); i++ {
		line := lines[i]
		if strings.TrimSpace(line) == "" {
			continue
		}
		indented := strings.HasPrefix(line, " ")
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "- ") {
			inList = true
			curSection = ""
			item := map[string]any{}
			curList = append(curList, item)
			// parse "- key: value" as a key in the item
			rest := strings.TrimSpace(trim[2:])
			if k, v, ok := strings.Cut(rest, ":"); ok {
				k, v = strings.TrimSpace(k), strings.TrimSpace(v)
				if v == "" {
					item[k] = map[string]string{}
				} else {
					item[k] = unquote(v)
				}
			}
			// subsequent indented lines handled below via curSection on item
			// encode: last item marker
			doc["_list_pending"] = item
			continue
		}
		if !indented && !strings.HasPrefix(trim, "-") {
			k, v, ok := strings.Cut(trim, ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if inList {
				item := curList[len(curList)-1]
				if v == "" {
					item[k] = map[string]string{}
					curSection = k
				} else {
					item[k] = unquote(v)
					curSection = ""
				}
				continue
			}
			if v == "" {
				doc[k] = map[string]string{}
				curSection = k
			} else {
				doc[k] = unquote(v)
				curSection = ""
			}
			continue
		}
		// indented line: depth 2 = item scalar/section header,
		// depth >=4 = field inside current section.
		k, v, ok := strings.Cut(trim, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		depth := len(line) - len(strings.TrimLeft(line, " "))
		if inList {
			item := curList[len(curList)-1]
			if depth >= 4 {
				m, ok2 := item[curSection].(map[string]string)
				if !ok2 {
					m = map[string]string{}
					item[curSection] = m
				}
				m[k] = unquote(v)
			} else if v == "" {
				item[k] = map[string]string{}
				curSection = k
			} else {
				item[k] = unquote(v)
			}
		} else {
			m, ok2 := doc[curSection].(map[string]string)
			if !ok2 {
				m = map[string]string{}
				doc[curSection] = m
			}
			m[k] = unquote(v)
		}
	}
	flushList()
	return doc
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if s == "~" {
		return ""
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

func snapStr(t *testing.T, d snapDoc, k string) string {
	t.Helper()
	v, ok := d[k].(string)
	if !ok {
		t.Fatalf("missing scalar key %q", k)
	}
	return v
}

func snapSection(t *testing.T, d map[string]any, k string) map[string]string {
	t.Helper()
	v, ok := d[k].(map[string]string)
	if !ok {
		t.Fatalf("missing section %q", k)
	}
	return v
}

func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(unquote(s))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func u32v(t *testing.T, s string) uint32 {
	t.Helper()
	var v uint64
	for _, c := range s {
		v = v*10 + uint64(c-'0')
	}
	return uint32(v)
}

// --- fixture replay ---

// replayHandshake mirrors the upstream test flow: draw two static keypairs,
// send init at idxI, accept, send response at idxR, accept on initiator.
func replayHandshake(
	t *testing.T,
	r *stdRng,
	unixSecs uint64,
	idxI, idxR uint32,
	initCookie, respCookie *[16]byte,
) (initRaw, respRaw []byte, initKeys, respKeys transportKeys) {
	initKP, err := generateKeyPair(r)
	if err != nil {
		t.Fatal(err)
	}
	respKP, err := generateKeyPair(r)
	if err != nil {
		t.Fatal(err)
	}
	ts := tai64nFromTime(time.Unix(int64(unixSecs), 0))

	initMsg, initState, err := sendHandshakeInit(r, ts, idxI, initKP, respKP.PubKey(), initCookie)
	if err != nil {
		t.Fatal(err)
	}
	initRaw = initMsg.marshal() // snapshot wire bytes before accept mutates in place
	respState, _, err := acceptHandshakeInit(respKP, initMsg)
	if err != nil {
		t.Fatal(err)
	}
	respMsg, respKeysOut, err := sendHandshakeResponse(r, idxR, respState, [32]byte{}, respCookie)
	if err != nil {
		t.Fatal(err)
	}
	respKeys = respKeysOut
	respRaw = respMsg.marshal()
	initKeys, err = acceptHandshakeResponse(
		initKP, initState.ephemeralPrivate, initState.hash, initState.chainingKey, respMsg, [32]byte{},
	)
	if err != nil {
		t.Fatal(err)
	}
	return initRaw, respRaw, initKeys, respKeys
}

func checkMessageTrace(t *testing.T, sec map[string]string, raw []byte) {
	t.Helper()
	want := hexBytes(t, sec["raw_bytes"])
	if hex.EncodeToString(raw) != hex.EncodeToString(want) {
		t.Fatalf("raw_bytes mismatch\n got %s\nwant %s", hex.EncodeToString(raw), hex.EncodeToString(want))
	}
}

func TestStdRngSelfCheck(t *testing.T) {
	doc := parseSnap(t, "testdata/monad_wireauth__protocol__handshake__tests__complete_handshake_trace.snap")
	r := newStdRng(42)
	initKP, _ := generateKeyPair(r)
	respKP, _ := generateKeyPair(r)
	isk := initKP.SecretKey()
	gotInit := hex.EncodeToString(isk[:])
	rsk := respKP.SecretKey()
	gotResp := hex.EncodeToString(rsk[:])
	if want := snapStr(t, doc, "initiator_static_private"); gotInit != want {
		t.Fatalf("initiator private mismatch: got %s want %s", gotInit, want)
	}
	if want := snapStr(t, doc, "responder_static_private"); gotResp != want {
		t.Fatalf("responder private mismatch: got %s want %s", gotResp, want)
	}
	if got := hex.EncodeToString(initKP.PubKey().Bytes()); got != snapStr(t, doc, "initiator_static_public") {
		t.Fatalf("initiator public mismatch: got %s", got)
	}
	if got := hex.EncodeToString(respKP.PubKey().Bytes()); got != snapStr(t, doc, "responder_static_public") {
		t.Fatalf("responder public mismatch: got %s", got)
	}
}

func TestCompleteHandshakeTrace(t *testing.T) {
	doc := parseSnap(t, "testdata/monad_wireauth__protocol__handshake__tests__complete_handshake_trace.snap")
	r := newStdRng(42)
	initRaw, respRaw, initKeys, respKeys := replayHandshake(
		t, r, 1700000000, 100, 200, nil, nil,
	)
	checkMessageTrace(t, snapSection(t, doc, "init_message"), initRaw)
	checkMessageTrace(t, snapSection(t, doc, "response_message"), respRaw)

	keys := snapSection(t, doc, "transport_keys")
	if got := hex.EncodeToString(initKeys.sendKey[:]); got != keys["initiator_send_key"] {
		t.Fatalf("initiator send key mismatch: got %s want %s", got, keys["initiator_send_key"])
	}
	if got := hex.EncodeToString(initKeys.recvKey[:]); got != keys["initiator_recv_key"] {
		t.Fatalf("initiator recv key mismatch: got %s want %s", got, keys["initiator_recv_key"])
	}
	if got := hex.EncodeToString(respKeys.sendKey[:]); got != keys["responder_send_key"] {
		t.Fatalf("responder send key mismatch: got %s want %s", got, keys["responder_send_key"])
	}
	if got := hex.EncodeToString(respKeys.recvKey[:]); got != keys["responder_recv_key"] {
		t.Fatalf("responder recv key mismatch: got %s want %s", got, keys["responder_recv_key"])
	}
}

func TestCookieHandshakeTrace(t *testing.T) {
	doc := parseSnap(t, "testdata/monad_wireauth__protocol__handshake__tests__cookie_handshake_trace.snap")
	r := newStdRng(43)
	ts := tai64nFromTime(time.Unix(1700000000, 0))

	initKP, _ := generateKeyPair(r)
	respKP, _ := generateKeyPair(r)

	// init without cookie, index 101
	initMsg, _, err := sendHandshakeInit(r, ts, 101, initKP, respKP.PubKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	checkMessageTrace(t, snapSection(t, doc, "init_without_cookie"), initMsg.marshal())

	// cookie machinery: cookie_secret = 0x77*32, nonce=42, ip=192.168.1.1
	cookieSecret := [32]byte{}
	for i := range cookieSecret {
		cookieSecret[i] = 0x77
	}
	ip := mustParseIP(t, "192.168.1.1")
	cookie := generateCookie(&cookieSecret, 42, ip)
	if got := hex.EncodeToString(cookie[:]); got != snapStr(t, doc, "cookie_value") {
		t.Fatalf("cookie value mismatch: got %s want %s", got, doc["cookie_value"])
	}

	nonceSecret := cookieSecret // [0x77;32]
	reply := sendCookieReply(&nonceSecret, 1234, respKP.PubKey(), initMsg.senderIndex, initMsg.mac1, cookie)
	cr := snapSection(t, doc, "cookie_reply")
	checkMessageTrace(t, cr, reply.marshal())
	if got := hex.EncodeToString(reply.nonce[:]); got != cr["nonce"] {
		t.Fatalf("cookie nonce mismatch: got %s want %s", got, cr["nonce"])
	}

	extracted, err := acceptCookieReply(respKP.PubKey(), reply, initMsg.mac1)
	if err != nil {
		t.Fatal(err)
	}
	if extracted != cookie {
		t.Fatal("extracted cookie mismatch")
	}

	// init with cookie at index 102
	initMsg2, _, err := sendHandshakeInit(r, ts, 102, initKP, respKP.PubKey(), &extracted)
	if err != nil {
		t.Fatal(err)
	}
	checkMessageTrace(t, snapSection(t, doc, "init_with_cookie"), initMsg2.marshal())

	respState, _, err := acceptHandshakeInit(respKP, initMsg2)
	if err != nil {
		t.Fatal(err)
	}
	respMsg, _, err := sendHandshakeResponse(r, 201, respState, [32]byte{}, &cookie)
	if err != nil {
		t.Fatal(err)
	}
	checkMessageTrace(t, snapSection(t, doc, "response_with_cookie"), respMsg.marshal())
}

func mustParseIP(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestDataEncryptionTraces(t *testing.T) {
	doc := parseSnap(t, "testdata/monad_wireauth__protocol__handshake__tests__data_encryption_traces.snap")
	list, ok := doc["_list"].([]map[string]any)
	if !ok || len(list) != 2 {
		t.Fatalf("expected 2 traces, got %v", doc["_list"])
	}
	r := newStdRng(44)
	initKP, _ := generateKeyPair(r)
	respKP, _ := generateKeyPair(r)
	ts := tai64nFromTime(time.Unix(1700000000, 0))

	initMsg, initState, err := sendHandshakeInit(r, ts, 102, initKP, respKP.PubKey(), nil)
	if err != nil {
		t.Fatal(err)
	}
	respState, _, err := acceptHandshakeInit(respKP, initMsg)
	if err != nil {
		t.Fatal(err)
	}
	respMsg, respKeys, err := sendHandshakeResponse(r, 202, respState, [32]byte{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	initKeys, err := acceptHandshakeResponse(
		initKP, initState.ephemeralPrivate, initState.hash, initState.chainingKey, respMsg, [32]byte{},
	)
	if err != nil {
		t.Fatal(err)
	}

	// initiator -> responder
	tr := list[0]
	plaintext := []byte("Hello, encrypted world!")
	nonce := cipherNonceFromU64(1)
	tag := encryptInPlace(&initKeys.sendKey, &nonce, plaintext, nil)
	if got := hex.EncodeToString(plaintext); got != tr["encrypted_payload"].(string) {
		t.Fatalf("i2r payload mismatch: got %s want %s", got, tr["encrypted_payload"])
	}
	if got := hex.EncodeToString(tag[:]); got != tr["auth_tag"].(string) {
		t.Fatalf("i2r tag mismatch: got %s want %s", got, tr["auth_tag"])
	}

	// responder -> initiator
	tr = list[1]
	plaintext2 := []byte("Response from responder!")
	tag2 := encryptInPlace(&respKeys.sendKey, &nonce, plaintext2, nil)
	if got := hex.EncodeToString(plaintext2); got != tr["encrypted_payload"].(string) {
		t.Fatalf("r2i payload mismatch: got %s want %s", got, tr["encrypted_payload"])
	}
	if got := hex.EncodeToString(tag2[:]); got != tr["auth_tag"].(string) {
		t.Fatalf("r2i tag mismatch: got %s want %s", got, tr["auth_tag"])
	}
}

func TestMultipleProtocolVectors(t *testing.T) {
	doc := parseSnap(t, "testdata/monad_wireauth__protocol__handshake__tests__multiple_protocol_vectors.snap")
	list, ok := doc["_list"].([]map[string]any)
	if !ok {
		t.Fatalf("expected vector list")
	}
	for _, item := range list {
		seed := u32v(t, item["seed"].(string))
		ts := u32v(t, item["timestamp"].(string))
		r := newStdRng(uint64(seed))
		initKP, _ := generateKeyPair(r)
		respKP, _ := generateKeyPair(r)
		idxI := r.nextUint32()
		idxR := r.nextUint32()

		initMsg, initState, err := sendHandshakeInit(
			r, tai64nFromTime(time.Unix(int64(ts), 0)), idxI, initKP, respKP.PubKey(), nil)
		if err != nil {
			t.Fatal(err)
		}
		checkMessageTrace(t, item["init_message"].(map[string]string), initMsg.marshal())

		respState, _, err := acceptHandshakeInit(respKP, initMsg)
		if err != nil {
			t.Fatal(err)
		}
		respMsg, respKeys, err := sendHandshakeResponse(r, idxR, respState, [32]byte{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		checkMessageTrace(t, item["response_message"].(map[string]string), respMsg.marshal())

		initKeys, err := acceptHandshakeResponse(
			initKP, initState.ephemeralPrivate, initState.hash, initState.chainingKey, respMsg, [32]byte{},
		)
		if err != nil {
			t.Fatal(err)
		}
		keys := item["transport_keys"].(map[string]string)
		if got := hex.EncodeToString(initKeys.sendKey[:]); got != keys["initiator_send_key"] {
			t.Fatalf("seed %d: initiator send key mismatch", seed)
		}
		if got := hex.EncodeToString(respKeys.sendKey[:]); got != keys["responder_send_key"] {
			t.Fatalf("seed %d: responder send key mismatch", seed)
		}
	}
}
