package bridge

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtquery "github.com/cometbft/cometbft/libs/pubsub/query"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/gorilla/websocket"
	"golang.org/x/time/rate"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/types"
)

// RPCServer — a bounded CometBFT-compatible JSON-RPC surface over the
// bridge's committed state. MonadBFT replaces CometBFT but SDK tooling
// (clientCtx, gRPC gateway, wallets, explorers) speaks the CometBFT RPC
// dialect — this shim serves the canonical read endpoints plus tx
// broadcast off the ledger's committed blocks and the app's committed
// results. Reads are mutex-guarded; broadcast goes through the node's
// TxPool so txs still forward to upcoming leaders.
//
// v1 endpoints: /health /status /net_info /block /block_by_hash
// /block_results /commit /validators /tx /tx_search (subset)
// /broadcast_tx_{async,sync,commit} /abci_query. Websocket subscriptions,
// evidence/peer management, and full tx_search filtering are follow-ups —
// this is the data source SDK tooling needs, not a drop-in bus.
type RPCServer struct {
	app     *App
	ledger  *Ledger
	pool    *TxPool
	self    types.NodeId
	chainID string

	peersFn func() []glue.PeerEntry // engine wires node.Peers() for net_info
	bus     *cmttypes.EventBus      // engine wires the commit bus for /websocket
	consFn  func() map[string]any   // last-commit consensus snapshot (dump_consensus_state)

	limiter *ipLimiter
	noLimit bool // rate limiting disabled (trusted/loopback benchmarking)

	http *http.Server
	ln   net.Listener
}

func NewRPCServer(app *App, ledger *Ledger, pool *TxPool, self types.NodeId, chainID string) *RPCServer {
	return &RPCServer{app: app, ledger: ledger, pool: pool, self: self, chainID: chainID}
}

// SetEventBus — enables the websocket subscription endpoint.
func (s *RPCServer) SetEventBus(b *cmttypes.EventBus) { s.bus = b }

// SetConsStateFunc — the commit-snapshot used by dump_consensus_state.
func (s *RPCServer) SetConsStateFunc(f func() map[string]any) { s.consFn = f }

// SetPeersFunc — live peer snapshot for net_info.
func (s *RPCServer) SetPeersFunc(f func() []glue.PeerEntry) { s.peersFn = f }

// Start binds the listener and serves until Close. Addr like ":26657".
func (s *RPCServer) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.http = &http.Server{
		Handler:           s.mux(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Read/WriteTimeout stay zero — websocket streams are long-lived.
	}
	go s.http.Serve(ln)
	return nil
}

// Addr — bound address (for ":0" starts).
func (s *RPCServer) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *RPCServer) Close() {
	if s.http != nil {
		_ = s.http.Close()
	}
}

// Handler — the http.Handler for tests/embedders that own the listener.
func (s *RPCServer) Handler() http.Handler { return s.mux() }

func (s *RPCServer) mux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/websocket", s.handleWS)
	// Catch-all: method dispatch happens in handle; unknown methods get
	// the CometBFT "unknown method" error rather than a 404.
	mux.HandleFunc("/", s.handle)
	return mux
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func writeResult(w http.ResponseWriter, id any, result any) {
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeErr(w http.ResponseWriter, id any, code int, msg string) {
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": id,
		"error": rpcError{Code: code, Message: msg}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// handle — dispatch GET query-params and POST JSON-RPC {method,params,id}.
func (s *RPCServer) handle(w http.ResponseWriter, r *http.Request) {
	// Broadcast is exempt — tx ingress is bounded by the mempool, and a
	// request-rate cap here would throttle legitimate submitters. Reads
	// (block/tx/abci) are the expensive paths worth limiting.
	if !strings.HasPrefix(r.URL.Path, "/broadcast_tx_") && !s.allow(r) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	method := strings.TrimPrefix(r.URL.Path, "/")
	params := r.URL.Query()
	var id any = -1
	if r.Method == http.MethodPost {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
			ID     any            `json:"id"`
		}
		// Read the whole body under the cap — streaming decode would stop
		// at the first complete JSON value and let an oversized trailer
		// slide past the limit.
		r.Body = http.MaxBytesReader(w, r.Body, maxRPCBody)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, -1, -32700, "request body too large")
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeErr(w, -1, -32700, "parse error")
			return
		}
		method, id = req.Method, req.ID
		params = url.Values{}
		for k, v := range req.Params {
			params[k] = []string{fmt.Sprint(v)}
		}
	}

	var (
		result any
		err    error
	)
	// Handlers that dereference app/ledger must not panic when the server
	// is wired without them (degraded/test modes).
	needsApp := s.app == nil || s.ledger == nil
	switch method {
	case "health":
		result = struct{}{}
	case "block", "block_by_hash", "block_results", "commit", "validators",
		"block_search", "tx_search", "tx", "status",
		"broadcast_tx_async", "broadcast_tx_sync", "broadcast_tx_commit",
		"abci_query":
		if needsApp {
			err = fmt.Errorf("method %q unavailable: app not attached", method)
			break
		}
		result, err = s.dispatch(method, params)
	case "net_info":
		var peers []any
		if s.peersFn != nil {
			for _, e := range s.peersFn() {
				pk := e.Pubkey.PubKey.Bytes()
				peers = append(peers, map[string]any{
					"node_info": map[string]any{"id": hex.EncodeToString(pk[:20])},
					"remote_ip": e.Addr.String(),
				})
			}
		}
		result = map[string]any{"listening": true, "listeners": []string{},
			"n_peers": strconv.Itoa(len(peers)), "peers": peers}
	case "dump_consensus_state":
		result, err = s.dumpConsensusState()
	case "subscribe", "unsubscribe", "unsubscribe_all":
		err = fmt.Errorf("%q is only available over the /websocket endpoint", method)
	default:
		err = fmt.Errorf("unknown method %q", method)
	}
	if err != nil {
		writeErr(w, id, -32603, err.Error())
		return
	}
	writeResult(w, id, result)
}

func paramsHeight(q url.Values) int64 {
	if v := q.Get("height"); v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return -1 // sentinel: latest
}

func (s *RPCServer) resolveHeight(h int64) int64 {
	if h < 0 {
		return s.app.Height()
	}
	return h
}

// ---- block encoding ----

// blockJSON — a CometBFT-shaped block synthesized from the committed
// consensus block + app result (the header is consensus-format; tx/result
// fields map straight through).
func (s *RPCServer) blockJSON(fb *cstypes.ConsensusFullBlock) map[string]any {
	h := fb.Header
	seq := int64(h.SeqNum.Uint64())
	blockID := h.GetId()
	parentID := h.GetParentId()
	_, _, txs, _, _, _, _ := s.app.CommittedEntry(seq)
	if txs == nil {
		if b, ok := fb.Body.Inner.ExecutionBody.(*EvmBody); ok {
			txs = b.Txs
		}
	}
	bodyID := fb.GetBodyId()
	txb64 := make([]string, len(txs))
	for i, tx := range txs {
		txb64[i] = base64.StdEncoding.EncodeToString(tx)
	}
	bt := time.Unix(0, int64(h.TimestampNs.Uint64())).UTC()

	var appHash string
	if e, _, _, _, _, _, ok := s.app.CommittedEntry(seq); ok && e != nil {
		appHash = strings.ToUpper(hex.EncodeToString(e.AppHash))
	}
	header := map[string]any{
		"version":  map[string]string{"block": "11"},
		"chain_id": s.chainID,
		"height":   strconv.FormatInt(seq, 10),
		"time":     bt.Format(time.RFC3339Nano),
		"last_block_id": map[string]any{
			"hash":  strings.ToUpper(hex.EncodeToString(parentID[:])),
			"parts": map[string]any{"total": 1, "hash": strings.ToUpper(hex.EncodeToString(parentID[:]))},
		},
		"data_hash":            strings.ToUpper(hex.EncodeToString(bodyID[:])),
		"validators_hash":      strings.ToUpper(hex.EncodeToString(s.app.ValidatorsHash())),
		"next_validators_hash": strings.ToUpper(hex.EncodeToString(s.app.ValidatorsHash())),
		"app_hash":             appHash,
		"proposer_address":     strings.ToUpper(hex.EncodeToString(s.app.ConsAddr(h.Author))),
		"last_commit_hash":     "",
		"consensus_hash":       "",
		"last_results_hash":    "",
		"evidence_hash":        "",
	}
	return map[string]any{
		"block_id": map[string]any{
			"hash":  strings.ToUpper(hex.EncodeToString(blockID[:])),
			"parts": map[string]any{"total": 1, "hash": strings.ToUpper(hex.EncodeToString(blockID[:]))},
		},
		"block": map[string]any{
			"header":      header,
			"data":        map[string]any{"txs": txb64},
			"evidence":    map[string]any{"evidence": []any{}},
			"last_commit": s.commitJSON(fb),
		},
	}
}

// commitJSON — the QC rendered as a CometBFT Commit (signer bitmap →
// per-validator flags; the aggregate signature isn't decomposable).
func (s *RPCServer) commitJSON(fb *cstypes.ConsensusFullBlock) map[string]any {
	h := fb.Header
	qc := h.QC
	votes := s.app.LastCommitWith(qc, s.app.ValSetAt(int64(h.SeqNum.Uint64())-1))
	sigs := make([]map[string]any, len(votes.Votes))
	for i, v := range votes.Votes {
		flag := "1"
		if v.BlockIdFlag == 3 { // cmtproto.BlockIDFlagCommit
			flag = "2"
		}
		sigs[i] = map[string]any{
			"block_id_flag":     flag,
			"validator_address": strings.ToUpper(hex.EncodeToString(v.Validator.Address)),
			"timestamp":         time.Unix(0, int64(h.TimestampNs.Uint64())).UTC().Format(time.RFC3339Nano),
			"signature":         "",
		}
	}
	qcID := qc.Info.ID
	return map[string]any{
		"height": strconv.FormatInt(int64(h.SeqNum.Uint64()), 10),
		"round":  strconv.FormatUint(uint64(qc.Info.Round), 10),
		"block_id": map[string]any{
			"hash":  strings.ToUpper(hex.EncodeToString(qcID[:])),
			"parts": map[string]any{"total": 1, "hash": strings.ToUpper(hex.EncodeToString(qcID[:]))},
		},
		"signatures": sigs,
	}
}

func (s *RPCServer) blockAt(h int64) (any, error) {
	seq := s.resolveHeight(h)
	fb := s.ledger.committedBlock(types.SeqNum(seq))
	if fb == nil {
		return nil, fmt.Errorf("block %d not found", seq)
	}
	return s.blockJSON(fb), nil
}

func (s *RPCServer) blockByHash(hashHex string) (any, error) {
	bz, err := hex.DecodeString(strings.TrimPrefix(hashHex, "0x"))
	if err != nil || len(bz) != 32 {
		return nil, fmt.Errorf("invalid block hash %q", hashHex)
	}
	// Comet block hash → height via the persisted index (O(1)).
	if h, ok := s.app.CmtHeight(bz); ok {
		if fb := s.ledger.committedBlock(types.SeqNum(uint64(h))); fb != nil {
			return s.blockJSON(fb), nil
		}
	}
	// Fallback: the caller passed a consensus BlockId.
	var id types.BlockId
	copy(id[:], bz)
	if fb := s.ledger.committedBlockByID(id); fb != nil {
		return s.blockJSON(fb), nil
	}
	return nil, fmt.Errorf("block %s not found", hashHex)
}

// blockSearch — "block.height op N" conditions over the committed index.
func (s *RPCServer) blockSearch(query, orderBy string) (any, error) {
	lo, hi, err := heightRange(query, "block.height")
	if err != nil {
		return nil, err
	}
	hi = min(hi, s.app.Height())
	desc := orderBy == "desc"
	var blocks []any
	step, start, end := int64(1), lo, hi
	if desc {
		step, start, end = -1, hi, lo
	}
	for h := start; h*step <= end*step; h += step {
		if h < 1 || h > s.app.Height() {
			break
		}
		if fb := s.ledger.committedBlock(types.SeqNum(h)); fb != nil {
			blocks = append(blocks, s.blockJSON(fb))
		}
	}
	return map[string]any{"blocks": blocks, "total_count": strconv.Itoa(len(blocks))}, nil
}

// txSearch — tx.hash point lookup + tx.height ranges over committed results.
func (s *RPCServer) txSearch(query string) (any, error) {
	if m := txHashCond.FindStringSubmatch(query); m != nil {
		tx, err := s.txByHash(m[1])
		if err != nil {
			return map[string]any{"txs": []any{}, "total_count": "0"}, nil
		}
		return map[string]any{"txs": []any{tx}, "total_count": "1"}, nil
	}
	lo, hi, err := heightRange(query, "tx.height")
	if err != nil {
		return nil, err
	}
	var out []any
	for h := lo; h <= hi && h <= s.app.Height(); h++ {
		_, _, txs, txRes, _, _, ok := s.app.CommittedEntry(h)
		if !ok {
			continue
		}
		for i, tx := range txs {
			var res any
			if i < len(txRes) && txRes[i] != nil {
				res = txRes[i]
			}
			out = append(out, map[string]any{
				"hash":   strings.ToUpper(hex.EncodeToString(tmhash.Sum(tx))),
				"height": strconv.FormatInt(h, 10),
				"index":  i, "tx_result": res,
				"tx": base64.StdEncoding.EncodeToString(tx),
			})
		}
	}
	return map[string]any{"txs": out, "total_count": strconv.Itoa(len(out))}, nil
}

func (s *RPCServer) blockResults(h int64) (any, error) {
	seq := s.resolveHeight(h)
	_, _, _, txResults, events, updates, ok := s.app.CommittedEntry(seq)
	if !ok {
		return nil, fmt.Errorf("block results %d not found", seq)
	}
	return map[string]any{
		"height":                  strconv.FormatInt(seq, 10),
		"txs_results":             txResults,
		"finalize_block_events":   events,
		"validator_updates":       updates,
		"consensus_param_updates": nil,
	}, nil
}

func (s *RPCServer) commitAt(h int64) (any, error) {
	seq := s.resolveHeight(h)
	fb := s.ledger.committedBlock(types.SeqNum(seq))
	if fb == nil {
		return nil, fmt.Errorf("commit %d not found", seq)
	}
	blk := s.blockJSON(fb)
	return map[string]any{
		"signed_header": map[string]any{
			"header": blk["block"].(map[string]any)["header"],
			"commit": s.commitJSON(fb),
		},
		"canonical": false,
	}, nil
}

func (s *RPCServer) validators(h int64) map[string]any {
	vals := s.app.Validators()
	out := make([]map[string]any, len(vals))
	for i, v := range vals {
		out[i] = map[string]any{
			"address":           strings.ToUpper(hex.EncodeToString(v.Address)),
			"pub_key":           map[string]any{"type": "tendermint/PubKeyEd25519", "value": base64.StdEncoding.EncodeToString(v.PubKey.Bytes())},
			"voting_power":      strconv.FormatInt(v.VotingPower, 10),
			"proposer_priority": strconv.FormatInt(v.ProposerPriority, 10),
		}
	}
	return map[string]any{
		"block_height": strconv.FormatInt(s.resolveHeight(h), 10),
		"count":        strconv.Itoa(len(out)),
		"total":        strconv.Itoa(len(out)),
		"validators":   out,
	}
}

func (s *RPCServer) txByHash(hashHex string) (any, error) {
	hashHex = strings.ToUpper(strings.TrimPrefix(hashHex, "0x"))
	height, ok := s.app.TxLookup(hashHex)
	if !ok {
		return nil, fmt.Errorf("tx %s not found", hashHex)
	}
	_, _, txs, txResults, _, _, _ := s.app.CommittedEntry(height)
	var index int
	var txBytes []byte
	for i, tx := range txs {
		if fmt.Sprintf("%X", tmhash.Sum(tx)) == hashHex {
			index, txBytes = i, tx
			break
		}
	}
	var txr any
	if index < len(txResults) {
		txr = txResults[index]
	}
	return map[string]any{
		"hash":      hashHex,
		"height":    strconv.FormatInt(height, 10),
		"index":     index,
		"tx_result": txr,
		"tx":        base64.StdEncoding.EncodeToString(txBytes),
	}, nil
}

func (s *RPCServer) broadcast(method, txParam string) (any, error) {
	bz, err := decodeTx(txParam)
	if err != nil {
		return nil, fmt.Errorf("bad tx encoding: %v", err)
	}
	hash := strings.ToUpper(hex.EncodeToString(tmhash.Sum(bz)))
	code, log, err := s.pool.SubmitTx(bz)
	if err != nil {
		return nil, err
	}
	if method == "broadcast_tx_commit" {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if h, ok := s.app.TxLookup(hash); ok {
				_, _, _, txrs, _, _, _ := s.app.CommittedEntry(h)
				return map[string]any{
					"height":    strconv.FormatInt(h, 10),
					"hash":      hash,
					"check_tx":  map[string]any{"code": code, "log": log},
					"tx_result": firstTxResult(txrs, bz),
				}, nil
			}
			time.Sleep(50 * time.Millisecond)
		}
		return nil, fmt.Errorf("tx submitted but not committed within timeout")
	}
	return map[string]any{"code": code, "data": "", "log": log, "hash": hash}, nil
}

func firstTxResult(txrs []*abcitypes.ExecTxResult, tx []byte) any {
	h := fmt.Sprintf("%X", tmhash.Sum(tx))
	_ = h
	if len(txrs) > 0 {
		return txrs[0]
	}
	return nil
}

func (s *RPCServer) abciQuery(q url.Values) (any, error) {
	var data []byte
	if d := q.Get("data"); d != "" {
		var err error
		data, err = decodeTx(d)
		if err != nil {
			return nil, err
		}
	}
	s.app.opMu.Lock()
	res, err := s.app.app.Query(context.Background(), &abcitypes.RequestQuery{
		Path:   q.Get("path"),
		Data:   data,
		Height: paramsHeight(q),
	})
	s.app.opMu.Unlock()
	if err != nil {
		return nil, err
	}
	return map[string]any{"response": res}, nil
}

// status — CometBFT ResultStatus shape.
func (s *RPCServer) status() map[string]any {
	height := s.app.Height()
	var blockHash, appHash string
	var blockTime string
	if height > 0 {
		if fb := s.ledger.committedBlock(types.SeqNum(height)); fb != nil {
			id := fb.GetId()
			blockHash = strings.ToUpper(hex.EncodeToString(id[:]))
			blockTime = time.Unix(0, int64(fb.Header.TimestampNs.Uint64())).UTC().Format(time.RFC3339Nano)
		}
		if r := s.app.Result(height); r != nil {
			appHash = strings.ToUpper(hex.EncodeToString(r.AppHash))
		}
	}
	var consAddr, power string
	for i := range s.app.monadVals {
		if s.app.monadVals[i].NodeId() == s.self {
			consAddr = strings.ToUpper(hex.EncodeToString(s.app.monadVals[i].ConsAddr()))
		}
	}
	for _, v := range s.app.Validators() {
		if strings.ToUpper(hex.EncodeToString(v.Address)) == consAddr {
			power = strconv.FormatInt(v.VotingPower, 10)
		}
	}
	return map[string]any{
		"node_info": map[string]any{
			"protocol_version": map[string]string{"p2p": "8", "block": "11", "app": "0"},
			"id":               strings.ToUpper(hex.EncodeToString(s.self.PubKey.Bytes())),
			"listen_addr":      "",
			"network":          s.chainID,
			"version":          "monadbft",
			"channels":         "",
			"moniker":          "monadbft",
			"other":            map[string]string{"tx_index": "on", "rpc_address": ""},
		},
		"sync_info": map[string]any{
			"latest_block_hash":     blockHash,
			"latest_app_hash":       appHash,
			"latest_block_height":   strconv.FormatInt(height, 10),
			"latest_block_time":     blockTime,
			"earliest_block_hash":   "",
			"earliest_app_hash":     "",
			"earliest_block_height": "1",
			"earliest_block_time":   blockTime,
			"catching_up":           false,
		},
		"validator_info": map[string]any{
			"address":      consAddr,
			"pub_key":      map[string]any{"type": "tendermint/PubKeyEd25519", "value": ""},
			"voting_power": power,
		},
	}
}

// decodeTx — CometBFT accepts base64 (default) or 0x-prefixed hex.
func decodeTx(s string) ([]byte, error) {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return hex.DecodeString(s[2:])
	}
	if bz, err := base64.StdEncoding.DecodeString(s); err == nil {
		return bz, nil
	}
	return hex.DecodeString(s)
}

// ---- dump_consensus_state ----

const (
	maxRPCBody       = 4 << 20 // 4 MiB POST cap — a 512-tx EVM block is ~1 MiB
	rpcRatePerSec    = 60      // per-IP sustained request rate
	rpcRateBurst     = 120
	wsMaxSubsPerConn = 32
	wsWriteTimeout   = 10 * time.Second
	wsSubBuffer      = 256
)

// dumpConsensusState — the last-commit consensus snapshot plus the peer
// set. CometBFT reports live round state; ours is captured on the commit
// path (the only point the consensus state can be read without racing the
// node loop) — heights/rounds describe the last finalized block.
func (s *RPCServer) dumpConsensusState() (any, error) {
	if s.consFn == nil {
		return nil, fmt.Errorf("consensus state snapshot not wired")
	}
	rs := s.consFn()
	var peers []any
	if s.peersFn != nil {
		for _, e := range s.peersFn() {
			pk := e.Pubkey.PubKey.Bytes()
			peers = append(peers, map[string]any{
				"node_address": hex.EncodeToString(pk[:20]) + "@" + e.Addr.String(),
			})
		}
	}
	return map[string]any{"round_state": rs, "peers": peers}, nil
}

// ---- websocket subscriptions ----

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Same-origin policy doesn't apply to CometBFT dialect clients
	// (CLI, indexers); operators front this with their own proxy rules.
	CheckOrigin: func(*http.Request) bool { return true },
}

type wsRequest struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
	ID     any            `json:"id"`
}

// handleWS — GET /websocket upgrade; serves the CometBFT subscription
// dialect: {"method":"subscribe","params":{"query":"tm.event='NewBlock'"}},
// "unsubscribe" (same params), "unsubscribe_all". Events stream as
// {"id":<sub id>,"result":{"query":…,"data":…,"events":{…}}}.
func (s *RPCServer) handleWS(w http.ResponseWriter, r *http.Request) {
	if s.bus == nil {
		http.Error(w, "subscriptions not enabled", http.StatusNotImplemented)
		return
	}
	if !s.allow(r) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return // upgrade writes its own error
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// Single writer: subscription fan-in and replies serialize here.
	type outMsg struct{ v any }
	outCh := make(chan outMsg, wsSubBuffer*2)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case m := <-outCh:
				_ = conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
				if err := conn.WriteJSON(m.v); err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()
	send := func(v any) {
		select {
		case outCh <- outMsg{v}:
		case <-done:
		}
	}
	reply := func(id any, result any, errMsg string) {
		if errMsg != "" {
			send(map[string]any{"jsonrpc": "2.0", "id": id,
				"error": rpcError{Code: -32603, Message: errMsg}})
			return
		}
		send(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	}

	subscriber := fmt.Sprintf("ws-%s", r.RemoteAddr)
	defer s.bus.UnsubscribeAll(context.Background(), subscriber) //nolint:errcheck

	var subsMu sync.Mutex
	subs := 0
	for {
		var req wsRequest
		if err := conn.ReadJSON(&req); err != nil {
			return // peer closed or frame error
		}
		switch req.Method {
		case "subscribe":
			q := fmt.Sprint(req.Params["query"])
			query, err := cmtquery.New(q)
			if err != nil {
				reply(req.ID, nil, "invalid query: "+err.Error())
				continue
			}
			subsMu.Lock()
			if subs >= wsMaxSubsPerConn {
				subsMu.Unlock()
				reply(req.ID, nil, "subscription limit reached")
				continue
			}
			subs++
			subsMu.Unlock()
			sub, err := s.bus.Subscribe(ctx, subscriber, query, wsSubBuffer)
			if err != nil {
				subsMu.Lock()
				subs--
				subsMu.Unlock()
				reply(req.ID, nil, err.Error())
				continue
			}
			subID := req.ID // events stream under the request id (comet dialect)
			go func() {
				defer s.bus.Unsubscribe(context.Background(), subscriber, query) //nolint:errcheck
				for {
					select {
					case msg := <-sub.Out():
						send(map[string]any{"jsonrpc": "2.0", "id": subID,
							"result": map[string]any{
								"query": q, "data": msg.Data(), "events": msg.Events(),
							}})
					case <-sub.Canceled():
						return
					case <-ctx.Done():
						return
					case <-done:
						return
					}
				}
			}()
			reply(req.ID, map[string]any{}, "")
		case "unsubscribe":
			q := fmt.Sprint(req.Params["query"])
			query, err := cmtquery.New(q)
			if err != nil {
				reply(req.ID, nil, "invalid query: "+err.Error())
				continue
			}
			if err := s.bus.Unsubscribe(ctx, subscriber, query); err != nil {
				reply(req.ID, nil, err.Error())
				continue
			}
			subsMu.Lock()
			if subs > 0 {
				subs--
			}
			subsMu.Unlock()
			reply(req.ID, map[string]any{}, "")
		case "unsubscribe_all":
			if err := s.bus.UnsubscribeAll(ctx, subscriber); err != nil {
				reply(req.ID, nil, err.Error())
				continue
			}
			subsMu.Lock()
			subs = 0
			subsMu.Unlock()
			reply(req.ID, map[string]any{}, "")
		default:
			reply(req.ID, nil, "unknown method "+strconv.Quote(req.Method))
		}
	}
}

// ---- per-IP rate limiting ----

type ipLimiter struct {
	mu     sync.Mutex
	limits map[string]*rate.Limiter
	lastGC time.Time
	perSec rate.Limit
	burst  int
}

func newIPLimiter(perSec rate.Limit, burst int) *ipLimiter {
	return &ipLimiter{limits: make(map[string]*rate.Limiter), perSec: perSec, burst: burst}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.limits == nil {
		l.limits = make(map[string]*rate.Limiter)
	}
	// Lazy sweep — drop stale limiter entries so the map can't grow with
	// every IP that ever connected.
	if now := time.Now(); now.Sub(l.lastGC) > 10*time.Minute {
		l.lastGC = now
		for k, v := range l.limits {
			if v.Tokens() > float64(l.burst)-1 {
				delete(l.limits, k)
			}
		}
	}
	lim, ok := l.limits[ip]
	if !ok {
		lim = rate.NewLimiter(l.perSec, l.burst)
		l.limits[ip] = lim
	}
	return lim.Allow()
}

// SetRateLimit — per-IP request limit: perSec 0 keeps the default
// (rpcRatePerSec/rpcRateBurst), < 0 disables limiting. Call before Start.
func (s *RPCServer) SetRateLimit(perSec float64, burst int) {
	switch {
	case perSec < 0:
		s.noLimit = true
	case perSec > 0:
		if burst <= 0 {
			burst = int(2 * perSec)
		}
		s.limiter = newIPLimiter(rate.Limit(perSec), burst)
	}
}

func (s *RPCServer) allow(r *http.Request) bool {
	if s.noLimit {
		return true
	}
	if s.limiter == nil {
		s.limiter = newIPLimiter(rpcRatePerSec, rpcRateBurst)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	return s.limiter.allow(ip)
}

// dispatch — app/ledger-backed methods (guarded by needsApp in handle).
func (s *RPCServer) dispatch(method string, params url.Values) (any, error) {
	switch method {
	case "status":
		return s.status(), nil
	case "block":
		return s.blockAt(paramsHeight(params))
	case "block_by_hash":
		return s.blockByHash(params.Get("hash"))
	case "block_results":
		return s.blockResults(paramsHeight(params))
	case "commit":
		return s.commitAt(paramsHeight(params))
	case "validators":
		return s.validators(paramsHeight(params)), nil
	case "block_search":
		return s.blockSearch(params.Get("query"), params.Get("order_by"))
	case "tx_search":
		return s.txSearch(params.Get("query"))
	case "tx":
		return s.txByHash(params.Get("hash"))
	case "broadcast_tx_async", "broadcast_tx_sync", "broadcast_tx_commit":
		return s.broadcast(method, params.Get("tx"))
	case "abci_query":
		return s.abciQuery(params)
	}
	return nil, fmt.Errorf("unknown method %q", method)
}
