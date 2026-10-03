//go:build test

package bridge_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"crypto/rand"

	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/gorilla/websocket"

	"github.com/abhijitkrm/monadbft-go/bridge"
	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/types"
)

// testNodeID — synthetic identity for RPC tests that don't inspect self.
func testNodeID(t *testing.T) types.NodeId {
	t.Helper()
	kp, err := crypto.GenerateSecpKeyPair(rand.Reader)
	require.NoError(t, err)
	return types.NewNodeId(kp.PubKey())
}

// rpcGet — JSON-RPC envelope unwrap for the CometBFT shim.
func rpcGet(t *testing.T, base, path string) map[string]any {
	t.Helper()
	res, err := http.Get(base + path)
	require.NoError(t, err)
	defer res.Body.Close()
	var env struct {
		Result json.RawMessage           `json:"result"`
		Error  *struct{ Message string } `json:"error"`
	}
	require.NoError(t, json.NewDecoder(res.Body).Decode(&env))
	require.Nil(t, env.Error, "%s: %v", path, env.Error)
	var out map[string]any
	require.NoError(t, json.Unmarshal(env.Result, &out))
	return out
}

// TestBridgeRPC — the CometBFT-compat shim over a live 4-node bridge swarm:
// /status and /block serve committed state, /validators serves the app set,
// and broadcast_tx_sync routes a real EVM tx into the mempool for
// inclusion; /tx then resolves it by tmhash.
func TestBridgeRPC(t *testing.T) {
	apps, raws, nodes := buildTestnetDelay(t, 4, types.SeqNum(2))
	ids := nodes.SortedKeys()
	runUntil(t, nodes, ids, 6)

	id0 := ids[0]
	node0 := nodes.Node(id0)
	ledger := node0.Executor.Ledger().(*bridge.Ledger)
	pool := node0.Executor.TxPool().(*bridge.TxPool)
	srv := bridge.NewRPCServer(apps[0], ledger, pool, id0.PeerID, "monadbft-bridge-test")
	require.NoError(t, srv.Start("127.0.0.1:0"))
	defer srv.Close()
	base := "http://" + srv.Addr()

	st := rpcGet(t, base, "/status")
	syncInfo := st["sync_info"].(map[string]any)
	require.Equal(t, fmt.Sprint(apps[0].Height()), syncInfo["latest_block_height"])
	require.NotEmpty(t, syncInfo["latest_app_hash"])
	require.Equal(t, false, syncInfo["catching_up"])

	blk := rpcGet(t, base, "/block?height=3")
	header := blk["block"].(map[string]any)["header"].(map[string]any)
	require.Equal(t, "3", header["height"])
	require.Equal(t, "monadbft-bridge-test", header["chain_id"])
	require.NotEmpty(t, header["app_hash"])
	blockID := blk["block_id"].(map[string]any)["hash"].(string)
	byHash := rpcGet(t, base, "/block_by_hash?hash="+blockID)
	require.Equal(t, blockID,
		byHash["block_id"].(map[string]any)["hash"].(string))

	res := rpcGet(t, base, "/block_results?height=3")
	require.Equal(t, "3", res["height"])

	vs := rpcGet(t, base, "/validators?height=3")
	require.Equal(t, "4", vs["count"])
	require.Len(t, vs["validators"], 4)

	cm := rpcGet(t, base, "/commit?height=3")
	commit := cm["signed_header"].(map[string]any)["commit"].(map[string]any)
	require.NotEmpty(t, commit["block_id"])

	// broadcast a real EVM tx, then find it via /tx once committed.
	tx := signTx(t, raws[0], 0,
		common.HexToAddress("0x000000000000000000000000000000000000dEaD"),
		big.NewInt(1_000_000_000_000_000_000))
	txParam := base64.StdEncoding.EncodeToString(tx)
	br := rpcGet(t, base, "/broadcast_tx_sync?tx="+url.QueryEscape(txParam))
	require.Equal(t, float64(0), br["code"], "broadcast: %v", br["log"])
	hash := br["hash"].(string)

	runUntil(t, nodes, ids, 12)
	got := rpcGet(t, base, "/tx?hash="+hash)
	require.Equal(t, hash, got["hash"])
	committedHeight := got["height"].(string)
	require.NotEqual(t, "0", committedHeight)
	decTx, err := base64.StdEncoding.DecodeString(got["tx"].(string))
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(tx), hex.EncodeToString(decTx))
	t.Logf("tx %s committed at height %s via RPC broadcast", hash[:16], committedHeight)

	time.Sleep(10 * time.Millisecond)
}

// TestBridgeRPCWebsocket — WS subscribe/unsubscribe end-to-end on the
// CometBFT dialect: connect, subscribe tm.event='NewBlock', publish on
// the bus, receive the streamed event, unsubscribe.
func TestBridgeRPCWebsocket(t *testing.T) {
	bus := cmttypes.NewEventBus()
	require.NoError(t, bus.Start())
	defer bus.Stop()

	srv := bridge.NewRPCServer(nil, nil, nil, testNodeID(t), "ws-test")
	srv.SetEventBus(bus)
	require.NoError(t, srv.Start("127.0.0.1:0"))
	defer srv.Close()

	wsURL := "ws://" + srv.Addr() + "/websocket"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	require.NoError(t, err)
	defer conn.Close()

	sub := map[string]any{
		"jsonrpc": "2.0", "id": "sub-1", "method": "subscribe",
		"params": map[string]any{"query": "tm.event='NewBlock'"},
	}
	require.NoError(t, conn.WriteJSON(sub))
	var ack map[string]any
	require.NoError(t, conn.ReadJSON(&ack))
	require.Contains(t, ack, "result", "subscribe ack: %v", ack)

	require.NoError(t, bus.PublishEventNewBlock(cmttypes.EventDataNewBlock{
		Block: &cmttypes.Block{Header: cmttypes.Header{Height: 7}},
	}))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	var ev map[string]any
	require.NoError(t, conn.ReadJSON(&ev))
	require.Equal(t, "sub-1", ev["id"])
	res := ev["result"].(map[string]any)
	require.Equal(t, "tm.event='NewBlock'", res["query"])
	require.NotNil(t, res["data"], "event data: %v", ev)

	unsub := map[string]any{
		"jsonrpc": "2.0", "id": "u-1", "method": "unsubscribe",
		"params": map[string]any{"query": "tm.event='NewBlock'"},
	}
	require.NoError(t, conn.WriteJSON(unsub))
	require.NoError(t, conn.ReadJSON(&ack))
	require.Contains(t, ack, "result", "unsubscribe ack: %v", ack)
}

// TestBridgeRPCDumpConsensusState — the snapshot hook feeds round_state.
func TestBridgeRPCDumpConsensusState(t *testing.T) {
	srv := bridge.NewRPCServer(nil, nil, nil, testNodeID(t), "dump-test")
	srv.SetConsStateFunc(func() map[string]any {
		return map[string]any{
			"height": "42", "round": "3", "step": "commit",
			"proposal_block_hash": "ABCD",
		}
	})
	require.NoError(t, srv.Start("127.0.0.1:0"))
	defer srv.Close()

	got := rpcGet(t, "http://"+srv.Addr(), "/dump_consensus_state")
	rs := got["round_state"].(map[string]any)
	require.Equal(t, "42", rs["height"])
	require.Equal(t, "3", rs["round"])
	require.Equal(t, "commit", rs["step"])
}

// TestBridgeRPCHardening — POST body cap and the search endpoints that
// were dispatchable but never routed (block_search/tx_search).
func TestBridgeRPCHardening(t *testing.T) {
	srv := bridge.NewRPCServer(nil, nil, nil, testNodeID(t), "hard-test")
	require.NoError(t, srv.Start("127.0.0.1:0"))
	defer srv.Close()
	base := "http://" + srv.Addr()

	// Oversized POST body → rejected (parse error or conn reset when the
	// server closes early); must not panic/OOM either way.
	big := strings.Repeat("x", 5<<20)
	resp, err := http.Post(base+"/health", "application/json",
		strings.NewReader(`{"method":"health","params":{},"id":1}`+big))
	if err == nil {
		defer resp.Body.Close()
		var env map[string]any
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&env))
		require.Contains(t, env, "error", "oversized body should fail parse")
	} // else: server RST'd mid-upload — also a valid rejection

	// search routes reachable (previously missing from the mux).
	r, err := http.Get(base + "/block_search?query=" +
		url.QueryEscape("block.height>0"))
	require.NoError(t, err)
	defer r.Body.Close()
	// nil app → error is fine, "unknown method" is the failure mode
	var env2 map[string]any
	require.NoError(t, json.NewDecoder(r.Body).Decode(&env2))
	require.NotContains(t, fmt.Sprint(env2), "unknown method")

	// server survived the oversized post — still serving.
	live, err := http.Get(base + "/health")
	require.NoError(t, err)
	live.Body.Close()
}
