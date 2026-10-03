// Soak — sustained-load evidence for the release gate. `init-files --fund N`
// writes N funded ethsecp256k1 accounts into every node's genesis plus a
// soak-keys.json at the devnet root; `soak` then runs the network under a
// target tx rate while sampling per-node RSS, disk growth, and committed
// height — optionally SIGKILLing a node mid-run and timing its rejoin.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"

	clienttx "github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"

	"github.com/cosmos/evm/crypto/ethsecp256k1"
	evmencoding "github.com/cosmos/evm/encoding"
	txtest "github.com/cosmos/evm/testutil/tx"
	evmtypes "github.com/cosmos/evm/x/vm/types"
)

const soakDenom = "atest" // evm_denom written by evmd testnet init-files
const soakBech32 = "cosmos"

// soakKey — one funded load-gen account (persisted at the devnet root).
type soakKey struct {
	PrivHex string `json:"priv"`
	Address string `json:"address"` // 20B hex; ethsecp256k1 ⇒ cosmos addr == evm addr
}

func (k soakKey) priv() *ethsecp256k1.PrivKey {
	bz, _ := hex.DecodeString(k.PrivHex)
	return &ethsecp256k1.PrivKey{Key: bz}
}

// fundSoakAccounts — called from init-files after homes exist: generates n
// deterministic funded accounts, injects auth account + bank balance into
// every node's genesis.json, writes <out>/soak-keys.json for soak.
func fundSoakAccounts(out string, n int, amount string) error {
	keys := make([]soakKey, n)
	for i := range keys {
		sum := sha256.Sum256([]byte(fmt.Sprintf("monadbft-devnet-soak-%d", i)))
		k := &ethsecp256k1.PrivKey{Key: sum[:]}
		keys[i] = soakKey{
			PrivHex: hex.EncodeToString(sum[:]),
			Address: hex.EncodeToString(k.PubKey().Address()),
		}
	}
	homes, _ := filepath.Glob(filepath.Join(out, "node*", "evmd"))
	if len(homes) == 0 {
		return fmt.Errorf("no node*/evmd homes under %s", out)
	}
	for _, home := range homes {
		if err := injectGenesisBalances(
			filepath.Join(home, "config", "genesis.json"), keys, amount); err != nil {
			return fmt.Errorf("%s: %w", home, err)
		}
	}
	raw, _ := json.MarshalIndent(keys, "", "  ")
	return os.WriteFile(filepath.Join(out, "soak-keys.json"), append(raw, '\n'), 0o644)
}

// injectGenesisBalances appends BaseAccount + bank Balance entries to the
// shared genesis (identical across nodes).
func injectGenesisBalances(genesisPath string, keys []soakKey, amount string) error {
	raw, err := os.ReadFile(genesisPath)
	if err != nil {
		return err
	}
	var g map[string]any
	if err := json.Unmarshal(raw, &g); err != nil {
		return err
	}
	app := g["app_state"].(map[string]any)
	auth := app["auth"].(map[string]any)
	bank := app["bank"].(map[string]any)
	accs, _ := auth["accounts"].([]any)
	bals, _ := bank["balances"].([]any)
	for _, k := range keys {
		pk := k.priv().PubKey()
		addr := sdk.MustBech32ifyAddressBytes(soakBech32, pk.Address())
		// pub_key stays nil — matches `evmd testnet` accounts; ethsecp256k1
		// identities are recovered from signatures, not the account field.
		accs = append(accs, map[string]any{
			"@type":          "/cosmos.auth.v1beta1.BaseAccount",
			"address":        addr,
			"pub_key":        nil,
			"account_number": "0",
			"sequence":       "0",
		})
		bals = append(bals, map[string]any{
			"address": addr,
			"coins":   []any{map[string]any{"denom": soakDenom, "amount": amount}},
		})
	}
	auth["accounts"] = accs
	bank["balances"] = bals
	// bank.supply must cover the added balances or InitChain panics on the
	// supply invariant check.
	added := new(big.Int)
	if amt, ok := new(big.Int).SetString(amount, 10); ok {
		added.Mul(amt, big.NewInt(int64(len(keys))))
	}
	supply, _ := bank["supply"].([]any)
	found := false
	for _, c := range supply {
		coin := c.(map[string]any)
		if coin["denom"] == soakDenom {
			cur, _ := new(big.Int).SetString(coin["amount"].(string), 10)
			coin["amount"] = new(big.Int).Add(cur, added).String()
			found = true
		}
	}
	if !found {
		supply = append(supply, map[string]any{"denom": soakDenom, "amount": added.String()})
	}
	bank["supply"] = supply
	out, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(genesisPath, out, 0o644)
}

// -- soak runner --

type soakSample struct {
	At            time.Time `json:"at"`
	Heights       []int64   `json:"heights"`
	RSSMB         []int64   `json:"rss_mb"`
	DiskMB        []int64   `json:"disk_mb"`
	AppHashParity bool      `json:"apphash_parity"` // live nodes agree on latest_app_hash
}

type soakReport struct {
	StartedAt    time.Time    `json:"started_at"`
	DurationS    float64      `json:"duration_s"`
	Nodes        int          `json:"nodes"`
	TargetTPS    int          `json:"target_tps"`
	Submitted    int64        `json:"submitted"`
	Rejected     int64        `json:"rejected"`
	Samples      []soakSample `json:"samples"`
	KillNode     int          `json:"kill_node"`
	Restarted    bool         `json:"restarted"`
	Recovered    bool         `json:"recovered_to_tip"`
	RecoverySecs float64      `json:"recovery_secs"`
	// Settle proof — heights keep advancing for settleWait after load stops,
	// showing the mempool drained rather than stalling on the killed node.
	SettleHeights []int64 `json:"settle_heights"`
	FinalHeights  []int64 `json:"final_heights"`
	ParityFails   int     `json:"apphash_parity_fails"`
}

func cmdSoak(args []string) error {
	fs := flag.NewFlagSet("soak", flag.ExitOnError)
	out := fs.String("o", "./devnet", "devnet directory from init-files --fund")
	evmd := fs.String("evmd", "", "path to evmd binary")
	dur := fs.Duration("duration", 3*time.Minute, "soak duration")
	rate := fs.Int("rate", 500, "target submitted tx/s across the fleet")
	killNode := fs.Int("kill", -1, "node index to SIGKILL mid-run (-1 = none)")
	killAfter := fs.Duration("kill-after", 45*time.Second, "when to kill -kill node")
	sampleEvery := fs.Duration("sample", 10*time.Second, "RSS/disk/height cadence")
	reportPath := fs.String("report", "", "write JSON report (default <out>/soak-report.json)")
	fs.Parse(args)

	bin, err := evmdBin(*evmd)
	if err != nil {
		return err
	}
	keys, err := loadSoakKeys(*out)
	if err != nil {
		return err
	}
	homes, _ := filepath.Glob(filepath.Join(*out, "node*", "evmd"))
	if len(homes) == 0 {
		return fmt.Errorf("no node*/evmd homes under %s", *out)
	}
	chainID, err := genesisChainID(filepath.Join(homes[0], "config", "genesis.json"))
	if err != nil {
		return err
	}

	// Hydrate the fork's process globals so tx signing matches the chain.
	if err := evmtypes.SetChainConfig(evmtypes.DefaultChainConfig(0)); err != nil {
		return err
	}
	if err := evmtypes.NewEVMConfigurator().WithEVMCoinInfo(evmtypes.EvmCoinInfo{
		Denom: soakDenom, ExtendedDenom: soakDenom, DisplayDenom: "test",
		Decimals: evmtypes.EighteenDecimals.Uint32(),
	}).Configure(); err != nil {
		return err
	}
	txCfg := evmencoding.MakeConfig(evmtypes.DefaultEVMChainID).TxConfig

	procs, err := startNodes(homes, bin, chainID)
	if err != nil {
		return err
	}
	defer killAll(procs)
	fmt.Printf("soak: %d nodes up, %d funded senders, rate=%d/s, duration=%s\n",
		len(procs), len(keys), *rate, dur)

	if err := waitForTip(*out, 2, 90*time.Second); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *dur)
	defer cancel()

	var submitted, rejected int64
	var wg sync.WaitGroup
	go runLoad(ctx, *out, keys, txCfg, len(homes), *rate, &submitted, &rejected, &wg)

	var samples []soakSample
	rep := soakReport{StartedAt: time.Now().UTC(), TargetTPS: *rate, KillNode: *killNode, Nodes: len(homes)}
	start := time.Now()

	var killed, restarted bool
	var killedAt time.Time

	tick := time.NewTicker(250 * time.Millisecond)
	sampleTick := time.NewTicker(*sampleEvery)
	defer tick.Stop()
	defer sampleTick.Stop()

	for {
		select {
		case <-ctx.Done():
			goto done
		case t := <-sampleTick.C:
			s := collectSample(*out, procs)
			if !s.AppHashParity {
				rep.ParityFails++
			}
			samples = append(samples, s)
			fmt.Printf("soak %4.0fs heights=%v rss_mb=%v disk_mb=%v submitted=%d rejected=%d\n",
				t.Sub(start).Seconds(), s.Heights, s.RSSMB, s.DiskMB,
				atomic.LoadInt64(&submitted), atomic.LoadInt64(&rejected))
		case <-tick.C:
		}
		if !killed && *killNode >= 0 && *killNode < len(procs) && time.Since(start) >= *killAfter {
			p := procs[*killNode]
			fmt.Printf("soak: SIGKILL node%d (pid %d)\n", *killNode, p.Process.Pid)
			_ = p.Process.Signal(syscall.SIGKILL)
			_ = p.Wait()
			killed, killedAt = true, time.Now()
		}
		if killed && !restarted && time.Since(killedAt) >= 3*time.Second {
			newp, err := startOne(homes[*killNode], *killNode, bin, chainID)
			if err != nil {
				fmt.Printf("soak: restart node%d failed: %v\n", *killNode, err)
				killedAt = time.Now() // back off before retrying
			} else {
				procs[*killNode] = newp
				restarted, rep.Restarted = true, true
				fmt.Printf("soak: node%d restarted (pid %d)\n", *killNode, newp.Process.Pid)
			}
		}
		if restarted && !rep.Recovered {
			tip := maxTip(*out)
			if h := nodeHeight(*killNode); tip > 0 && h >= tip-1 {
				rep.Recovered = true
				rep.RecoverySecs = time.Since(killedAt).Seconds()
				fmt.Printf("soak: node%d recovered to tip (h=%d, %.0fs)\n",
					*killNode, h, rep.RecoverySecs)
			}
		}
	}
done:
	cancel()
	wg.Wait()
	// settle: let the mempool drain, then take final heights.
	settleStart := time.Now()
	for time.Since(settleStart) < 10*time.Second {
		hs := make([]int64, len(homes))
		for i := range homes {
			hs[i] = nodeHeight(i)
		}
		rep.SettleHeights = append(rep.SettleHeights, hs...)
		time.Sleep(2 * time.Second)
	}
	for i := range homes {
		rep.FinalHeights = append(rep.FinalHeights, nodeHeight(i))
	}
	rep.Submitted = atomic.LoadInt64(&submitted)
	rep.Rejected = atomic.LoadInt64(&rejected)
	rep.DurationS = time.Since(start).Seconds()
	rep.Samples = samples

	outPath := *reportPath
	if outPath == "" {
		outPath = filepath.Join(*out, "soak-report.json")
	}
	raw, _ := json.MarshalIndent(rep, "", "  ")
	if err := os.WriteFile(outPath, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("soak: report at %s — submitted=%d rejected=%d recovered=%v (%.0fs)\n",
		outPath, rep.Submitted, rep.Rejected, rep.Recovered, rep.RecoverySecs)
	return nil
}

// runLoad — round-robin senders submitting signed transfers at `rate`/s
// spread across node RPC ports. A rejected tx retries its nonce next tick
// so per-sender nonce order never gaps.
func runLoad(ctx context.Context, out string, keys []soakKey, txCfg clienttx.TxConfig,
	nNodes, rate int, submitted, rejected *int64, wg *sync.WaitGroup,
) {
	wg.Add(1)
	defer wg.Done()
	if rate <= 0 || len(keys) == 0 {
		return
	}
	interval := time.Second / time.Duration(rate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	nonces := make([]uint64, len(keys))
	to := common.HexToAddress("0x00000000000000000000000000000000c0ffee01")
	var idx uint64
	tick := time.NewTicker(interval)
	defer tick.Stop()
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			ki := int(idx % uint64(len(keys)))
			idx++
			k := keys[ki].priv()
			msg := evmtypes.NewTx(&evmtypes.EvmTxArgs{
				ChainID:  evmtypes.GetEthChainConfig().ChainID,
				Nonce:    nonces[ki],
				To:       &to,
				Amount:   big.NewInt(1),
				GasLimit: 21_000,
				GasPrice: big.NewInt(1_000_000_000_000),
			})
			msg.From = common.BytesToAddress(k.PubKey().Address().Bytes()).Bytes()
			sdkTx, err := txtest.PrepareEthTx(txCfg, k, msg)
			if err != nil {
				atomic.AddInt64(rejected, 1)
				continue
			}
			bz, err := txCfg.TxEncoder()(sdkTx)
			if err != nil {
				atomic.AddInt64(rejected, 1)
				continue
			}
			u := fmt.Sprintf("http://127.0.0.1:%d/broadcast_tx_async?tx=0x%s",
				rpcBase+(ki%nNodes), hex.EncodeToString(bz))
			resp, err := client.Get(u)
			if err != nil {
				atomic.AddInt64(rejected, 1)
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()
			var env struct {
				Result struct {
					Code int `json:"code"`
				} `json:"result"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(body, &env); err == nil && env.Error == nil && env.Result.Code == 0 {
				atomic.AddInt64(submitted, 1)
				nonces[ki]++
			} else {
				atomic.AddInt64(rejected, 1)
			}
		}
	}
}

// collectSample — RSS (ps) + data-dir size (du) + committed height (/status).
func collectSample(out string, procs []*exec.Cmd) soakSample {
	s := soakSample{At: time.Now().UTC(), AppHashParity: true}
	homes, _ := filepath.Glob(filepath.Join(out, "node*", "evmd"))
	hashes := map[string]int{}
	live := 0
	var lo, hi int64 = -1, -1
	for i, p := range procs {
		s.RSSMB = append(s.RSSMB, procRSS(p)/1024)
		if i < len(homes) {
			s.DiskMB = append(s.DiskMB, dirKB(homes[i])/1024)
		}
		h, ah := nodeStatus(i)
		s.Heights = append(s.Heights, h)
		if ah != "" {
			hashes[ah]++
			live++
			if lo < 0 || h < lo {
				lo = h
			}
			if h > hi {
				hi = h
			}
		}
	}
	// Parity means live nodes agree on latest_app_hash — but only when
	// they're at the same tip height; a lagging restart node legitimately
	// reports an older hash, so skip the check when heights spread > 1.
	if live > 1 && hi-lo <= 1 && len(hashes) > 1 {
		s.AppHashParity = false
	}
	return s
}

func procRSS(p *exec.Cmd) int64 {
	if p == nil || p.Process == nil {
		return 0
	}
	out, err := exec.Command("ps", "-o", "rss=", "-p", strconv.Itoa(p.Process.Pid)).Output()
	if err != nil {
		return -1
	}
	kb, _ := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	return kb
}

func dirKB(path string) int64 {
	out, err := exec.Command("du", "-sk", path).Output()
	if err != nil {
		return -1
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return -1
	}
	kb, _ := strconv.ParseInt(f[0], 10, 64)
	return kb
}

func nodeHeight(i int) int64 {
	h, _ := nodeStatus(i)
	return h
}

// nodeStatus — committed height + latest app hash from /status.
func nodeStatus(i int) (int64, string) {
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/status", rpcBase+i))
	if err != nil {
		return -1, ""
	}
	defer resp.Body.Close()
	var env struct {
		Result struct {
			SyncInfo struct {
				H string `json:"latest_block_height"`
				A string `json:"latest_app_hash"`
			} `json:"sync_info"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return -1, ""
	}
	h, _ := strconv.ParseInt(env.Result.SyncInfo.H, 10, 64)
	return h, env.Result.SyncInfo.A
}

func maxTip(out string) int64 {
	var hi int64
	homes, _ := filepath.Glob(filepath.Join(out, "node*", "evmd"))
	for i := range homes {
		if h := nodeHeight(i); h > hi {
			hi = h
		}
	}
	return hi
}

func waitForTip(out string, h int64, d time.Duration) error {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if nodeHeight(0) >= h {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("tip never reached %d", h)
}

func loadSoakKeys(out string) ([]soakKey, error) {
	raw, err := os.ReadFile(filepath.Join(out, "soak-keys.json"))
	if err != nil {
		return nil, fmt.Errorf("soak-keys.json: %w (run init-files --fund first)", err)
	}
	var keys []soakKey
	return keys, json.Unmarshal(raw, &keys)
}

func killAll(procs []*exec.Cmd) {
	for _, p := range procs {
		if p != nil && p.Process != nil {
			_ = p.Process.Signal(syscall.SIGTERM)
		}
	}
	for _, p := range procs {
		if p != nil {
			_ = p.Wait()
		}
	}
}
