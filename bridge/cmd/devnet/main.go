// devnet — multi-node MonadBFT devnet tooling: scaffold N validator homes
// via `evmd testnet init-files`, then lay the MonadBFT consensus files on
// top (monad.key.json per node, shared validators.json + peers.json, and a
// per-node monadbft.json), and run the fleet as local evmd processes.
//
//	devnet init-files -n 4 -o ./devnet -transport tcp -chain-id monad-1
//	devnet start -o ./devnet
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	cmted25519 "github.com/cometbft/cometbft/crypto/ed25519"

	"github.com/abhijitkrm/monadbft-go/bridge"
	"github.com/abhijitkrm/monadbft-go/node"
)

// port layout per node i on a single host (JSON-RPC/gRPC bases are offset
// from the well-known 8545/9090 to coexist with any locally running node)
const (
	tcpBase     = 9000
	udpBase     = 8000
	authBase    = 9500
	metricsBase = 9100
	jsonRPCBase = 8645
	rpcBase     = 36657 // CometBFT-compat JSON-RPC (off 26657 to dodge collisions)
	grpcBase    = 9190
	grpcWebBase = 9990
	wsBase      = 8746
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init-files":
		err = cmdInitFiles(os.Args[2:])
	case "start":
		err = cmdStart(os.Args[2:])
	case "soak":
		err = cmdSoak(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "devnet:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  devnet init-files -n 4 -o ./devnet [-evmd evmd] [-transport tcp|raptorcast|none] [-chain-id monad-1]
  devnet start      -o ./devnet [-evmd evmd]
  devnet soak       -o ./devnet [-evmd evmd] [-rate 500] [-duration 3m] [-kill 2] [-kill-after 45s]
`)
}

func evmdBin(flagPath string) (string, error) {
	if flagPath != "" {
		return flagPath, nil
	}
	return exec.LookPath("evmd")
}

func cmdInitFiles(args []string) error {
	fs := flag.NewFlagSet("init-files", flag.ExitOnError)
	n := fs.Int("n", 4, "number of validators")
	out := fs.String("o", "./devnet", "output directory")
	evmd := fs.String("evmd", "", "path to evmd binary (default: PATH lookup)")
	transport := fs.String("transport", "tcp", "consensus transport: tcp|raptorcast|none")
	chainID := fs.String("chain-id", "monad-1", "genesis chain-id")
	advertise := fs.String("ip", "127.0.0.1", "advertise address written into peer records")
	fund := fs.Int("fund", 0, "also write N funded soak accounts into genesis + soak-keys.json")
	fundAmt := fs.String("fund-amount", "1000000000000000000000000", "balance per funded account (atest)")
	engine := fs.String("engine", engineMonad, "consensus engine: monadbft|comet (comet = stock CometBFT baseline)")
	commitTimeout := fs.Duration("comet-commit-timeout", 300*time.Millisecond,
		"comet only: consensus.timeout_commit (the evmd scaffold default is 5s — a straw-man baseline)")
	signedWindow := fs.Int("signed-blocks-window", 10000, "x/slashing signed_blocks_window")
	minSigned := fs.String("min-signed-per-window", "0.050000000000000000", "x/slashing min_signed_per_window")
	fs.Parse(args)
	if *engine != engineMonad && *engine != engineComet {
		return fmt.Errorf("bad -engine %q (monadbft|comet)", *engine)
	}

	bin, err := evmdBin(*evmd)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(*advertise)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("-ip must be IPv4: %q", *advertise)
	}
	if *transport != "tcp" && *transport != "raptorcast" && *transport != "none" {
		return fmt.Errorf("bad -transport %q", *transport)
	}

	// 1. evmd scaffolds the SDK-side homes (genesis, gentxs, keys, comet
	//    priv_validator keys) under <out>/node{i}/evmd.
	initArgs := []string{
		"testnet", "init-files",
		"--validator-count", fmt.Sprint(*n),
		"--output-dir", *out,
		"--chain-id", *chainID,
		"--keyring-backend", "test",
		"--single-host",
		// scaffolded config.toml defaults db_backend=rocksdb, which this
		// build doesn't compile — pin a backend that exists
		"--config-changes", "db_backend=goleveldb",
		// the EVM mempool requires comet's app-side mempool type (evmd
		// refuses to start with the scaffold's default "flood")
		"--config-changes", "mempool.type=app",
		"--commit-timeout", commitTimeout.String(),
	}
	c := exec.Command(bin, initArgs...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("evmd testnet init-files: %w", err)
	}

	// 2. Per node: monad consensus keys + read the comet priv_validator
	//    pubkey for the binding.
	bindings := make([]bridge.ValidatorBinding, 0, *n)
	peers := make([]node.BootstrapPeerConfig, 0, *n)
	for i := 0; i < *n; i++ {
		home := filepath.Join(*out, fmt.Sprintf("node%d", i), "evmd")
		cfgDir := filepath.Join(home, "config")

		secp, bls, err := bridge.LoadOrGenMonadKey(filepath.Join(cfgDir, "monad.key.json"))
		if err != nil {
			return fmt.Errorf("node%d monad key: %w", i, err)
		}
		consPub, err := readConsPubKey(filepath.Join(cfgDir, "priv_validator_key.json"))
		if err != nil {
			return fmt.Errorf("node%d: %w", i, err)
		}
		bindings = append(bindings, bridge.ValidatorBinding{
			ConsPubKey: hex.EncodeToString(consPub[:]),
			SecpPubKey: hex.EncodeToString(secp.PubKey().Bytes()),
			BlsPubKey:  hex.EncodeToString(bls.PubKey().Compress()),
		})

		peers = append(peers, node.SelfBootstrapPeer(
			secp, ip,
			uint16(tcpBase+i), uint16(udpBase+i), uint16(authBase+i),
			uint16(udpBase+i), uint16(tcpBase+i), // direct_udp, encrypted_tcp
			1, // record_seq_num
		))
	}

	// 3. Shared files at the devnet root.
	if err := bridge.WriteValidators(filepath.Join(*out, "validators.json"), bindings); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "peers.json"), append(raw, '\n'), 0o644); err != nil {
		return err
	}

	// 4. Per-node monadbft.json (sibling-relative paths resolved from
	//    <home>/config → ../../validators.json).
	for i := 0; i < *n; i++ {
		cfg := bridge.DefaultEngineConfig()
		cfg.Transport = *transport
		cfg.TCPAddress = fmt.Sprintf("%s:%d", ip, tcpBase+i)
		cfg.UDPPort = udpBase + i
		cfg.AuthPort = authBase + i
		cfg.MetricsAddr = fmt.Sprintf("127.0.0.1:%d", metricsBase+i)
		cfg.RPCAddr = fmt.Sprintf("127.0.0.1:%d", rpcBase+i)
		cfg.RPCRatePerSec = -1                          // loopback-bound devnet RPC: unlimited, like comet's
		cfg.AdvertiseIP = ip.String()                   // self name-record addr (raptorcast)
		cfg.ValidatorsFile = "../../../validators.json" // root/config/../../../ = <out>/
		cfg.PeersFile = "../../../peers.json"
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return err
		}
		p := filepath.Join(*out, fmt.Sprintf("node%d", i), "evmd", "config", "monadbft.json")
		if err := os.WriteFile(p, append(raw, '\n'), 0o644); err != nil {
			return err
		}
		// per-node WS JSON-RPC port (app.toml, no start flag exists)
		appToml := filepath.Join(*out, fmt.Sprintf("node%d", i), "evmd", "config", "app.toml")
		if err := replaceLine(appToml, "ws-address = ",
			fmt.Sprintf(`ws-address = "127.0.0.1:%d"`, wsBase+i)); err != nil {
			return err
		}
	}

	if *engine == engineComet {
		// Comet RPC on the same per-node port the monadbft shim uses, so
		// soak/bench drive both engines identically.
		for i := 0; i < *n; i++ {
			cfgToml := filepath.Join(*out, fmt.Sprintf("node%d", i), "evmd", "config", "config.toml")
			if err := setTOML(cfgToml, "rpc", "laddr", fmt.Sprintf(`"tcp://127.0.0.1:%d"`, rpcBase+i)); err != nil {
				return err
			}
		}
	}
	if err := os.WriteFile(filepath.Join(*out, "engine"), []byte(*engine+"\n"), 0o644); err != nil {
		return err
	}
	// Downtime slashing tuned for QC semantics (both engines, so baselines
	// share genesis): a MonadBFT QC carries only the first 2f+1 votes, so
	// honest validators are routinely absent from DecidedLastCommit. A long
	// window + low floor still jails a validator that is actually offline.
	for i := 0; i < *n; i++ {
		g := filepath.Join(*out, fmt.Sprintf("node%d", i), "evmd", "config", "genesis.json")
		if err := setSlashingParams(g, *signedWindow, *minSigned); err != nil {
			return fmt.Errorf("node%d genesis: %w", i, err)
		}
	}

	if *fund > 0 {
		if err := fundSoakAccounts(*out, *fund, *fundAmt); err != nil {
			return fmt.Errorf("fund soak accounts: %w", err)
		}
		fmt.Printf("devnet: %d soak accounts funded (soak-keys.json)\n", *fund)
	}

	fmt.Printf("devnet: %d validators under %s (engine=%s)\n", *n, *out, *engine)
	fmt.Printf("devnet: start with  devnet start -o %s -evmd %s\n", *out, bin)
	return nil
}

func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	out := fs.String("o", "./devnet", "devnet directory from init-files")
	evmd := fs.String("evmd", "", "path to evmd binary (default: PATH lookup)")
	fs.Parse(args)

	bin, err := evmdBin(*evmd)
	if err != nil {
		return err
	}
	entries, err := filepath.Glob(filepath.Join(*out, "node*", "evmd"))
	if err != nil || len(entries) == 0 {
		return errors.New("no node*/evmd homes found — run init-files first")
	}
	chainID, err := genesisChainID(filepath.Join(entries[0], "config", "genesis.json"))
	if err != nil {
		return err
	}

	procs, err := startNodes(entries, bin, chainID, devnetEngine(*out))
	if err != nil {
		return err
	}
	fmt.Printf("devnet: %d nodes started (Ctrl-C to stop)\n", len(procs))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	for _, p := range procs {
		_ = p.Process.Signal(syscall.SIGTERM)
	}
	for _, p := range procs {
		_ = p.Wait()
	}
	return nil
}

// startOne launches a single evmd node with the per-node port layout.
func startOne(home string, i int, bin, chainID, engine string) (*exec.Cmd, error) {
	args := []string{"start",
		"--home", home,
		"--chain-id", chainID,
		"--json-rpc.address", fmt.Sprintf("127.0.0.1:%d", jsonRPCBase+i),
		"--grpc.address", fmt.Sprintf("localhost:%d", grpcBase+i),
		"--grpc-web.address", fmt.Sprintf("localhost:%d", grpcWebBase+i),
	}
	if engine != engineComet {
		args = append(args, "--engine=monadbft")
	}
	c := exec.Command(bin, args...)
	// Raw output is also appended to <home>/evmd.log (survives restarts;
	// soak scans it for panics after the run).
	logf, err := os.OpenFile(nodeLogPath(home), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("node%d log: %w", i, err)
	}
	c.Stdout = io.MultiWriter(logf, prefixWriter(fmt.Sprintf("node%d ", i), os.Stdout))
	c.Stderr = io.MultiWriter(logf, prefixWriter(fmt.Sprintf("node%d ", i), os.Stderr))
	if err := c.Start(); err != nil {
		logf.Close()
		return nil, fmt.Errorf("node%d: %w", i, err)
	}
	return c, nil
}

func nodeLogPath(home string) string { return filepath.Join(home, "evmd.log") }

const (
	engineMonad = "monadbft"
	engineComet = "comet"
)

// devnetEngine — the engine init-files recorded (monadbft when absent).
func devnetEngine(out string) string {
	raw, err := os.ReadFile(filepath.Join(out, "engine"))
	if err != nil {
		return engineMonad
	}
	return strings.TrimSpace(string(raw))
}

// setTOML — set key = value inside [section] ("" = top-level table, before
// the first header). Fails if the key isn't present there.
func setTOML(path, section, key, value string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	cur := ""
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur = strings.Trim(t, "[]")
			continue
		}
		if cur == section && strings.HasPrefix(t, key+" ") || cur == section && strings.HasPrefix(t, key+"=") {
			lines[i] = key + " = " + value
			return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	return fmt.Errorf("%s: key %q not found in [%s]", path, key, section)
}

// startNodes launches every home; shared by `start` and `soak`.
func startNodes(homes []string, bin, chainID, engine string) ([]*exec.Cmd, error) {
	procs := make([]*exec.Cmd, 0, len(homes))
	for i, home := range homes {
		c, err := startOne(home, i, bin, chainID, engine)
		if err != nil {
			for _, p := range procs {
				_ = p.Process.Kill()
			}
			return nil, err
		}
		procs = append(procs, c)
	}
	return procs, nil
}

// replaceLine rewrites the first TOML line starting with prefix.
func replaceLine(path, prefix, repl string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, prefix) {
			lines[i] = repl
			return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	return fmt.Errorf("%s: no line starting %q", path, prefix)
}

func genesisChainID(path string) (string, error) {
	var g struct {
		ChainID string `json:"chain_id"`
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(raw, &g); err != nil || g.ChainID == "" {
		return "", fmt.Errorf("read chain_id from %s", path)
	}
	return g.ChainID, nil
}

// privValidatorKeyFile — the comet priv_validator_key.json pub_key shape.
type privValidatorKeyFile struct {
	PubKey struct {
		Value string `json:"value"` // base64 ed25519
	} `json:"pub_key"`
}

func readConsPubKey(path string) (cmted25519.PubKey, error) {
	var f privValidatorKeyFile
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	b, err := base64.StdEncoding.DecodeString(f.PubKey.Value)
	if err != nil || len(b) != cmted25519.PubKeySize {
		return nil, fmt.Errorf("%s: bad pub_key", path)
	}
	return cmted25519.PubKey(b), nil
}

// prefixWriter prepends a tag to each line (log multiplexing).
type linePrefixWriter struct {
	tag string
	w   *os.File
	buf []byte
}

func prefixWriter(tag string, w *os.File) *linePrefixWriter {
	return &linePrefixWriter{tag: tag, w: w}
}

func (p *linePrefixWriter) Write(b []byte) (int, error) {
	for _, c := range b {
		if c == '\n' {
			fmt.Fprintf(p.w, "%s| %s\n", p.tag, p.buf)
			p.buf = p.buf[:0]
		} else {
			p.buf = append(p.buf, c)
		}
	}
	return len(b), nil
}

// setSlashingParams — rewrite x/slashing downtime params in a genesis file.
func setSlashingParams(path string, window int, minSigned string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var g map[string]any
	if err := json.Unmarshal(raw, &g); err != nil {
		return err
	}
	app, _ := g["app_state"].(map[string]any)
	sl, _ := app["slashing"].(map[string]any)
	params, _ := sl["params"].(map[string]any)
	if params == nil {
		return errors.New("no app_state.slashing.params")
	}
	params["signed_blocks_window"] = fmt.Sprint(window)
	params["min_signed_per_window"] = minSigned
	out, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
}
