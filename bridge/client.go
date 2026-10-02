package bridge

import (
	"context"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"
	cmtcrypto "github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/crypto/tmhash"
	cmtbytes "github.com/cometbft/cometbft/libs/bytes"
	cmtquery "github.com/cometbft/cometbft/libs/pubsub/query"
	"github.com/cometbft/cometbft/libs/service"
	cmtp2p "github.com/cometbft/cometbft/p2p"
	rpcclient "github.com/cometbft/cometbft/rpc/client"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Client — in-process CometBFT RPC client over the bridge's committed
// state. Satisfies rpcclient.Client so every cosmos-evm consumer (clientCtx,
// json-rpc backend, indexer service, gRPC tx service) works unchanged.
// Read paths serve the committed ledger/results; broadcast goes through the
// bridge mempool (CheckTx + leader forwarding).
type Client struct {
	*service.BaseService

	app    *App
	ledger *Ledger
	pool   *TxPool
	bus    *cmttypes.EventBus
	genDoc *cmttypes.GenesisDoc
	// catchingUp — consensus-side statesync predicate (nil → never).
	catchingUp func() bool
	// selfAddr/selfPub — the local validator's app-side identity for
	// /status validator_info.
	selfAddr []byte
	selfPub  cmtcrypto.PubKey
}

var (
	_ rpcclient.Client = (*Client)(nil)
	_ service.Service  = (*Client)(nil)
)

// NewClient — the engine-facing constructor. catchingUp may be nil.
func NewClient(app *App, ledger *Ledger, pool *TxPool, bus *cmttypes.EventBus,
	genDoc *cmttypes.GenesisDoc, catchingUp func() bool, self *Validator) *Client {
	c := &Client{
		app:        app,
		ledger:     ledger,
		pool:       pool,
		bus:        bus,
		genDoc:     genDoc,
		catchingUp: catchingUp,
	}
	if self != nil {
		c.selfAddr = self.ConsAddr()
		c.selfPub = self.ConsPub
	}
	c.BaseService = service.NewBaseService(nil, "BridgeClient", c)
	return c
}

// -- service.Service — the BaseService impl drives OnStart/OnStop.

func (c *Client) OnStart() error { return nil }
func (c *Client) OnStop()        {}

// -- StatusClient --

func (c *Client) Status(ctx context.Context) (*coretypes.ResultStatus, error) {
	tip := c.app.Height()
	res := &coretypes.ResultStatus{
		NodeInfo: cmtp2p.DefaultNodeInfo{
			DefaultNodeID: cmtp2p.ID(fmt.Sprintf("%x", c.selfAddr)),
			Network:       c.app.ChainID(),
			Moniker:       "monadbft",
		},
		SyncInfo: coretypes.SyncInfo{
			LatestBlockHeight: tip,
			CatchingUp:        c.catchingUp != nil && c.catchingUp(),
		},
		ValidatorInfo: coretypes.ValidatorInfo{
			Address:     c.selfAddr,
			VotingPower: 0,
		},
	}
	if c.selfPub != nil {
		res.ValidatorInfo.PubKey = c.selfPub
	}
	if b := c.ledger.committedBlock(types.SeqNum(uint64(tip))); b != nil {
		blk := c.app.SynthBlock(b)
		res.SyncInfo.LatestBlockHash = blk.Hash()
		res.SyncInfo.LatestBlockTime = blk.Header.Time
		res.SyncInfo.LatestAppHash = blk.Header.AppHash
	}
	if vs := c.app.ValSetAt(tip + 1); vs != nil {
		if _, v := vs.GetByAddress(c.selfAddr); v != nil {
			res.ValidatorInfo.VotingPower = v.VotingPower
		}
	}
	// earliest heights — bridge keeps the full result index today.
	if tip > 0 {
		res.SyncInfo.EarliestBlockHeight = 1
		res.SyncInfo.EarliestAppHash = c.resultAppHash(1)
		res.SyncInfo.EarliestBlockTime = c.blockTime(1)
	}
	return res, nil
}

// -- SignClient --

func (c *Client) Block(ctx context.Context, height *int64) (*coretypes.ResultBlock, error) {
	b, err := c.committedAt(height)
	if err != nil {
		return nil, err
	}
	blk := c.app.SynthBlock(b)
	return &coretypes.ResultBlock{
		BlockID: cmttypes.BlockID{Hash: blk.Hash(),
			PartSetHeader: cmttypes.PartSetHeader{Total: 1, Hash: blk.Hash()}},
		Block: blk,
	}, nil
}

func (c *Client) BlockByHash(ctx context.Context, hash []byte) (*coretypes.ResultBlock, error) {
	tip := c.app.Height()
	for h := tip; h >= 1; h-- {
		b := c.ledger.committedBlock(types.SeqNum(uint64(h)))
		if b == nil {
			continue
		}
		blk := c.app.SynthBlock(b)
		if string(blk.Hash()) == string(hash) {
			return &coretypes.ResultBlock{
				BlockID: cmttypes.BlockID{Hash: blk.Hash(),
					PartSetHeader: cmttypes.PartSetHeader{Total: 1, Hash: blk.Hash()}},
				Block: blk,
			}, nil
		}
	}
	return nil, fmt.Errorf("block not found: %x", hash)
}

func (c *Client) Header(ctx context.Context, height *int64) (*coretypes.ResultHeader, error) {
	b, err := c.committedAt(height)
	if err != nil {
		return nil, err
	}
	hdr := c.app.synthHeader(b)
	return &coretypes.ResultHeader{Header: &hdr}, nil
}

func (c *Client) HeaderByHash(ctx context.Context, hash cmtbytes.HexBytes) (*coretypes.ResultHeader, error) {
	res, err := c.BlockByHash(ctx, hash)
	if err != nil {
		return nil, err
	}
	return &coretypes.ResultHeader{Header: &res.Block.Header}, nil
}

func (c *Client) BlockResults(ctx context.Context, height *int64) (*coretypes.ResultBlockResults, error) {
	seq := c.resolveHeight(height)
	hdr, _, _, txRes, events, updates, ok := c.app.CommittedEntry(seq)
	if !ok || hdr == nil {
		return nil, fmt.Errorf("block results not found at height %d", seq)
	}
	res := &coretypes.ResultBlockResults{
		Height:                seq,
		TxsResults:            txRes,
		FinalizeBlockEvents:   events,
		ValidatorUpdates:      updates,
		ConsensusParamUpdates: c.app.ConsensusParams(),
	}
	return res, nil
}

// Commit — the commit certificate for height h, reconstructed from the
// next block's QC (the QC certifying h lives in h+1's header). A tip-height
// request has no committed successor — return an error there, matching
// CometBFT's "block not yet committed" behavior.
func (c *Client) Commit(ctx context.Context, height *int64) (*coretypes.ResultCommit, error) {
	seq := c.resolveHeight(height)
	next := c.ledger.committedBlock(types.SeqNum(uint64(seq + 1)))
	if next == nil {
		return nil, fmt.Errorf("commit for height %d not available yet", seq)
	}
	cur := c.ledger.committedBlock(types.SeqNum(uint64(seq)))
	if cur == nil {
		return nil, fmt.Errorf("block not found at height %d", seq)
	}
	hdr := c.app.synthHeader(cur)
	commit := c.app.synthCommit(next)
	return &coretypes.ResultCommit{
		SignedHeader:    cmttypes.SignedHeader{Header: &hdr, Commit: commit},
		CanonicalCommit: false,
	}, nil
}

func (c *Client) Validators(ctx context.Context, height *int64, page, perPage *int) (*coretypes.ResultValidators, error) {
	seq := c.resolveHeight(height)
	vs := c.app.ValSetAt(seq)
	if vs == nil {
		return nil, fmt.Errorf("validator set not found at height %d", seq)
	}
	vals := vs.Validators
	total := len(vals)
	start, end := 0, total
	if perPage != nil && *perPage > 0 {
		p := 1
		if page != nil && *page > 0 {
			p = *page
		}
		start = (p - 1) * *perPage
		end = start + *perPage
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}
	}
	return &coretypes.ResultValidators{
		BlockHeight: seq,
		Validators:  append([]*cmttypes.Validator(nil), vals[start:end]...),
		Count:       end - start,
		Total:       total,
	}, nil
}

func (c *Client) Tx(ctx context.Context, hash []byte, prove bool) (*coretypes.ResultTx, error) {
	h, ok := c.app.TxLookup(fmt.Sprintf("%X", hash))
	if !ok {
		return nil, fmt.Errorf("tx %x not found", hash)
	}
	_, _, txs, txRes, _, _, ok := c.app.CommittedEntry(h)
	if !ok {
		return nil, fmt.Errorf("tx %x: height %d result missing", hash, h)
	}
	for i, tx := range txs {
		if string(tmhash.Sum(tx)) == string(hash) {
			var res abcitypes.ExecTxResult
			if i < len(txRes) && txRes[i] != nil {
				res = *txRes[i]
			}
			return &coretypes.ResultTx{
				Hash:     hash,
				Height:   h,
				Index:    uint32(i),
				TxResult: res,
				Tx:       tx,
			}, nil
		}
	}
	return nil, fmt.Errorf("tx %x: index mismatch at height %d", hash, h)
}

// TxSearch — minimal implementation: supports tx.hash='X' point lookups and
// tx.height=N scans (the queries RPC/CLI consumers actually issue).
func (c *Client) TxSearch(ctx context.Context, query string, prove bool,
	page, perPage *int, orderBy string) (*coretypes.ResultTxSearch, error) {
	if _, err := cmtquery.New(query); err != nil {
		return nil, err
	}
	if m := txHashCond.FindStringSubmatch(query); m != nil {
		hash, err := hexDecode(m[1])
		if err != nil {
			return nil, fmt.Errorf("bad tx.hash %q", m[1])
		}
		tx, err := c.Tx(ctx, hash, prove)
		if err != nil {
			return &coretypes.ResultTxSearch{TotalCount: 0}, nil
		}
		return &coretypes.ResultTxSearch{Txs: []*coretypes.ResultTx{tx}, TotalCount: 1}, nil
	}
	if m := txHeightCond.FindStringSubmatch(query); m != nil {
		var height int64
		if _, err := fmt.Sscanf(m[1], "%d", &height); err != nil {
			return nil, fmt.Errorf("bad tx.height %q", m[1])
		}
		_, _, txs, txRes, _, _, ok := c.app.CommittedEntry(height)
		if !ok {
			return &coretypes.ResultTxSearch{TotalCount: 0}, nil
		}
		var out []*coretypes.ResultTx
		for i, tx := range txs {
			var res abcitypes.ExecTxResult
			if i < len(txRes) && txRes[i] != nil {
				res = *txRes[i]
			}
			out = append(out, &coretypes.ResultTx{
				Hash: tmhash.Sum(tx), Height: height,
				Index: uint32(i), TxResult: res, Tx: tx,
			})
		}
		return &coretypes.ResultTxSearch{Txs: out, TotalCount: len(out)}, nil
	}
	return nil, fmt.Errorf("TxSearch: unsupported query %q (supports tx.hash, tx.height)", query)
}

func (c *Client) BlockSearch(ctx context.Context, query string, page, perPage *int,
	orderBy string) (*coretypes.ResultBlockSearch, error) {
	return nil, fmt.Errorf("BlockSearch not implemented")
}

// -- HistoryClient --

func (c *Client) Genesis(ctx context.Context) (*coretypes.ResultGenesis, error) {
	if c.genDoc == nil {
		return nil, fmt.Errorf("genesis doc unavailable")
	}
	return &coretypes.ResultGenesis{Genesis: c.genDoc}, nil
}

func (c *Client) GenesisChunked(ctx context.Context, id uint) (*coretypes.ResultGenesisChunk, error) {
	return nil, fmt.Errorf("genesis chunking unsupported")
}

func (c *Client) BlockchainInfo(ctx context.Context, minHeight, maxHeight int64) (*coretypes.ResultBlockchainInfo, error) {
	tip := c.app.Height()
	if minHeight <= 0 {
		minHeight = 1
	}
	if maxHeight <= 0 || maxHeight > tip {
		maxHeight = tip
	}
	if minHeight > maxHeight {
		return nil, fmt.Errorf("min height %d > max %d", minHeight, maxHeight)
	}
	metas := make([]*cmttypes.BlockMeta, 0, maxHeight-minHeight+1)
	for h := maxHeight; h >= minHeight; h-- {
		b := c.ledger.committedBlock(types.SeqNum(uint64(h)))
		if b == nil {
			continue
		}
		blk := c.app.SynthBlock(b)
		metas = append(metas, &cmttypes.BlockMeta{
			BlockID: cmttypes.BlockID{Hash: blk.Hash(),
				PartSetHeader: cmttypes.PartSetHeader{Total: 1, Hash: blk.Hash()}},
			Header: blk.Header,
			NumTxs: len(blk.Data.Txs),
		})
	}
	return &coretypes.ResultBlockchainInfo{
		LastHeight: tip,
		BlockMetas: metas,
	}, nil
}

// -- NetworkClient --

func (c *Client) NetInfo(ctx context.Context) (*coretypes.ResultNetInfo, error) {
	return &coretypes.ResultNetInfo{
		Listening: true,
		Listeners: []string{},
		Peers:     []coretypes.Peer{},
	}, nil
}

func (c *Client) DumpConsensusState(ctx context.Context) (*coretypes.ResultDumpConsensusState, error) {
	return &coretypes.ResultDumpConsensusState{}, nil
}

func (c *Client) ConsensusState(ctx context.Context) (*coretypes.ResultConsensusState, error) {
	return &coretypes.ResultConsensusState{}, nil
}

func (c *Client) ConsensusParams(ctx context.Context, height *int64) (*coretypes.ResultConsensusParams, error) {
	seq := c.resolveHeight(height)
	res := &coretypes.ResultConsensusParams{
		BlockHeight: seq,
	}
	if p := c.app.ConsensusParams(); p != nil {
		res.ConsensusParams = cmttypes.ConsensusParamsFromProto(*p)
	}
	return res, nil
}

func (c *Client) Health(ctx context.Context) (*coretypes.ResultHealth, error) {
	return &coretypes.ResultHealth{}, nil
}

// -- MempoolClient --

func (c *Client) CheckTx(ctx context.Context, tx cmttypes.Tx) (*coretypes.ResultCheckTx, error) {
	c.app.opMu.Lock()
	defer c.app.opMu.Unlock()
	res, err := c.app.ABCI().CheckTx(ctx, &abcitypes.RequestCheckTx{
		Tx:   tx,
		Type: abcitypes.CheckTxType_New,
	})
	if err != nil {
		return nil, err
	}
	return &coretypes.ResultCheckTx{ResponseCheckTx: *res}, nil
}

// UnconfirmedTxs — the app-side EVM mempool owns pending txs; the bridge
// pool doesn't enumerate them, so report the empty set honestly.
func (c *Client) UnconfirmedTxs(ctx context.Context, limit *int) (*coretypes.ResultUnconfirmedTxs, error) {
	return &coretypes.ResultUnconfirmedTxs{Count: 0, Total: 0, Txs: nil}, nil
}

func (c *Client) NumUnconfirmedTxs(ctx context.Context) (*coretypes.ResultUnconfirmedTxs, error) {
	return c.UnconfirmedTxs(ctx, nil)
}

// -- EventsClient — the synthetic bus answers subscriptions identically to
// CometBFT's in-process path (local.Local.eventsRoutine equivalent).

func (c *Client) Subscribe(ctx context.Context, subscriber, query string,
	outCapacity ...int) (out <-chan coretypes.ResultEvent, err error) {
	if !c.IsRunning() {
		return nil, fmt.Errorf("client not running")
	}
	q, err := cmtquery.New(query)
	if err != nil {
		return nil, fmt.Errorf("invalid query: %w", err)
	}
	outCap := 1
	if len(outCapacity) > 0 {
		outCap = outCapacity[0]
	}
	var sub cmttypes.Subscription
	if outCap > 0 {
		sub, err = c.bus.Subscribe(ctx, subscriber, q, outCap)
	} else {
		sub, err = c.bus.SubscribeUnbuffered(ctx, subscriber, q)
	}
	if err != nil {
		return nil, fmt.Errorf("subscribe: %w", err)
	}
	outc := make(chan coretypes.ResultEvent, outCap)
	go c.eventsRoutine(sub, outc)
	return outc, nil
}

func (c *Client) eventsRoutine(sub cmttypes.Subscription, outc chan<- coretypes.ResultEvent) {
	for {
		select {
		case msg := <-sub.Out():
			outc <- coretypes.ResultEvent{Data: msg.Data(), Events: msg.Events()}
		case <-sub.Canceled():
			return
		case <-c.Quit():
			return
		}
	}
}

func (c *Client) Unsubscribe(ctx context.Context, subscriber, query string) error {
	q, err := cmtquery.New(query)
	if err != nil {
		return err
	}
	return c.bus.Unsubscribe(ctx, subscriber, q)
}

func (c *Client) UnsubscribeAll(ctx context.Context, subscriber string) error {
	return c.bus.UnsubscribeAll(ctx, subscriber)
}

// -- ABCIClient --

func (c *Client) ABCIInfo(ctx context.Context) (*coretypes.ResultABCIInfo, error) {
	res, err := c.app.ABCI().Info(ctx, &abcitypes.RequestInfo{})
	if err != nil {
		return nil, err
	}
	return &coretypes.ResultABCIInfo{Response: *res}, nil
}

func (c *Client) ABCIQuery(ctx context.Context, path string, data cmtbytes.HexBytes) (*coretypes.ResultABCIQuery, error) {
	return c.ABCIQueryWithOptions(ctx, path, data, rpcclient.DefaultABCIQueryOptions)
}

func (c *Client) ABCIQueryWithOptions(ctx context.Context, path string, data cmtbytes.HexBytes,
	opts rpcclient.ABCIQueryOptions) (*coretypes.ResultABCIQuery, error) {
	c.app.opMu.Lock()
	defer c.app.opMu.Unlock()
	height := opts.Height
	if height == 0 {
		// "latest" resolved against the canonical committed tip — not the
		// store version, which a speculative finalize in flight puts
		// transiently ahead of any check/finalize ctx header.
		height = c.app.committedHeight()
	}
	res, err := c.app.ABCI().Query(ctx, &abcitypes.RequestQuery{
		Path:   path,
		Data:   data,
		Height: height,
		Prove:  opts.Prove,
	})
	if err != nil {
		return nil, err
	}
	return &coretypes.ResultABCIQuery{Response: *res}, nil
}

func (c *Client) BroadcastTxAsync(ctx context.Context, tx cmttypes.Tx) (*coretypes.ResultBroadcastTx, error) {
	c.pool.SendTransaction(tx)
	return &coretypes.ResultBroadcastTx{Hash: cmttypes.Tx(tx).Hash()}, nil
}

func (c *Client) BroadcastTxSync(ctx context.Context, tx cmttypes.Tx) (*coretypes.ResultBroadcastTx, error) {
	code, log, err := c.pool.SubmitTx(tx)
	if err != nil {
		return nil, err
	}
	return &coretypes.ResultBroadcastTx{
		Code: code,
		Log:  log,
		Hash: cmttypes.Tx(tx).Hash(),
	}, nil
}

// BroadcastTxCommit — submit then wait for the tx's commit event on the bus.
func (c *Client) BroadcastTxCommit(ctx context.Context, tx cmttypes.Tx) (*coretypes.ResultBroadcastTxCommit, error) {
	code, log, err := c.pool.SubmitTx(tx)
	if err != nil {
		return nil, err
	}
	res := &coretypes.ResultBroadcastTxCommit{
		CheckTx:  abcitypes.ResponseCheckTx{Code: code, Log: log},
		TxResult: abcitypes.ExecTxResult{},
		Hash:     cmttypes.Tx(tx).Hash(),
	}
	if code != 0 {
		return res, nil
	}
	// Wait for the commit event (bounded — the caller's ctx usually carries
	// no deadline, so cap at 30s like comet's subscriber timeout).
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	want := fmt.Sprintf("%X", cmttypes.Tx(tx).Hash())
	sub, err := c.Subscribe(waitCtx, "broadcast-tx-commit",
		cmttypes.QueryForEvent(cmttypes.EventTx).String(), 1)
	if err == nil {
		for {
			select {
			case ev := <-sub:
				if d, ok := ev.Data.(cmttypes.EventDataTx); ok &&
					fmt.Sprintf("%X", cmttypes.Tx(d.Tx).Hash()) == want {
					res.TxResult = d.Result
					res.Height = d.Height
					return res, nil
				}
			case <-waitCtx.Done():
				return res, fmt.Errorf("tx %s commit wait: %w", want, waitCtx.Err())
			}
		}
	}
	// subscription failed — fall back to polling the tx index
	for {
		select {
		case <-waitCtx.Done():
			return res, fmt.Errorf("tx %s commit wait: %w", want, waitCtx.Err())
		case <-time.After(50 * time.Millisecond):
			if h, ok := c.app.TxLookup(want); ok {
				if r, err := c.Tx(ctx, cmttypes.Tx(tx).Hash(), false); err == nil {
					res.TxResult = r.TxResult
					res.Height = h
				}
				return res, nil
			}
		}
	}
}

// -- EvidenceClient — deferred (equivocation evidence is upstream-TODO too).

func (c *Client) BroadcastEvidence(ctx context.Context, ev cmttypes.Evidence) (*coretypes.ResultBroadcastEvidence, error) {
	return nil, fmt.Errorf("evidence broadcast not supported")
}

// -- helpers --

func (c *Client) resolveHeight(height *int64) int64 {
	if height == nil || *height <= 0 {
		return c.app.Height()
	}
	return *height
}

func (c *Client) committedAt(height *int64) (*cstypes.ConsensusFullBlock, error) {
	seq := c.resolveHeight(height)
	b := c.ledger.committedBlock(types.SeqNum(uint64(seq)))
	if b == nil {
		return nil, fmt.Errorf("block not found at height %d (tip %d)", seq, c.app.Height())
	}
	return b, nil
}

func (c *Client) resultAppHash(h int64) []byte {
	if e, _, _, _, _, _, ok := c.app.CommittedEntry(h); ok && e != nil {
		return e.AppHash
	}
	return nil
}

func (c *Client) blockTime(h int64) time.Time {
	if b := c.ledger.committedBlock(types.SeqNum(uint64(h))); b != nil {
		return time.Unix(0, int64(b.Header.TimestampNs.Uint64())).UTC()
	}
	return time.Time{}
}

// hexDecode — odd-tolerance hex decode for query operands (quoted values).
func hexDecode(s string) ([]byte, error) {
	return hex.DecodeString(strings.Trim(s, "'"))
}

var (
	txHashCond   = regexp.MustCompile(`tx\.hash\s*=\s*'([0-9a-fA-F]+)'`)
	txHeightCond = regexp.MustCompile(`tx\.height\s*=\s*'?([0-9]+)'?`)
)
