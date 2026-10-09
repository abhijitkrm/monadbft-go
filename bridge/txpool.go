package bridge

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/swarm"
)

// TxPool — swarm.TxPool backed by the app's ABCI mempool seam:
//
//   - CreateProposal → ReapTxs + PrepareProposal (the exact CometBFT flow —
//     CometBFT reaps the app mempool into RequestPrepareProposal.Txs and the
//     proposal handler re-selects)
//   - SendTransaction / InsertForwardedTxs → CheckTx + InsertTx
//   - BlockCommit/EnterRound/Reset → nop (the mempool's own hooks run inside
//     FinalizeBlock)
type TxPool struct {
	app *App
	// ledger — source of finalized-but-not-yet-executed blocks for the
	// in-flight exclusion set (nil → extending blocks only).
	ledger *Ledger
	// mu guards events+lastErrs: SendTransaction is called from outside the
	// node loop (RPC submission); Ready/Next/Exec run on the loop.
	mu       sync.Mutex
	events   []glue.MonadEvent
	lastErrs []error
	wake     func()
	// diagnostic: count of forwarded-tx batches received from peers
	fwdBatches atomic.Int64

	// baseFee triple stamped into proposals (chain params; SetFeeParams
	// overrides the devnet defaults used by tests).
	baseFee       uint64
	baseFeeTrend  uint64
	baseFeeMoment uint64
}

var _ swarm.TxPool = (*TxPool)(nil)

func NewTxPool(app *App) *TxPool {
	return &TxPool{
		app:           app,
		baseFee:       swarm.MinBaseFee,
		baseFeeTrend:  swarm.GenesisBaseFeeTrend,
		baseFeeMoment: swarm.GenesisBaseFeeMoment,
	}
}

// SetFeeParams — the proposal base-fee stamp (must match the chain's
// EvmBlockPolicy expectations or proposals get rejected).
func (t *TxPool) SetFeeParams(baseFee, trend, moment uint64) {
	t.baseFee, t.baseFeeTrend, t.baseFeeMoment = baseFee, trend, moment
}

// SetLedger — wire the ledger for the in-flight exclusion set.
func (t *TxPool) SetLedger(l *Ledger) { t.ledger = l }

// inflightMargin — executed heights still included in the exclusion set,
// covering the window between the app recording a commit and the mempool
// finishing its recheck at that height.
const inflightMargin = 2

// inflightTxs — txs already carried by the chain this proposal extends but
// not yet reflected in the app state the mempool validates against: the
// unfinalized extending blocks plus finalized blocks the app hasn't
// executed. With final-only execution the mempool's view trails the
// proposal frontier by several blocks, so without this every upcoming
// leader (all of which receive forwarded txs) re-proposes the same txs and
// the repeats fail on nonce at execution.
func (t *TxPool) inflightTxs(extending []*cstypes.ConsensusFullBlock) (map[[32]byte]struct{}, int) {
	set := map[[32]byte]struct{}{}
	size := 0
	add := func(b *cstypes.ConsensusFullBlock) {
		body, ok := b.Body.Inner.ExecutionBody.(*EvmBody)
		if !ok {
			return
		}
		for _, tx := range body.Txs {
			h := sha256.Sum256(tx)
			if _, dup := set[h]; !dup {
				set[h] = struct{}{}
				size += len(tx)
			}
		}
	}
	if t.ledger != nil {
		for _, b := range t.ledger.committedAbove(t.app.committedHeight() - inflightMargin) {
			add(b)
		}
	}
	for _, b := range extending {
		add(b)
	}
	return set, size
}

// SetWakeFunc — node.WakeProducer: SendTransaction enqueues ForwardTxs
// events outside the exec loop.
func (t *TxPool) SetWakeFunc(f func()) { t.wake = f }

func (t *TxPool) Exec(cmds []glue.TxPoolCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.TxPoolCreateProposal:
			t.createProposal(c)
		case glue.TxPoolInsertForwardedTxs:
			t.fwdBatches.Add(1)
			t.insertTxs(c.Txs)
		case glue.TxPoolBlockCommit, glue.TxPoolReset, glue.TxPoolEnterRound:
			// nop — mempool lifecycle hooks run inside the app's
			// FinalizeBlock (evmd wires them via SetPrepareCheckStater).
		}
	}
}

// createProposal — reap + PrepareProposal, then emit EvMempoolProposal with
// the selected txs as the block body.
func (t *TxPool) createProposal(c glue.TxPoolCreateProposal) {
	ctx := context.Background()
	inflight, inflightBytes := t.inflightTxs(c.ExtendingBlocks)

	// opMu: ReapTxs+PrepareProposal must not interleave with a spec commit.
	t.app.opMu.Lock()
	reap, err := t.app.app.ReapTxs(ctx, &abcitypes.RequestReapTxs{
		MaxBytes: c.ProposalByteLimit,
		MaxGas:   c.ProposalGasLimit,
	})
	if err != nil {
		t.app.opMu.Unlock()
		panic(fmt.Sprintf("bridge: ReapTxs r=%d seq=%d: %v", c.Round, c.SeqNum, err))
	}

	// Height is the store's next height (store tip + 1), NOT the consensus
	// seqnum: the mempool selects txs validated at the latest committed
	// state (selectHeight = req.Height-1). MonadBFT pipelines proposals ~2
	// seqs ahead of finalization, so passing the seqnum would make the
	// mempool wait on a height that can only commit via this very proposal
	// — a deadlock. With speculative execution the store tip runs ahead of
	// the canonicalized height — those heights are committed to the store,
	// so they're the right validation context (and it keeps req.Height away
	// from initialHeight, whose SDK path reads a finalize slot that Commit
	// clears). ReapNewValidTxs returns only unreaped txs, so in-flight
	// proposals stay disjoint.
	res, err := t.app.app.PrepareProposal(ctx, &abcitypes.RequestPrepareProposal{
		Txs: reap.Txs,
		// Selection runs over the mempool's pending set at the executed
		// height, which still contains the in-flight txs (lowest nonces,
		// selected first): widen the budget by their size so filtering
		// them out below doesn't starve the block.
		MaxTxBytes:         int64(c.ProposalByteLimit) + int64(inflightBytes),
		Height:             t.app.StoreTip() + 1,
		Time:               time.Unix(0, int64(c.TimestampNs.Uint64())),
		ProposerAddress:    t.app.ConsAddr(c.NodeId),
		LocalLastCommit:    t.app.LocalLastCommitWith(c.HighQC, t.app.ValSetAt(int64(c.SeqNum)-1)),
		NextValidatorsHash: t.app.valSetHashAt(int64(c.SeqNum)),
	})
	t.app.opMu.Unlock()
	if err != nil {
		panic(fmt.Sprintf("bridge: PrepareProposal r=%d seq=%d: %v", c.Round, c.SeqNum, err))
	}
	res.Txs = trimProposal(res.Txs, inflight, c.TxLimit, c.ProposalByteLimit)

	t.mu.Lock()
	t.events = append(t.events, glue.EvMempoolProposal{
		Epoch:          c.Epoch,
		Round:          c.Round,
		SeqNum:         c.SeqNum,
		HighQC:         c.HighQC,
		TimestampNs:    c.TimestampNs,
		RoundSignature: c.RoundSignature,

		BaseFee:       t.baseFee,
		BaseFeeTrend:  t.baseFeeTrend,
		BaseFeeMoment: t.baseFeeMoment,

		DelayedExecutionResults: c.DelayedExecutionResults,
		ProposedExecutionInputs: glue.ProposedExecutionInputs{
			Header: &EvmProposedHeader{},
			Body:   &EvmBody{Txs: res.Txs},
		},

		LastRoundTC:              c.LastRoundTC,
		FreshProposalCertificate: c.FreshProposalCertificate,
	})
	t.mu.Unlock()
}

// trimProposal — drop in-flight txs, then cap to the proposal tx/byte
// limits (selection order preserved).
func trimProposal(txs [][]byte, inflight map[[32]byte]struct{}, txLimit, byteLimit uint64) [][]byte {
	out := txs[:0:0]
	var bytes uint64
	for _, tx := range txs {
		if _, dup := inflight[sha256.Sum256(tx)]; dup {
			continue
		}
		if uint64(len(out)) >= txLimit || bytes+uint64(len(tx)) > byteLimit {
			break
		}
		out = append(out, tx)
		bytes += uint64(len(tx))
	}
	return out
}

// insertTxs — CheckTx + InsertTx; returns the txs that landed in the pool.
// Failures are captured in lastErrs for diagnostics (and dropped otherwise —
// the mempool legitimately rejects txs). Caller must not hold mu.
func (t *TxPool) insertTxs(txs [][]byte) [][]byte {
	ctx := context.Background()
	var inserted [][]byte
	for _, tx := range txs {
		// CheckTx+InsertTx under one opMu hold (spec commits can't
		// interleave between validation and insertion).
		err := func() error {
			t.app.opMu.Lock()
			defer t.app.opMu.Unlock()
			res, err := t.app.app.CheckTx(ctx, &abcitypes.RequestCheckTx{
				Tx:   tx,
				Type: abcitypes.CheckTxType_New,
			})
			if err != nil {
				return err
			}
			if res.Code != 0 {
				return fmt.Errorf("CheckTx code=%d: %s", res.Code, res.Log)
			}
			_, err = t.app.app.InsertTx(ctx, &abcitypes.RequestInsertTx{Tx: tx})
			return err
		}()
		if err != nil {
			t.errf("submit: %v", err)
			continue
		}
		inserted = append(inserted, tx)
	}
	return inserted
}

func (t *TxPool) errf(format string, args ...any) {
	t.mu.Lock()
	t.lastErrs = append(t.lastErrs, fmt.Errorf(format, args...))
	t.mu.Unlock()
}

// LastErrs — recent CheckTx/InsertTx failures (test diagnostics).
func (t *TxPool) LastErrs() []error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]error(nil), t.lastErrs...)
}

// ForwardedBatches — count of peer-forwarded tx batches ingested.
func (t *TxPool) ForwardedBatches() int { return int(t.fwdBatches.Load()) }

// Forwarding caps — upstream: MAX_FORWARDED_TXS_PER_MESSAGE and
// egress_max_size_bytes = 2*max_code_size + 128KiB (evmd default
// MaxCodeSize = 24KiB).
const (
	maxForwardedTxsPerMessage = 5000
	maxForwardBatchBytes      = 2*24_576 + 128*1024
)

// SendTransaction — swarm.TxPool: inject a tx into the mempool, then queue
// EvMempoolForwardTxs batches for the upcoming leaders (upstream: owned
// txs are owned+forwardable; forwarded txs are never re-forwarded).
func (t *TxPool) SendTransaction(tx []byte) {
	inserted := t.insertTxs([][]byte{tx})
	if len(inserted) == 0 {
		return
	}
	t.enqueueForward(inserted)
}

// SubmitTx — the RPC broadcast path: CheckTx + InsertTx + forward enqueue,
// returning the CheckTx outcome for the sync-response. Errors are the
// CheckTx failure (code/log) or a transport-level error, matching
// CometBFT's broadcast_tx_sync semantics.
func (t *TxPool) SubmitTx(tx []byte) (uint32, string, error) {
	ctx := context.Background()
	t.app.opMu.Lock()
	res, err := t.app.app.CheckTx(ctx, &abcitypes.RequestCheckTx{
		Tx:   tx,
		Type: abcitypes.CheckTxType_New,
	})
	if err != nil {
		t.app.opMu.Unlock()
		return 0, "", err
	}
	if res.Code != 0 {
		t.app.opMu.Unlock()
		return res.Code, res.Log, nil
	}
	if _, err := t.app.app.InsertTx(ctx, &abcitypes.RequestInsertTx{Tx: tx}); err != nil {
		t.app.opMu.Unlock()
		return 0, "", err
	}
	t.app.opMu.Unlock()
	t.enqueueForward([][]byte{tx})
	return 0, "", nil
}

// enqueueForward — queue EvMempoolForwardTxs batches for the upcoming
// leaders under the upstream size caps.
func (t *TxPool) enqueueForward(inserted [][]byte) {
	var batch [][]byte
	batchBytes := 0
	flush := func() {
		if len(batch) > 0 {
			t.events = append(t.events, glue.EvMempoolForwardTxs{Txs: batch})
			batch, batchBytes = nil, 0
		}
	}
	for _, tx := range inserted {
		if len(tx) > maxForwardBatchBytes {
			continue // upstream logs + drops oversized
		}
		if len(batch) == maxForwardedTxsPerMessage || batchBytes+len(tx) > maxForwardBatchBytes {
			flush()
		}
		batch = append(batch, tx)
		batchBytes += len(tx)
	}
	t.mu.Lock()
	flush()
	t.mu.Unlock()
	if t.wake != nil {
		t.wake()
	}
}

func (t *TxPool) Ready() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.events) > 0
}

func (t *TxPool) Next() glue.MonadEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.events) == 0 {
		return nil
	}
	ev := t.events[0]
	t.events = t.events[1:]
	return ev
}
