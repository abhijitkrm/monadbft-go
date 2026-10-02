package bridge

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	abcitypes "github.com/cometbft/cometbft/abci/types"

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
	// mu guards events+lastErrs: SendTransaction is called from outside the
	// node loop (RPC submission); Ready/Next/Exec run on the loop.
	mu       sync.Mutex
	events   []glue.MonadEvent
	lastErrs []error
	wake     func()
	// diagnostic: count of forwarded-tx batches received from peers
	fwdBatches atomic.Int64
}

var _ swarm.TxPool = (*TxPool)(nil)

func NewTxPool(app *App) *TxPool { return &TxPool{app: app} }

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
		Txs:                reap.Txs,
		MaxTxBytes:         int64(c.ProposalByteLimit),
		Height:             t.app.StoreTip() + 1,
		Time:               time.Unix(0, int64(c.TimestampNs.Uint64())),
		ProposerAddress:    t.app.ConsAddr(c.NodeId),
		LocalLastCommit:    t.app.LocalLastCommit(c.HighQC),
		NextValidatorsHash: t.app.ValidatorsHash(),
	})
	t.app.opMu.Unlock()
	if err != nil {
		panic(fmt.Sprintf("bridge: PrepareProposal r=%d seq=%d: %v", c.Round, c.SeqNum, err))
	}
	if uint64(len(res.Txs)) > c.TxLimit {
		res.Txs = res.Txs[:c.TxLimit]
	}

	t.mu.Lock()
	t.events = append(t.events, glue.EvMempoolProposal{
		Epoch:          c.Epoch,
		Round:          c.Round,
		SeqNum:         c.SeqNum,
		HighQC:         c.HighQC,
		TimestampNs:    c.TimestampNs,
		RoundSignature: c.RoundSignature,

		BaseFee:       swarm.MinBaseFee,
		BaseFeeTrend:  swarm.GenesisBaseFeeTrend,
		BaseFeeMoment: swarm.GenesisBaseFeeMoment,

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
