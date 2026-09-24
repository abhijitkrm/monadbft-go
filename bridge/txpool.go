package bridge

import (
	"context"
	"fmt"
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
	app    *App
	events []glue.MonadEvent
}

var _ swarm.TxPool = (*TxPool)(nil)

func NewTxPool(app *App) *TxPool { return &TxPool{app: app} }

func (t *TxPool) Exec(cmds []glue.TxPoolCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.TxPoolCreateProposal:
			t.createProposal(c)
		case glue.TxPoolInsertForwardedTxs:
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

	reap, err := t.app.app.ReapTxs(ctx, &abcitypes.RequestReapTxs{
		MaxBytes: c.ProposalByteLimit,
		MaxGas:   c.ProposalGasLimit,
	})
	if err != nil {
		panic(fmt.Sprintf("bridge: ReapTxs r=%d seq=%d: %v", c.Round, c.SeqNum, err))
	}

	// Height is the app's next committed height (committed tip + 1), NOT the
	// consensus seqnum: the mempool selects txs validated at the latest
	// committed state (selectHeight = req.Height-1). MonadBFT pipelines
	// proposals ~2 seqs ahead of finalization, so passing the seqnum would
	// make the mempool wait on a height that can only commit via this very
	// proposal — a deadlock. ReapNewValidTxs returns only unreaped txs, so
	// in-flight proposals stay disjoint.
	res, err := t.app.app.PrepareProposal(ctx, &abcitypes.RequestPrepareProposal{
		Txs:                reap.Txs,
		MaxTxBytes:         int64(c.ProposalByteLimit),
		Height:             t.app.height + 1,
		Time:               time.Unix(0, int64(c.TimestampNs.Uint64())),
		ProposerAddress:    t.app.ConsAddr(c.NodeId),
		LocalLastCommit:    t.app.LocalLastCommit(c.HighQC),
		NextValidatorsHash: t.app.ValidatorsHash(),
	})
	if err != nil {
		panic(fmt.Sprintf("bridge: PrepareProposal r=%d seq=%d: %v", c.Round, c.SeqNum, err))
	}
	if uint64(len(res.Txs)) > c.TxLimit {
		res.Txs = res.Txs[:c.TxLimit]
	}

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
}

// insertTxs — CheckTx + InsertTx (the app-side mempool insert path).
func (t *TxPool) insertTxs(txs [][]byte) {
	ctx := context.Background()
	for _, tx := range txs {
		res, err := t.app.app.CheckTx(ctx, &abcitypes.RequestCheckTx{
			Tx:   tx,
			Type: abcitypes.CheckTxType_New,
		})
		if err != nil || res.Code != 0 {
			continue
		}
		if _, err := t.app.app.InsertTx(ctx, &abcitypes.RequestInsertTx{Tx: tx}); err != nil {
			continue
		}
	}
}

// SendTransaction — swarm.TxPool: inject a tx into the mempool.
func (t *TxPool) SendTransaction(tx []byte) { t.insertTxs([][]byte{tx}) }

func (t *TxPool) Ready() bool { return len(t.events) > 0 }

func (t *TxPool) Next() glue.MonadEvent {
	if len(t.events) == 0 {
		return nil
	}
	ev := t.events[0]
	t.events = t.events[1:]
	return ev
}
