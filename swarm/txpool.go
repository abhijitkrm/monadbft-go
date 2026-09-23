package swarm

import (
	"github.com/abhijitkrm/monadbft-go/exec"
	"github.com/abhijitkrm/monadbft-go/glue"
)

// Base-fee constants — Rust monad_tfm::base_fee. The mock proposal path stamps
// these onto every MempoolEvent::Proposal.
const (
	MinBaseFee           uint64 = 100_000_000_000 // 100 gwei
	GenesisBaseFeeTrend  uint64 = 0
	GenesisBaseFeeMoment uint64 = 0
)

// ByzantineConfig — Rust txpool::ByzantineConfig (test-only faults).
type ByzantineConfig struct {
	NoIncrementSeqNum bool
}

// MockTxPoolExecutor — port of monad-updaters::txpool::MockTxPoolExecutor for
// MockExecutionProtocol: every CreateProposal command produces a canned
// MempoolEvent::Proposal carrying an empty MockExecutionBody.
type MockTxPoolExecutor struct {
	byzantine ByzantineConfig
	events    []glue.MonadEvent // queued MempoolEvent::Proposal
}

var _ EventSource = (*MockTxPoolExecutor)(nil)

func NewMockTxPoolExecutor() *MockTxPoolExecutor {
	return &MockTxPoolExecutor{}
}

// WithByzantine — Rust with_byzantine_config.
func (t *MockTxPoolExecutor) WithByzantine(b ByzantineConfig) *MockTxPoolExecutor {
	t.byzantine = b
	return t
}

// Exec — Rust Executor::exec(TxPoolCommand).
func (t *MockTxPoolExecutor) Exec(cmds []glue.TxPoolCommand) {
	for _, cmd := range cmds {
		switch c := cmd.(type) {
		case glue.TxPoolCreateProposal:
			seqNum := c.SeqNum
			if t.byzantine.NoIncrementSeqNum {
				seqNum = seqNum.Sub(1)
			}
			t.events = append(t.events, glue.EvMempoolProposal{
				Epoch:          c.Epoch,
				Round:          c.Round,
				SeqNum:         seqNum,
				HighQC:         c.HighQC,
				TimestampNs:    c.TimestampNs,
				RoundSignature: c.RoundSignature,

				BaseFee:       MinBaseFee,
				BaseFeeTrend:  GenesisBaseFeeTrend,
				BaseFeeMoment: GenesisBaseFeeMoment,

				DelayedExecutionResults: c.DelayedExecutionResults,
				ProposedExecutionInputs: glue.ProposedExecutionInputs{
					Header: &exec.MockProposedHeader{},
					Body:   &exec.MockBody{},
				},

				LastRoundTC:              c.LastRoundTC,
				FreshProposalCertificate: c.FreshProposalCertificate,
			})
		case glue.TxPoolInsertForwardedTxs:
			panic("MockTxPoolExecutor should never receive txs with MockExecutionProtocol")
		case glue.TxPoolBlockCommit, glue.TxPoolReset, glue.TxPoolEnterRound:
			// nop — Rust matches these to ()
		}
	}
}

// SendTransaction — Rust MockableTxPool::send_transaction (EthTxPool only;
// MockExecutionProtocol txpool rejects forwarded txs).
func (t *MockTxPoolExecutor) SendTransaction(_ []byte) {
	panic("MockTxPoolExecutor should never receive txs with MockExecutionProtocol")
}

func (t *MockTxPoolExecutor) Ready() bool { return len(t.events) > 0 }

// Next — Rust Stream::next → MonadEvent::MempoolEvent.
func (t *MockTxPoolExecutor) Next() glue.MonadEvent {
	if len(t.events) == 0 {
		return nil
	}
	ev := t.events[0]
	t.events = t.events[1:]
	return ev
}
