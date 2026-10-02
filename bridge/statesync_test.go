//go:build test

package bridge_test

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/abhijitkrm/monadbft-go/bridge"
	"github.com/abhijitkrm/monadbft-go/cstypes"
	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/sigcol"
	"github.com/abhijitkrm/monadbft-go/types"
)

// evmSyncBlock — a canonical-chain ConsensusFullBlock for sync tests: an
// EvmBody payload and QC parent linkage (the fields the ledger's
// finalizeRequest consumes).
func evmSyncBlock(t *testing.T, seq uint64, parentID types.BlockId, parentRound types.Round, author *bridge.Validator, txs [][]byte) *cstypes.ConsensusFullBlock {
	t.Helper()
	round := types.Round(seq)
	body := cstypes.ConsensusBlockBody{Inner: cstypes.ConsensusBlockBodyInner{
		ExecutionBody: &bridge.EvmBody{Txs: txs},
	}}
	qc := cstypes.QuorumCertificate{
		Info:       cstypes.Vote{ID: parentID, Round: parentRound, Epoch: types.Epoch(1)},
		Signatures: *sigcol.Empty(),
	}
	hdr := cstypes.NewConsensusBlockHeader(
		author.NodeId(), types.Epoch(1), round,
		nil, &bridge.EvmProposedHeader{}, body.GetId(), qc,
		types.SeqNum(seq), types.U128FromUint64(seq*1_000_000_000),
		cstypes.NewRoundSignature(round, author.Bls),
		0, 0, 0,
	)
	fb, err := cstypes.NewFullBlock(hdr, body)
	require.NoError(t, err)
	return &fb
}

// pumpStateSync — relay executor events between two StateSync executors
// until the client emits EvStateSyncDoneSync (or maxRounds is exhausted).
func pumpStateSync(t *testing.T, srvID, cliID types.NodeId, srv, cli *bridge.StateSync) types.SeqNum {
	t.Helper()
	for rounds := 0; rounds < 64; rounds++ {
		progress := false
		for _, side := range []struct {
			src  *bridge.StateSync
			dst  *bridge.StateSync
			self types.NodeId
		}{{cli, srv, cliID}, {srv, cli, srvID}} {
			for side.src.Ready() {
				progress = true
				ev := side.src.Next()
				switch e := ev.(type) {
				case glue.EvStateSyncOutbound:
					if e.To == side.self {
						t.Fatalf("executor emitted a message to itself")
					}
					side.dst.Exec([]glue.StateSyncCommand{
						glue.StateSyncMessage{To: side.self, Message: e.Message},
					})
				case glue.EvStateSyncDoneSync:
					if side.src == cli {
						return e.SeqNum
					}
				default:
					t.Fatalf("unexpected statesync event %T", ev)
				}
			}
		}
		if !progress {
			t.Fatalf("statesync stalled — no events left and no DoneSync")
		}
	}
	t.Fatalf("statesync did not complete within 64 rounds")
	return 0
}

// TestStateSyncReplay — the full statesync executor cycle: a fresh node
// requests the canonical block range from a serving peer, replays it
// through FinalizeBlock+Commit, verifies the synced AppHash, and reports
// DoneSync. Exercises both wire directions over real evmd apps.
func TestStateSyncReplay(t *testing.T) {
	vals := bridge.MakeValidators(4)
	const target = 5

	// Serving node: a canonical chain committed to `target`, with a real
	// EVM tx in block 1 so replay parity is meaningful.
	srv, srvRaw, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	srvLedger := bridge.NewLedger(srv, nil)
	srvSync := bridge.NewStateSync(srv, srvLedger, nil)
	srvID := vals[0].NodeId()
	srvSync.Exec([]glue.StateSyncCommand{glue.StateSyncStartExecution{}})

	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	tx := signTx(t, srvRaw, 0, to, big.NewInt(1_000_000_000_000_000_000))

	var pid types.BlockId // GENESIS_BLOCK_ID (zero)
	pr := types.GENESIS_ROUND
	var last *cstypes.ConsensusFullBlock
	for i := uint64(1); i <= target; i++ {
		var txs [][]byte
		if i == 1 {
			txs = [][]byte{tx}
		}
		b := evmSyncBlock(t, i, pid, pr, &vals[0], txs)
		srvLedger.Exec([]glue.LedgerCommand{glue.LedgerCommit{
			Commit: glue.OptimisticCommit{Kind: glue.CommitProposed, Block: b},
		}})
		pid, pr = b.GetId(), b.GetBlockRound()
		last = b
	}
	srvLedger.Exec([]glue.LedgerCommand{glue.LedgerCommit{
		Commit: glue.OptimisticCommit{Kind: glue.CommitFinalized, Block: last},
	}})
	require.Equal(t, int64(target), srv.Height())
	want := srv.Result(target)
	require.NotNil(t, want)

	// Syncing node: fresh app at genesis, real spec bookkeeping so the
	// post-sync realignment is exercised.
	cli, _, err := bridge.NewEvmdApp(specEvmdCfg(t), vals)
	require.NoError(t, err)
	cliSpec := bridge.NewSpecApp(cli)
	cliLedger := bridge.NewLedger(cli, cliSpec)
	cliSync := bridge.NewStateSync(cli, cliLedger, cliSpec)
	cliID := vals[1].NodeId()

	cliSync.Exec([]glue.StateSyncCommand{
		glue.StateSyncExpandUpstreamPeers{Peers: []types.NodeId{srvID}},
		glue.StateSyncRequestSync{Header: &bridge.EvmFinalizedHeader{
			Number:  types.SeqNum(target),
			AppHash: want.AppHash,
		}},
	})

	done := pumpStateSync(t, srvID, cliID, srvSync, cliSync)
	require.Equal(t, types.SeqNum(target), done)

	require.Equal(t, int64(target), cli.Height())
	got := cli.Result(target)
	require.NotNil(t, got)
	require.Equal(t, want.AppHash, got.AppHash, "synced apphash")
	require.Equal(t, int64(target), cliSpec.SpecTip(), "spec frontier re-anchored")

	// The synced ledger serves its new canonical blocks onward.
	require.NotNil(t, cliLedger.GetFinalizedBlocks())
	require.Equal(t, target, len(cliLedger.GetFinalizedBlocks()))
}
