package swarm

import (
	"fmt"
	"reflect"
)

// SwarmLedgerVerification — Rust swarm_ledger_verification: pull each node's
// finalized ledger and verify them.
func SwarmLedgerVerification(swarm *Nodes, minLedgerLen int) {
	var ledgers [][]FinalizedBlock
	for _, nd := range swarm.OrderedNodes() {
		ledgers = append(ledgers, nd.Executor.Ledger().GetFinalizedBlocks())
	}
	LedgerVerification(ledgers, minLedgerLen)
}

// LedgerVerification — Rust ledger_verification:
//  1. every ledger has >= min_ledger_len blocks
//  2. every ledger is a prefix of the longest ledger
//  3. no ledger lags more than 5 blocks behind the longest
func LedgerVerification(ledgers [][]FinalizedBlock, minLedgerLen int) {
	maxIdx, maxLen := 0, 0
	for i, l := range ledgers {
		if len(l) > maxLen {
			maxIdx, maxLen = i, len(l)
		}
	}
	longest := ledgers[maxIdx]

	for _, ledger := range ledgers {
		if len(ledger) < minLedgerLen {
			panic(fmt.Sprintf("ledger length expected %d actual %d", minLedgerLen, len(ledger)))
		}
		for i, e := range ledger {
			if !reflect.DeepEqual(*e.Block, *longest[i].Block) {
				panic(fmt.Sprintf("ledger diverges at seq %d", e.SeqNum.Uint64()))
			}
		}
		if maxLen-len(ledger) > 5 {
			panic(fmt.Sprintf("ledger lags: max=%d len=%d", maxLen, len(ledger)))
		}
	}
}
