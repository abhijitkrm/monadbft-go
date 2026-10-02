package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/abhijitkrm/monadbft-go/glue"
	"github.com/abhijitkrm/monadbft-go/store"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/wal"

	"github.com/abhijitkrm/monadbft-go/bridge"
)

func main() {
	if os.Args[1] == "-blocks" {
		dumpBlocks(os.Args[2])
		return
	}
	r, err := wal.NewReader(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer r.Close()
	raws, err := r.ReadAllRaw()
	if err != nil {
		panic(err)
	}
	n := len(raws)
	start, end := 0, n
	if len(os.Args) > 2 && os.Args[2] != "" {
		fmt.Sscanf(os.Args[2], "%d", &start)
		if len(os.Args) > 3 {
			fmt.Sscanf(os.Args[3], "%d", &end)
		} else {
			end = start + 100
		}
	} else if n > 100 {
		start = n - 100
	}
	if end > n {
		end = n
	}
	fmt.Printf("total events: %d; window [%d,%d):\n", n, start, end)
	for i := start; i < end; i++ {
		ev, err := glue.DeserializeLogFriendly(raws[i], bridge.Evm)
		if err != nil {
			fmt.Printf("%d: <decode err %v> (%d bytes)\n", i, err, len(raws[i]))
			continue
		}
		if strings.Contains(fmt.Sprintf("%T", ev.Event), "TimestampUpdate") {
			continue
		}
		fmt.Printf("%d %s %T ", i, ev.Timestamp.Format("15:04:05.000"), ev.Event)
		if m, ok := ev.Event.(glue.EvConsensusMessage); ok {
			u := m.UnverifiedMessage.Obj.Message
			switch {
			case u.Proposal != nil:
				fmt.Printf("PROPOSAL r=%d seq=%d\n", u.Proposal.ProposalRound, u.Proposal.Tip.BlockHeader.SeqNum)
			case u.Vote != nil:
				fmt.Printf("VOTE r=%d\n", u.Vote.Vote.Round)
			case u.Timeout != nil:
				fmt.Printf("TIMEOUT r=%d\n", u.Timeout.Timeout.TmInfo.Round)
			default:
				fmt.Printf("kind=%d\n", u.Kind)
			}
			continue
		}
		if t, ok := ev.Event.(glue.EvConsensusTimeout); ok {
			fmt.Printf("local-timeout r=%d\n", t.Round)
			continue
		}
		if r, ok := ev.Event.(glue.EvBlockSyncSelfResponse); ok {
			fmt.Printf("self-resp %+v\n", r.Response)
			continue
		}
		if r, ok := ev.Event.(glue.EvBlockSyncTimeout); ok {
			fmt.Printf("bsync-timeout req=%+v\n", r.Request)
			continue
		}
		fmt.Printf("%+v\n", ev.Event)
	}
}

func dumpBlocks(dir string) {
	bs, err := store.OpenBlockStore(dir, bridge.Evm)
	if err != nil {
		panic(err)
	}
	defer bs.Close()
	blocks, err := bs.AllBlocks()
	if err != nil {
		panic(err)
	}
	fmt.Printf("total blocks: %d\n", len(blocks))
	// find target
	target := os.Args[3]
	byParent := map[string][]uint64{}
	for _, b := range blocks {
		p := fmt.Sprintf("%x", b.GetParentId())
		byParent[p[:len(target)]] = append(byParent[p[:len(target)]], b.GetSeqNum().Uint64())
	}
	for _, b := range blocks {
		id := fmt.Sprintf("%x", b.GetId())
		mark := ""
		if len(id) >= len(target) && id[:len(target)] == target {
			mark = " <== WANTED"
		}
		if kids := byParent[target]; mark == "" && len(kids) > 0 && len(os.Args) > 3 {
			_ = kids
		}
		if b.GetSeqNum() > 250 || mark != "" {
			fmt.Printf("seq=%d id=%s parent=%s%s\n",
				b.GetSeqNum(), id[:16], fmt.Sprintf("%x", b.GetParentId())[:16], mark)
		}
	}
	fmt.Printf("children of target %s: %v\n", target, byParent[target])
	var tid types.BlockId
	tb, _ := hex.DecodeString(strings.TrimPrefix(target, "0x"))
	copy(tid[:], tb)
	gb, gerr := bs.GetBlock(tid)
	fmt.Printf("GetBlock(%s): found=%v err=%v\n", target, gb != nil, gerr)

	cp, err := store.LoadCheckpoint(filepath.Dir(dir), bridge.Evm)
	if err != nil {
		panic(err)
	}
	if cp != nil {
		fmt.Printf("checkpoint root raw: %x (len %d)\n", cp.Root[:], len(cp.Root))
		for _, b := range blocks {
			if b.GetId() == cp.Root {
				fmt.Printf("  == root is block seq=%d\n", b.GetSeqNum())
			}
		}
		hc := cp.HighCertificate
		if hc.IsQC {
			qc := hc.GetQC()
			fmt.Printf("highcert QC r=%d block=%s\n", qc.GetRound(), qc.GetBlockId())
		} else if tc := hc.GetTC(); tc != nil {
			fmt.Printf("highcert TC r=%d\n", tc.Round)
			if tc.HighExtend.IsTip {
				fmt.Printf("  tip r=%d block=%s\n", tc.HighExtend.Tip.BlockHeader.BlockRound,
					tc.HighExtend.Tip.BlockHeader.GetId())
			} else if tc.HighExtend.QC != nil {
				fmt.Printf("  tip QC r=%d block=%s\n", tc.HighExtend.QC.GetRound(), tc.HighExtend.QC.GetBlockId())
			}
		}
	}
}
