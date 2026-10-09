// apphash-diff — app-hash divergence triage across stopped evmd homes:
// finds the first height whose multistore commit hash differs between
// nodes and prints the per-module store hashes there.
//
//	apphash-diff [-from 1] [-to 0] <home> <home> [<home>...]
//
// Reads <home>/data/application.db (goleveldb) commit info ("s/<height>").
// The nodes must be stopped (the DB lock is exclusive).
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	dbm "github.com/cosmos/cosmos-db"
	"github.com/cosmos/cosmos-sdk/store/v2/rootmulti"
	"github.com/cosmos/cosmos-sdk/store/v2/types"
)

func main() {
	from := flag.Int64("from", 1, "first height to compare")
	to := flag.Int64("to", 0, "last height (0 = highest common)")
	flag.Parse()
	homes := flag.Args()
	if len(homes) < 2 {
		fmt.Fprintln(os.Stderr, "usage: apphash-diff [-from N] [-to N] <home> <home> [...]")
		os.Exit(2)
	}
	dbs := make([]dbm.DB, len(homes))
	for i, h := range homes {
		db, err := dbm.NewGoLevelDB("application", filepath.Join(h, "data"), nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", h, err)
			os.Exit(1)
		}
		defer db.Close()
		dbs[i] = db
	}
	hi := *to
	if hi == 0 {
		hi = -1
		for _, db := range dbs {
			l := rootmulti.GetLatestVersion(db)
			if hi < 0 || l < hi {
				hi = l
			}
		}
	}
	for h := *from; h <= hi; h++ {
		infos := make([]*types.CommitInfo, len(dbs))
		for i, db := range dbs {
			infos[i] = commitInfo(db, h)
		}
		if infos[0] == nil {
			continue
		}
		diverged := false
		for _, ci := range infos[1:] {
			if ci == nil || !bytes.Equal(ci.Hash(), infos[0].Hash()) {
				diverged = true
			}
		}
		if !diverged {
			continue
		}
		fmt.Printf("first divergence at height %d\n", h)
		for i, ci := range infos {
			if ci != nil {
				fmt.Printf("  %-50s app_hash=%X\n", homes[i], ci.Hash())
			}
		}
		stores := map[string][]string{}
		for i, ci := range infos {
			if ci == nil {
				continue
			}
			for _, si := range ci.StoreInfos {
				for len(stores[si.Name]) < i {
					stores[si.Name] = append(stores[si.Name], "")
				}
				stores[si.Name] = append(stores[si.Name], hex.EncodeToString(si.CommitId.Hash))
			}
		}
		names := make([]string, 0, len(stores))
		for n := range stores {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			hs := stores[n]
			same := true
			for _, x := range hs[1:] {
				if x != hs[0] {
					same = false
				}
			}
			if !same {
				fmt.Printf("  store %-16s DIFFERS:", n)
				for i, x := range hs {
					fmt.Printf(" n%d=%.12s", i, x)
				}
				fmt.Println()
			}
		}
		return
	}
	fmt.Printf("no divergence in heights %d..%d\n", *from, hi)
}

func commitInfo(db dbm.DB, h int64) *types.CommitInfo {
	bz, err := db.Get([]byte(fmt.Sprintf("s/%d", h)))
	if err != nil || bz == nil {
		return nil
	}
	ci := &types.CommitInfo{}
	if err := ci.Unmarshal(bz); err != nil {
		return nil
	}
	return ci
}
