package monadbft_test

import (
	"sort"
	"strconv"

	gethsecp "github.com/ethereum/go-ethereum/crypto/secp256k1"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/rlp"
	"github.com/abhijitkrm/monadbft-go/types"
)

type streamT = rlp.Stream

func streamOf(b []byte) *rlp.Stream { return rlp.NewStream(b) }

func decodeExact(b []byte, fn func(*rlp.Stream) error) error {
	return rlp.DecodeExact(b, fn)
}

func bytes32(v byte) types.BlockId {
	var b types.BlockId
	for i := range b {
		b[i] = v
	}
	return b
}

func sortNodeIds(ns []types.NodeId) {
	sort.Slice(ns, func(i, j int) bool { return ns[i].Cmp(ns[j]) < 0 })
}

func itoa(i int) string { return strconv.Itoa(i) }

// uncompressedPubkey returns the 65-byte uncompressed form (Rust PubKey::bytes()).
func uncompressedPubkey(pk crypto.SecpPubKey) []byte {
	x, y := gethsecp.DecompressPubkey(pk[:])
	if x == nil {
		panic("bad pubkey")
	}
	return gethsecp.S256().Marshal(x, y)
}
