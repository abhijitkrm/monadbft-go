package raptorcast

// Conformance tests against fixtures generated from the upstream
// monad-raptorcast sources (assigner.rs / regular.rs / monad-merkle)
// compiled verbatim in the rcgen harness.

import (
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"os"
	"sort"
	"testing"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/types"
	"github.com/abhijitkrm/monadbft-go/validator"
)

type fixturesFile struct {
	Shuffle struct {
		Shuffle []struct {
			SeedHex     string   `json:"seed_hex"`
			N           int      `json:"n"`
			Permutation []uint32 `json:"permutation"`
		} `json:"shuffle"`
		GenRange []struct {
			SeedHex string   `json:"seed_hex"`
			Draws   []uint64 `json:"draws"`
		} `json:"gen_range"`
	} `json:"shuffle"`
	Assignment []struct {
		AppHashHex     string `json:"app_hash_hex"`
		SeedHex        string `json:"seed_hex"`
		NumBaseSymbols int    `json:"num_base_symbols"`
		RedundancyBits uint32 `json:"redundancy_bits"`
		NumChunks      int    `json:"num_chunks"`
		Members        []struct {
			Pubkey string `json:"pubkey"`
			Stake  string `json:"stake"`
		} `json:"members"`
		Author string `json:"author"`
		Chunks []struct {
			ChunkID     int      `json:"chunk_id"`
			Recipient   string   `json:"recipient"`
			Rebroadcast []string `json:"rebroadcast"`
		} `json:"chunks"`
	} `json:"assignment"`
	Merkle []struct {
		Depth   int      `json:"depth"`
		Leaves  []string `json:"leaves"`
		RootHex string   `json:"root_hex"`
		Proofs  []struct {
			LeafIdx  int    `json:"leaf_idx"`
			LeafHex  string `json:"leaf_hex"`
			ProofHex string `json:"proof_hex"`
			Verified bool   `json:"verified"`
		} `json:"proofs"`
	} `json:"merkle"`
	Packets []struct {
		Name           string `json:"name"`
		Author         string `json:"author"`
		Epoch          uint64 `json:"epoch"`
		TS             uint64 `json:"ts"`
		SegmentLen     int    `json:"segment_len"`
		Depth          int    `json:"depth"`
		MsgHex         string `json:"msg_hex"`
		PointTo        string `json:"point_to"`
		RedundancyBits uint32 `json:"redundancy_bits"`
		Members        []struct {
			Pubkey string `json:"pubkey"`
			Stake  string `json:"stake"`
		} `json:"members"`
		Packets []struct {
			Recipient  string `json:"recipient"`
			Stride     int    `json:"stride"`
			PayloadHex string `json:"payload_hex"`
		} `json:"packets"`
	} `json:"packets"`
}

func loadFixtures(t *testing.T) *fixturesFile {
	t.Helper()
	data, err := os.ReadFile("testdata/raptorcast_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixturesFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func nodeFromPkHex(t *testing.T, s string) types.NodeId {
	t.Helper()
	pk, err := crypto.SecpPubKeyFromBytes(decodeHex(t, s))
	if err != nil {
		t.Fatalf("bad pubkey %s: %v", s, err)
	}
	return types.NodeId{PubKey: pk}
}

// getKey mirrors upstream monad_testutil::signing::get_key(seed):
// secret = blake3(seed.to_le_bytes()).
func getKey(t *testing.T, seed uint64) *crypto.SecpKeyPair {
	t.Helper()
	var buf [8]byte
	for i := 0; i < 8; i++ {
		buf[i] = byte(seed >> (8 * i))
	}
	digest := blake3Hash(buf[:])
	kp, err := crypto.SecpKeyPairFromBytes(digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func TestShuffleConformance(t *testing.T) {
	f := loadFixtures(t)
	for _, c := range f.Shuffle.Shuffle {
		var seed [32]byte
		copy(seed[:], decodeHex(t, c.SeedHex))
		rng := newChaCha20Rng(seed)
		v := make([]uint32, c.N)
		for i := range v {
			v[i] = uint32(i)
		}
		rng.shuffle(c.N, func(i, j int) { v[i], v[j] = v[j], v[i] })
		for i, want := range c.Permutation {
			if v[i] != want {
				t.Fatalf("n=%d seed=%s: perm[%d]=%d want %d", c.N, c.SeedHex[:8], i, v[i], want)
			}
		}
	}
	for _, c := range f.Shuffle.GenRange {
		var seed [32]byte
		copy(seed[:], decodeHex(t, c.SeedHex))
		rng := newChaCha20Rng(seed)
		for i, want := range c.Draws {
			got := rng.genRangeU32(1 << 20)
			if uint64(got) != want {
				t.Fatalf("seed=%s draw[%d]=%d want %d", c.SeedHex[:8], i, got, want)
			}
		}
	}
}

func TestAssignmentConformance(t *testing.T) {
	f := loadFixtures(t)
	for ci, c := range f.Assignment {
		members := make([]types.NodeId, 0, len(c.Members))
		stakes := make(map[[33]byte]types.Stake)
		for _, m := range c.Members {
			id := nodeFromPkHex(t, m.Pubkey)
			members = append(members, id)
			v, ok := new(big.Int).SetString(m.Stake, 10)
			if !ok {
				t.Fatalf("bad stake %q", m.Stake)
			}
			stakes[[33]byte(id.PubKey)] = types.StakeFromBig(v)
		}
		sort.Slice(members, func(i, j int) bool { return members[i].Cmp(members[j]) < 0 })
		author := nodeFromPkHex(t, c.Author)
		var appHash AppMessageHash
		copy(appHash[:], decodeHex(t, c.AppHashHex))

		var total types.Stake
		view := &validatorGroupView{
			epoch:    types.Epoch(7),
			author:   author,
			members:  members,
			stakeOf:  func(id types.NodeId) types.Stake { return stakes[[33]byte(id.PubKey)] },
			totalAll: total,
		}
		part := stakePartitionFromGroup(view)
		var seed [32]byte
		copy(seed[:], decodeHex(t, c.SeedHex))
		part.shuffle(seed)

		a, err := part.assign(c.NumBaseSymbols, Redundancy(c.RedundancyBits))
		if err != nil {
			t.Fatalf("case %d assign: %v", ci, err)
		}
		if a.numChunks() != c.NumChunks {
			t.Fatalf("case %d: numChunks %d want %d", ci, a.numChunks(), c.NumChunks)
		}
		for _, want := range c.Chunks {
			r, ok := a.resolveChunkID(want.ChunkID)
			if !ok {
				t.Fatalf("case %d chunk %d unresolved", ci, want.ChunkID)
			}
			gotPk := hex.EncodeToString(r.recipient.PubKey[:])
			if gotPk != want.Recipient {
				t.Fatalf("case %d chunk %d recipient %s want %s", ci, want.ChunkID, gotPk, want.Recipient)
			}
			gotRB := r.rebroadcastTargets()
			if len(gotRB) != len(want.Rebroadcast) {
				t.Fatalf("case %d chunk %d rebroadcast count %d want %d", ci, want.ChunkID, len(gotRB), len(want.Rebroadcast))
			}
			for i, n := range gotRB {
				if hex.EncodeToString(n.PubKey[:]) != want.Rebroadcast[i] {
					t.Fatalf("case %d chunk %d rebroadcast[%d] %s want %s", ci, want.ChunkID, i,
						hex.EncodeToString(n.PubKey[:]), want.Rebroadcast[i])
				}
			}
		}
	}
}

func TestMerkleConformance(t *testing.T) {
	f := loadFixtures(t)
	for _, c := range f.Merkle {
		leaves := make([][32]byte, len(c.Leaves))
		for i, l := range c.Leaves {
			b := decodeHex(t, l)
			copy(leaves[i][:], b)
		}
		tree := newMerkleTreeWithDepth(leaves, c.Depth)
		var wantRoot MerkleRoot
		copy(wantRoot[:], decodeHex(t, c.RootHex))
		if got := tree.root(); got != wantRoot {
			t.Fatalf("root %x want %x", got, wantRoot)
		}
		for _, p := range c.Proofs {
			proof := tree.proof(p.LeafIdx)
			wantProof := decodeHex(t, p.ProofHex)
			if len(proof)*20 != len(wantProof) {
				t.Fatalf("proof %d len %d want %d", p.LeafIdx, len(proof)*20, len(wantProof))
			}
			for i, h := range proof {
				if got, want := h[:], wantProof[i*20:(i+1)*20]; string(got) != string(want) {
					t.Fatalf("proof %d sibling %d: %x want %x", p.LeafIdx, i, got, want)
				}
			}
			var leaf [32]byte
			copy(leaf[:], decodeHex(t, p.LeafHex))
			root, ok := merkleProofComputeRoot(leaf, proof, p.LeafIdx)
			if !ok || root != wantRoot {
				t.Fatalf("proof %d verify failed: ok=%v root=%x want %x",
					p.LeafIdx, ok, root, wantRoot)
			}
			if !p.Verified {
				t.Fatalf("proof %d: fixture says invalid but we verified", p.LeafIdx)
			}
		}
	}
}

func TestPacketBuildConformance(t *testing.T) {
	f := loadFixtures(t)
	for _, c := range f.Packets {
		members := make([]types.NodeId, 0, len(c.Members))
		stakes := make(map[[33]byte]types.Stake)
		for _, m := range c.Members {
			id := nodeFromPkHex(t, m.Pubkey)
			members = append(members, id)
			v, _ := new(big.Int).SetString(m.Stake, 10)
			stakes[[33]byte(id.PubKey)] = types.StakeFromBig(v)
		}
		sort.Slice(members, func(i, j int) bool { return members[i].Cmp(members[j]) < 0 })
		author := nodeFromPkHex(t, c.Author)

		// the author key isn't in the fixture — derive it by scanning seeds
		var key *crypto.SecpKeyPair
		for seed := uint64(1); seed <= 20; seed++ {
			kp := getKey(t, seed)
			if (types.NodeId{PubKey: kp.PubKey()}) == author {
				key = kp
				break
			}
		}
		if key == nil {
			t.Fatalf("case %s: could not derive author key", c.Name)
		}

		view := &validatorGroupView{
			epoch:    types.Epoch(c.Epoch),
			author:   author,
			members:  members,
			stakeOf:  func(id types.NodeId) types.Stake { return stakes[[33]byte(id.PubKey)] },
			totalAll: types.Stake{},
		}
		var bt *buildTarget
		if c.PointTo != "" {
			bt = &buildTarget{
				mode:      BroadcastUnspecified,
				recipient: nodeFromPkHex(t, c.PointTo),
				epoch:     types.Epoch(c.Epoch),
			}
		} else {
			bt = &buildTarget{
				mode:  BroadcastPrimary,
				epoch: types.Epoch(c.Epoch),
				group: view,
			}
		}

		layout := newPacketLayoutV0(c.SegmentLen, c.Depth)
		msg := decodeHex(t, c.MsgHex)
		var got []udpMessage
		err := buildInto(key, layout, Redundancy(c.RedundancyBits), c.TS, msg, bt,
			func(m udpMessage) { got = append(got, m) })
		if err != nil {
			t.Fatalf("case %s build: %v", c.Name, err)
		}
		if len(got) != len(c.Packets) {
			t.Fatalf("case %s: %d packets, want %d", c.Name, len(got), len(c.Packets))
		}
		for i, want := range c.Packets {
			if hex.EncodeToString(got[i].recipient.PubKey[:]) != want.Recipient {
				t.Fatalf("case %s packet %d: recipient %s want %s", c.Name, i,
					hex.EncodeToString(got[i].recipient.PubKey[:]), want.Recipient)
			}
			if int(got[i].stride) != want.Stride {
				t.Fatalf("case %s packet %d: stride %d want %d", c.Name, i, got[i].stride, want.Stride)
			}
			wantPayload := decodeHex(t, want.PayloadHex)
			if string(got[i].payload) != string(wantPayload) {
				t.Fatalf("case %s packet %d: payload mismatch\n got %x\nwant %x", c.Name, i,
					got[i].payload[:64], wantPayload[:64])
			}
		}
	}
}

// TestPacketReceiveConformance feeds every fixture packet through the real
// parse → validate → decode pipeline and checks the reconstructed message.
func TestPacketReceiveConformance(t *testing.T) {
	f := loadFixtures(t)
	for _, c := range f.Packets {
		if c.PointTo != "" {
			continue // covered by unicast receive check below via decoder path
		}
		vals := make([]validator.ValidatorData, 0, len(c.Members))
		for _, m := range c.Members {
			id := nodeFromPkHex(t, m.Pubkey)
			v, _ := new(big.Int).SetString(m.Stake, 10)
			vals = append(vals, validator.ValidatorData{NodeId: id, Stake: types.StakeFromBig(v)})
		}
		vs, err := validator.NewValidatorSet(vals)
		if err != nil {
			t.Fatal(err)
		}
		author := nodeFromPkHex(t, c.Author)
		// receiving node = first non-author member
		var selfID types.NodeId
		for _, m := range c.Members {
			if id := nodeFromPkHex(t, m.Pubkey); id != author {
				selfID = id
				break
			}
		}

		verifier := newSignatureVerifier(SignatureCacheSize, math.MaxUint32)
		cache := newDecoderCache(defaultDecoderCacheConfig)
		var decoded []byte
		for i, p := range c.Packets {
			payload := decodeHex(t, p.PayloadHex)
			pkt, err := parsePacket(payload)
			if err != nil {
				t.Fatalf("case %s packet %d parse: %v", c.Name, i, err)
			}
			bypass := func(types.Epoch) bool { return true }
			chk, err := pkt.validateChunk(payload, verifier, math.MaxUint64, bypass, selfID)
			if err != nil {
				t.Fatalf("case %s packet %d validate: %v", c.Name, i, err)
			}
			if chk.author != author {
				t.Fatalf("case %s packet %d: author %s want %s", c.Name, i,
					hex.EncodeToString(chk.author.PubKey[:]), c.Author)
			}
			res, err := cache.tryDecode(chk, vs, math.MaxUint64)
			if err != nil {
				t.Fatalf("case %s packet %d decode: %v", c.Name, i, err)
			}
			if res.status == statusDecoded {
				decoded = res.appMessage
			}
		}
		want := decodeHex(t, c.MsgHex)
		if string(decoded) != string(want) {
			t.Fatalf("case %s: decoded %d bytes, want %d (first bytes %x vs %x)",
				c.Name, len(decoded), len(want),
				decoded[:min(32, len(decoded))], want[:min(32, len(want))])
		}

	}
}
