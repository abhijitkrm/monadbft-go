package raptorcast

import (
	"encoding/binary"

	"github.com/zeebo/blake3"

	"github.com/abhijitkrm/monadbft-go/crypto"
	"github.com/abhijitkrm/monadbft-go/raptor"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Regular (v0) packet wire layout — ports monad-raptorcast packet/regular.rs.
//
//	[0:65)    sender recoverable signature
//	[65:67)   version u16 LE = 0
//	[67]      broadcast bits (hi 2) | merkle tree depth (lo 4)
//	[68:76)   group id u64 LE (epoch for primary)
//	[76:84)   unix timestamp ms u64 LE
//	[84:104)  app-message hash (20)
//	[104:108) app-message len u32 LE
//	[108:108+20*(depth-1)) merkle proof
//	[..+24)   chunk header: recipient hash(20) | leaf idx(1) | reserved(1) | chunk id u16 LE
//	[..seg)   raptor symbol
const (
	packetHeaderLenV0  = SignatureSize + 2 + 1 + 8 + 8 + 20 + 4 // 108
	chunkHeaderLenV0   = 20 + 1 + 1 + 2                         // 24
	packetVersionV0    = 0
	minChunkLength     = 960
	minMerkleTreeDepth = 1
	maxMerkleTreeDepth = 9

	// DefaultMerkleTreeDepth — packet/builder.rs DEFAULT_MERKLE_TREE_DEPTH.
	DefaultMerkleTreeDepth = 6

	// defaultMTU/minMTU-derived segment sizes (dataplane::segment_size_for_mtu).
	minSegmentLength     = 1252 // 1280 - 20 - 8
	DefaultSegmentLength = 1472 // 1500 - 20 - 8
	maxSegmentLength     = DefaultSegmentLength
)

// packetLayoutV0 — Rust regular::PacketLayout.
type packetLayoutV0 struct {
	chunkHeaderStart int
	segmentLen       int
}

func newPacketLayoutV0(segmentLen, merkleTreeDepth int) packetLayoutV0 {
	return packetLayoutV0{
		chunkHeaderStart: packetHeaderLenV0 + 20*(merkleTreeDepth-1),
		segmentLen:       segmentLen,
	}
}

func calcSegmentLen(chunkLen, depth int) int {
	return packetHeaderLenV0 + 20*(depth-1) + chunkHeaderLenV0 + chunkLen
}

func (l packetLayoutV0) numBaseSymbols(appMessageLen int) int {
	return (appMessageLen + l.symbolLen() - 1) / l.symbolLen()
}

func (l packetLayoutV0) merkleProofLen() int {
	return l.chunkHeaderStart - packetHeaderLenV0
}

func (l packetLayoutV0) merkleTreeDepth() int {
	return l.merkleProofLen()/20 + 1
}

func (l packetLayoutV0) symbolStart() int {
	return l.chunkHeaderStart + chunkHeaderLenV0
}

func (l packetLayoutV0) symbolLen() int {
	return l.segmentLen - l.symbolStart()
}

func (l packetLayoutV0) merkleBatchLen() int {
	return 1 << (l.merkleTreeDepth() - 1)
}

// writeHeader writes signature + fixed header (sans signature region).
func (l packetLayoutV0) writeHeader(c *chunk, signature, header []byte) {
	copy(c.payload[0:SignatureSize], signature)
	copy(c.payload[SignatureSize:packetHeaderLenV0], header)
}

func (l packetLayoutV0) writeChunkHeader(c *chunk, merkleLeafIndex uint8) error {
	if c.chunkID > 0xffff {
		return ErrChunkIDOverflow
	}
	h := computeHash(c.recipient)
	buf := c.payload[l.chunkHeaderStart : l.chunkHeaderStart+chunkHeaderLenV0]
	copy(buf[0:20], h[:])
	buf[20] = merkleLeafIndex
	// buf[21] reserved, stays zero
	binary.LittleEndian.PutUint16(buf[22:24], uint16(c.chunkID))
	return nil
}

func (l packetLayoutV0) writeMerkleProof(c *chunk, proof []MerkleRoot) {
	buf := c.payload[packetHeaderLenV0:l.chunkHeaderStart]
	for i, h := range proof {
		copy(buf[i*20:(i+1)*20], h[:])
	}
}

func (l packetLayoutV0) chunkHash(c *chunk) [32]byte {
	return blake3.Sum256(c.payload[l.chunkHeaderStart:l.segmentLen])
}

func (l packetLayoutV0) symbol(c *chunk) []byte {
	return c.payload[l.symbolStart():l.segmentLen]
}

// chunk — Rust packet/chunk.rs Chunk: chunk_id + recipient + packet buffer.
type chunk struct {
	chunkID   int
	recipient types.NodeId
	payload   []byte
}

// buildHeaderV0 — Rust regular::build_header (sans signature).
func buildHeaderV0(mode BroadcastMode, treeDepth int, groupID GroupId, unixTsMs uint64, appMessageHash AppMessageHash, appMessageLen int) ([]byte, error) {
	if treeDepth&0b1111_0000 != 0 {
		return nil, ErrMerkleTreeTooDeep
	}
	buf := make([]byte, packetHeaderLenV0-SignatureSize)
	binary.LittleEndian.PutUint16(buf[0:2], packetVersionV0)
	var broadcastByte byte
	switch mode {
	case BroadcastPrimary:
		broadcastByte = 0b10 << 6
	case BroadcastSecondary:
		broadcastByte = 0b01 << 6
	default:
		broadcastByte = 0
	}
	buf[2] = broadcastByte | byte(treeDepth&0b1111)
	binary.LittleEndian.PutUint64(buf[3:11], groupID.Uint64())
	binary.LittleEndian.PutUint64(buf[11:19], unixTsMs)
	copy(buf[19:39], appMessageHash[:])
	binary.LittleEndian.PutUint32(buf[39:43], uint32(appMessageLen))
	return buf, nil
}

// encodeSymbols — Rust regular::encode_symbols: first chunk with a given
// chunk_id gets the encoded symbol; later duplicates copy it.
func encodeSymbols(appMessage []byte, chunks []*chunk, layout packetLayoutV0) error {
	symbolLen := layout.symbolLen()
	enc, err := raptor.NewEncoder(appMessage, symbolLen)
	if err != nil {
		return ErrEncoderFailed
	}
	assigned := make([]int, len(chunks)) // chunk_id → 1+source index
	for i, c := range chunks {
		chunkID := c.chunkID
		if chunkID >= len(assigned) {
			return ErrTooManyChunks
		}
		if assigned[chunkID] == 0 {
			enc.EncodeSymbol(layout.symbol(c), chunkID)
			assigned[chunkID] = i + 1
		} else {
			src := chunks[assigned[chunkID]-1]
			copy(layout.symbol(c), layout.symbol(src))
		}
	}
	return nil
}

// assemble — Rust regular::assemble: encode symbols, then per merkle batch
// write chunk headers, build the tree, sign header||root, write proofs.
func assemble(chunks []*chunk, key *crypto.SecpKeyPair, layout packetLayoutV0, appMessage, header []byte, collect func(udpMessage)) error {
	if err := encodeSymbols(appMessage, chunks, layout); err != nil {
		return err
	}
	batchLen := layout.merkleBatchLen()
	for start := 0; start < len(chunks); start += batchLen {
		end := start + batchLen
		if end > len(chunks) {
			end = len(chunks)
		}
		batch := chunks[start:end]

		hashes := make([][32]byte, len(batch))
		for i, c := range batch {
			if err := layout.writeChunkHeader(c, uint8(i)); err != nil {
				return err
			}
			hashes[i] = layout.chunkHash(c)
		}
		tree := newMerkleTreeWithDepth(hashes, layout.merkleTreeDepth())

		// signature over header-without-sig || merkle root
		signBuf := make([]byte, 0, len(header)+MerkleHashLen)
		signBuf = append(signBuf, header...)
		root := tree.root()
		signBuf = append(signBuf, root[:]...)
		sig := key.Sign(crypto.DomainRaptorcastChunk, signBuf)

		for i, c := range batch {
			layout.writeHeader(c, sig.Serialize(), header)
			layout.writeMerkleProof(c, tree.proof(i))
			collect(udpMessage{
				recipient: c.recipient,
				stride:    uint16(len(c.payload)),
				payload:   c.payload,
			})
		}
	}
	return nil
}

// buildInto — Rust regular::build_into: generate chunks per build target,
// write the common header, assemble and emit.
func buildInto(key *crypto.SecpKeyPair, layout packetLayoutV0, redundancy Redundancy, unixTsMs uint64, appMessage []byte, target *buildTarget, collect func(udpMessage)) error {
	appHash := computeAppMessageHash(appMessage)
	selfID := types.NodeId{PubKey: key.PubKey()}

	numBaseSymbols := layout.numBaseSymbols(len(appMessage))

	var chunks []*chunk
	var mode BroadcastMode
	var groupID GroupId

	switch {
	case target.mode == BroadcastUnspecified && len(target.members()) == 0 && target.recipient != (types.NodeId{}):
		// PointToPoint
		mode = BroadcastUnspecified
		groupID = PrimaryGroup(target.epoch)
		if target.recipient == selfID {
			return nil
		}
		numSymbols, ok := redundancy.scale(numBaseSymbols)
		if !ok || numSymbols > maxTriples {
			return ErrTooManyChunks
		}
		var err error
		chunks, err = unicastAssignment(target.recipient, numSymbols).materialize(layout.segmentLen)
		if err != nil {
			return err
		}

	case target.mode == BroadcastUnspecified:
		// Primary Broadcast: unicast assignment to every non-author member.
		mode = BroadcastUnspecified
		groupID = PrimaryGroup(target.epoch)
		numSymbols, ok := redundancy.scale(numBaseSymbols)
		if !ok || numSymbols > maxTriples {
			return ErrTooManyChunks
		}
		for _, m := range target.group.members {
			if m == selfID {
				continue
			}
			cs, err := unicastAssignment(m, numSymbols).materialize(layout.segmentLen)
			if err != nil {
				return err
			}
			chunks = append(chunks, cs...)
		}

	case target.mode == BroadcastPrimary:
		// Raptorcast primary: stake-weighted assignment.
		mode = BroadcastPrimary
		groupID = PrimaryGroup(target.epoch)
		part := stakePartitionFromGroup(target.group)
		part.shuffle(deriveSeed(appHash))
		assignment, err := part.assign(numBaseSymbols, redundancy)
		if err != nil {
			return err
		}
		chunks, err = assignment.materialize(layout.segmentLen)
		if err != nil {
			return err
		}
	}

	if len(chunks) > MaxNumPackets {
		return ErrTooManyChunks
	}
	if len(chunks) == 0 {
		return nil
	}

	header, err := buildHeaderV0(mode, layout.merkleTreeDepth(), groupID, unixTsMs, appHash, len(appMessage))
	if err != nil {
		return err
	}
	return assemble(chunks, key, layout, appMessage, header, collect)
}

func (t *buildTarget) members() []types.NodeId {
	if t.group == nil {
		return nil
	}
	return t.group.members
}
