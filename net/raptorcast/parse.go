package raptorcast

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/zeebo/blake3"

	"github.com/abhijitkrm/monadbft-go/raptor"
	"github.com/abhijitkrm/monadbft-go/types"
)

// Packet parsing and chunk validation — ports
// monad-raptorcast parser/packet_parser.rs (v0 layout; v1 deterministic
// headers are recognized but rejected as unsupported).

var (
	ErrTooShort                 = errors.New("packet too short")
	ErrTooLong                  = errors.New("packet too long")
	ErrInvalidTreeDepth         = errors.New("invalid merkle tree depth")
	ErrInvalidBroadcastBits     = errors.New("invalid broadcast bits")
	ErrUnknownVersion           = errors.New("unknown packet version")
	ErrInvalidTimestamp         = errors.New("invalid timestamp")
	ErrInvalidSignature         = errors.New("invalid signature")
	ErrInvalidChunkID           = errors.New("invalid chunk id")
	ErrInvalidChunkLen          = errors.New("invalid chunk length")
	ErrInvalidAppMessageLen     = errors.New("invalid app message length")
	ErrInvalidMerkleProof       = errors.New("invalid merkle proof")
	ErrInvalidBroadcastMode     = errors.New("invalid broadcast mode")
	ErrRateLimited              = errors.New("signature verification rate limited")
	ErrLoopback                 = errors.New("chunk from self")
	ErrSigVerificationRateLimit = errors.New("signature verification rate limited")
)

// parsedPacketV0 — a parsed regular raptorcast packet (borrowed slices).
type parsedPacketV0 struct {
	// fixed fields (header sans signature)
	broadcastTreeDepth byte
	groupIDRaw         uint64
	unixTsMs           uint64
	appMessageHash     AppMessageHash
	appMessageLen      uint32

	merkleProof []MerkleRoot

	recipientHash         NodeIdHash
	merkleLeafIdx         uint8
	chunkID               uint16
	chunkHeaderAndPayload []byte
	payloadOffset         int
}

// parsePacket parses the common header and dispatches on version.
// Returns a v0 packet or an error; v1 packets are rejected for now.
func parsePacket(data []byte) (*parsedPacketV0, error) {
	if len(data) < SignatureSize+2 {
		return nil, ErrTooShort
	}
	version := binary.LittleEndian.Uint16(data[SignatureSize:])
	switch version {
	case packetVersionV0:
		return parsePacketV0(data[SignatureSize+2:])
	case 1:
		return nil, fmt.Errorf("%w: v1 deterministic not supported", ErrUnknownVersion)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, version)
	}
}

func parsePacketV0(rest []byte) (*parsedPacketV0, error) {
	if len(rest) < 41 { // headerV0 size = 1+8+8+20+4
		return nil, ErrTooShort
	}
	p := &parsedPacketV0{}
	p.broadcastTreeDepth = rest[0]
	p.groupIDRaw = binary.LittleEndian.Uint64(rest[1:9])
	p.unixTsMs = binary.LittleEndian.Uint64(rest[9:17])
	copy(p.appMessageHash[:], rest[17:37])
	p.appMessageLen = binary.LittleEndian.Uint32(rest[37:41])

	depth := p.broadcastTreeDepth & 0b0000_1111
	if depth < minMerkleTreeDepth || depth > maxMerkleTreeDepth {
		return nil, fmt.Errorf("%w: %d", ErrInvalidTreeDepth, depth)
	}
	proofLen := int(depth-1) * MerkleHashLen
	rest = rest[41:]
	if len(rest) < proofLen+chunkHeaderLenV0 {
		return nil, ErrTooShort
	}
	for i := 0; i < int(depth)-1; i++ {
		var h MerkleRoot
		copy(h[:], rest[i*20:(i+1)*20])
		p.merkleProof = append(p.merkleProof, h)
	}
	rest = rest[proofLen:]
	p.chunkHeaderAndPayload = rest
	copy(p.recipientHash[:], rest[0:20])
	p.merkleLeafIdx = rest[20]
	p.chunkID = binary.LittleEndian.Uint16(rest[22:24])
	if len(rest) <= chunkHeaderLenV0 {
		return nil, ErrTooShort
	}
	p.payloadOffset = SignatureSize + 2 + 41 + proofLen + chunkHeaderLenV0
	return p, nil
}

func (p *parsedPacketV0) broadcastMode() (BroadcastMode, error) {
	primary := p.broadcastTreeDepth&(1<<7) != 0
	secondary := p.broadcastTreeDepth&(1<<6) != 0
	switch {
	case primary && !secondary:
		return BroadcastPrimary, nil
	case secondary && !primary:
		return BroadcastSecondary, nil
	case !primary && !secondary:
		return BroadcastUnspecified, nil
	default:
		return BroadcastUnspecified, fmt.Errorf("%w: 0b11", ErrInvalidBroadcastBits)
	}
}

func (p *parsedPacketV0) groupID() (GroupId, error) {
	mode, err := p.broadcastMode()
	if err != nil {
		return GroupId{}, err
	}
	if mode == BroadcastSecondary {
		return SecondaryGroup(types.Round(p.groupIDRaw)), nil
	}
	return PrimaryGroup(types.Epoch(p.groupIDRaw)), nil
}

// signedOverDataV0 — the bytes the chunk signature covers:
// header-sans-signature || merkle root.
func (p *parsedPacketV0) signedOverData(message []byte, merkleRoot MerkleRoot) []byte {
	out := make([]byte, 0, packetHeaderLenV0-SignatureSize+MerkleHashLen)
	out = append(out, message[SignatureSize:packetHeaderLenV0]...)
	out = append(out, merkleRoot[:]...)
	return out
}

// validatedChunk — Rust ValidatedChunk: a chunk that has passed structural
// and signature validation.
type validatedChunk struct {
	chunk                 []byte // full packet bytes (for rebroadcast)
	signature             []byte
	author                types.NodeId
	groupID               GroupId
	unixTsMs              uint64
	appMessageHash        *AppMessageHash // nil for v1
	merkleRoot            MerkleRoot
	appMessageLen         uint32
	encodingScheme        EncodingScheme
	broadcastMode         BroadcastMode
	recipientHash         *NodeIdHash
	chunkID               uint16
	numSourceSymbols      int
	encodedSymbolCapacity int
	payloadOffset         int
}

// appMessage returns the decoded app message payload range (the raptor
// symbol).
func (p *parsedPacketV0) symbol(message []byte) []byte {
	return message[p.payloadOffset:]
}

func unixTsMsNow() uint64 {
	return uint64(time.Now().UnixMilli())
}

// validateChunk — Rust RaptorcastPacket::validate_chunk for v0:
// meta validation (timestamp, sizes, merkle proof/root, chunk-id cap)
// then rate-limited signature recovery.
func (p *parsedPacketV0) validateChunk(message []byte, verifier *signatureVerifier, maxAgeMs uint64, bypassRateLimiter func(epoch types.Epoch) bool, selfID types.NodeId) (*validatedChunk, error) {
	// timestamp
	now := unixTsMsNow()
	var delta uint64
	if now > p.unixTsMs {
		delta = now - p.unixTsMs
	} else {
		delta = p.unixTsMs - now
	}
	if delta > maxAgeMs {
		return nil, ErrInvalidTimestamp
	}

	appMessageLen := int(p.appMessageLen)
	if appMessageLen <= 0 || appMessageLen > MaxMessageSize {
		return nil, fmt.Errorf("%w: %d", ErrInvalidAppMessageLen, appMessageLen)
	}

	symbolLen := len(message) - p.payloadOffset
	// upstream: chunk_len >= MIN_CHUNK_LENGTH || chunk_len == app_message_len
	if symbolLen < minChunkLength && symbolLen != appMessageLen {
		return nil, ErrInvalidChunkLen
	}

	numSourceSymbols := (appMessageLen + symbolLen - 1) / symbolLen
	if numSourceSymbols < raptor.SourceSymbolsMin || numSourceSymbols > raptor.SourceSymbolsMax {
		return nil, fmt.Errorf("%w: %d", ErrInvalidAppMessageLen, appMessageLen)
	}

	mode, err := p.broadcastMode()
	if err != nil {
		return nil, err
	}
	groupID, err := p.groupID()
	if err != nil {
		return nil, err
	}

	// chunk id cap — upstream: MAX_REDUNDANCY.scale(num_source_symbols),
	// plus MAX_VALIDATOR_SET_SIZE for the primary (stake-partitioned) mode.
	chunkIDCap, capOK := MaxRedundancy.scale(numSourceSymbols)
	if !capOK {
		return nil, ErrInvalidChunkID
	}
	if mode == BroadcastPrimary {
		chunkIDCap += MaxValidatorSetSize
	}
	if int(p.chunkID) >= chunkIDCap {
		return nil, ErrInvalidChunkID
	}

	// merkle proof → root
	leafHash := blake3.Sum256(p.chunkHeaderAndPayload)
	merkleRoot, ok := merkleProofComputeRoot(leafHash, p.merkleProof, int(p.merkleLeafIdx))
	if !ok {
		return nil, ErrInvalidMerkleProof
	}

	// signature
	signedOver := p.signedOverData(message, merkleRoot)
	var epochBypass bool
	if !groupID.IsSecondary {
		epochBypass = bypassRateLimiter(types.Epoch(groupID.N))
	}
	author, err := verifier.verifyChunkSignature(message[:SignatureSize], signedOver, epochBypass)
	if err != nil {
		return nil, err
	}
	if author == selfID {
		return nil, ErrLoopback
	}
	// merkle leaf idx must be consistent with the actual proof depth:
	// upstream rejects when proof construction fails (idx >= num_leaves).
	numLeaves := 1 << len(p.merkleProof)
	if int(p.merkleLeafIdx) >= numLeaves {
		return nil, ErrInvalidMerkleProof
	}

	appHash := p.appMessageHash
	recip := p.recipientHash
	return &validatedChunk{
		chunk:                 message,
		signature:             message[:SignatureSize],
		author:                author,
		groupID:               groupID,
		unixTsMs:              p.unixTsMs,
		appMessageHash:        &appHash,
		merkleRoot:            merkleRoot,
		appMessageLen:         p.appMessageLen,
		encodingScheme:        EncodingUnspecified,
		broadcastMode:         mode,
		recipientHash:         &recip,
		chunkID:               p.chunkID,
		numSourceSymbols:      numSourceSymbols,
		encodedSymbolCapacity: chunkIDCap,
		payloadOffset:         p.payloadOffset,
	}, nil
}

// symbolData returns the raptor symbol bytes of a validated chunk.
func (c *validatedChunk) symbolData() []byte {
	return c.chunk[c.payloadOffset:]
}
