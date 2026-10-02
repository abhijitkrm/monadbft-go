// Package raptorcast ports monad-raptorcast's primary (validator) raptorcast
// path: stake-weighted chunk assignment, Raptor/R10 symbol spreading across
// UDP packets, merkle-batched chunk authentication, and receive-side
// decode/rebroadcast. The wire format is byte-compatible with upstream's
// regular (v0) packet layout.
package raptorcast

import (
	"fmt"

	"github.com/zeebo/blake3"

	"github.com/abhijitkrm/monadbft-go/types"
)

const (
	// MerkleHashLen is the truncated hash size used throughout raptorcast
	// packets (app-message hash, node-id hash, merkle nodes).
	MerkleHashLen = 20

	// SIGNATURE_SIZE is the secp256k1 recoverable signature size.
	SignatureSize = 65

	// MAX_NUM_PACKETS bounds the number of chunks emitted per app message.
	MaxNumPackets = 65535

	// MaxMessageSize is the largest serialized app message (3 MiB).
	MaxMessageSize = 3 * 1024 * 1024

	// MaxValidatorSetSize mirrors monad-validator's bound.
	MaxValidatorSetSize = 300
)

// NodeIdHash is blake3(compressed pubkey) truncated to 20 bytes.
type NodeIdHash [MerkleHashLen]byte

// AppMessageHash is blake3(app message) truncated to 20 bytes.
type AppMessageHash [MerkleHashLen]byte

// MerkleRoot is the root of a chunk merkle batch.
type MerkleRoot [MerkleHashLen]byte

func blake3Hash(b []byte) [32]byte { return blake3.Sum256(b) }

// computeHash — Rust util::compute_hash: truncated node-id hash.
func computeHash(id types.NodeId) NodeIdHash {
	var h NodeIdHash
	full := blake3Hash(id.PubKey[:])
	copy(h[:], full[:MerkleHashLen])
	return h
}

// computeAppMessageHash — Rust util::compute_app_message_hash.
func computeAppMessageHash(appMsg []byte) AppMessageHash {
	var h AppMessageHash
	full := blake3Hash(appMsg)
	copy(h[:], full[:MerkleHashLen])
	return h
}

// GroupId identifies the broadcast group a chunk belongs to.
// Primary(epoch) covers validator primary broadcasts; Secondary(round)
// covers full-node secondary broadcasts (v1.1 scope).
type GroupId struct {
	IsSecondary bool
	// N is the Epoch for primary groups, the Round for secondary groups.
	N uint64
}

func PrimaryGroup(epoch types.Epoch) GroupId {
	return GroupId{N: uint64(epoch)}
}

func SecondaryGroup(round types.Round) GroupId {
	return GroupId{IsSecondary: true, N: uint64(round)}
}

// Uint64 — Rust impl From<GroupId> for u64.
func (g GroupId) Uint64() uint64 { return g.N }

// BroadcastMode — Rust util::BroadcastMode.
type BroadcastMode int

const (
	BroadcastUnspecified BroadcastMode = iota // unicast / direct broadcast
	BroadcastPrimary                          // validator raptorcast
	BroadcastSecondary                        // full-node raptorcast
)

// EncodingScheme — Rust util::EncodingScheme. The v0 packet layout always
// uses Unspecified; deterministic v1 chunks carry a scheme.
type EncodingScheme struct {
	Deterministic bool
	Round         types.Round
}

var EncodingUnspecified = EncodingScheme{}

// Redundancy — Rust util::Redundancy, a FixedU16<U11> fixed-point factor.
type Redundancy uint32 // fixed-point, 11 fractional bits

// RedundancyFromFract — Rust Redundancy::from_fract(n, d*100) style helper:
// factor = numerator/denominator.
func RedundancyFromFract(numerator, denominator uint32) Redundancy {
	return Redundancy(numerator * (1 << 11) / denominator)
}

func RedundancyFromU8(v uint8) Redundancy { return Redundancy(v) << 11 }

// RedundancyFromFloat approximates Rust Redundancy::from_f32.
func RedundancyFromFloat(f float32) (Redundancy, error) {
	if f < 0 || f > float32((1<<5)-1) {
		return 0, fmt.Errorf("redundancy %f out of range", f)
	}
	return Redundancy(f * (1 << 11)), nil
}

// DefaultPrimaryRedundancy — upstream validator default (2.5).
var DefaultPrimaryRedundancy = RedundancyFromFract(5, 2)

// MaxRedundancy — regular::MAX_REDUNDANCY = 3.
var MaxRedundancy = RedundancyFromU8(3)

// scale — Rust Redundancy::scale: ceil(fp * base / 2^11), None on overflow
// past u16 (MAX_NUM_PACKETS guard lives at the call sites).
func (r Redundancy) scale(base int) (int, bool) {
	prod := uint64(r) * uint64(base)
	if prod > (uint64(^uint16(0)) << 11) {
		return 0, false
	}
	return int((prod + (1<<11 - 1)) >> 11), true
}

// buildTarget describes where a message is headed at packet-build time
// (Rust util::BuildTarget). Only the v0/regular variants needed for the
// primary path are present; secondary full-node targets come with B5.
type buildTarget struct {
	mode BroadcastMode

	// PointToPoint target.
	recipient types.NodeId

	// Primary validator group (for Broadcast and Raptorcast).
	epoch types.Epoch
	group *validatorGroupView
}

// validatorGroupView is the send-side view of a validator set: ordered
// members with stakes plus the author for exclusion.
type validatorGroupView struct {
	epoch    types.Epoch
	author   types.NodeId
	members  []types.NodeId // sorted (ValidatorSet member order)
	stakeOf  func(types.NodeId) types.Stake
	totalAll types.Stake
}

// udpMessage is a single UDP datagram's worth of chunk payload plus routing.
// Mirrors Rust util::UdpMessage.
type udpMessage struct {
	recipient types.NodeId
	stride    uint16
	payload   []byte
}
