// Package glue ports monad-executor-glue: the Command/MonadEvent sum types,
// router/timer/ledger/txpool/statesync command enums, and the MonadMessage /
// VerifiedMonadMessage wire envelope (which in Rust lives in monad-state but is
// co-located here so the router command can carry a concrete message type).
package glue

import (
	"github.com/abhijitkrm/monadbft-go/rlp"
)

// Protocol/serialization version constants — Rust monad_types.
const (
	protocolVersion    uint32 = 1
	clientMajorVersion uint16 = 0
	clientMinorVersion uint16 = 1
	hashVersion        uint16 = 1
	serializeVersion   uint16 = 1
)

// MonadVersion — Rust monad_types::MonadVersion (RlpEncodable list of 5).
type MonadVersion struct {
	ProtocolVersion  uint32
	ClientVersionMaj uint16
	ClientVersionMin uint16
	HashVersion      uint16
	SerializeVersion uint16
}

// Version — Rust MonadVersion::version().
func Version() MonadVersion {
	return MonadVersion{
		ProtocolVersion:  protocolVersion,
		ClientVersionMaj: clientMajorVersion,
		ClientVersionMin: clientMinorVersion,
		HashVersion:      hashVersion,
		SerializeVersion: serializeVersion,
	}
}

func (v MonadVersion) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendUint32(p, v.ProtocolVersion)
		p = rlp.AppendUint64(p, uint64(v.ClientVersionMaj))
		p = rlp.AppendUint64(p, uint64(v.ClientVersionMin))
		p = rlp.AppendUint64(p, uint64(v.HashVersion))
		p = rlp.AppendUint64(p, uint64(v.SerializeVersion))
		return p
	})
}

func (v *MonadVersion) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	pv, err := l.Uint64()
	if err != nil {
		return err
	}
	v.ProtocolVersion = uint32(pv)
	maj, err := l.Uint64()
	if err != nil {
		return err
	}
	v.ClientVersionMaj = uint16(maj)
	min, err := l.Uint64()
	if err != nil {
		return err
	}
	v.ClientVersionMin = uint16(min)
	hv, err := l.Uint64()
	if err != nil {
		return err
	}
	v.HashVersion = uint16(hv)
	sv, err := l.Uint64()
	if err != nil {
		return err
	}
	v.SerializeVersion = uint16(sv)
	return l.Done()
}

// UdpPriority — Rust monad_types::UdpPriority.
type UdpPriority uint8

const (
	UdpPriorityHigh    UdpPriority = 0
	UdpPriorityRegular UdpPriority = 1
)

// StateSync versions — Rust monad_executor_glue.
const (
	statesyncMajor uint16 = 1
	statesyncMinor uint16 = 2
)

// StateSyncVersion — Rust StateSyncVersion { major, minor }.
type StateSyncVersion struct {
	Major uint16
	Minor uint16
}

// SelfStateSyncVersion / min — Rust SELF_STATESYNC_VERSION = v1.2.
var (
	StateSyncVersionSelf = StateSyncVersion{Major: statesyncMajor, Minor: statesyncMinor}
	StateSyncVersionMin  = StateSyncVersion{Major: statesyncMajor, Minor: statesyncMinor}
)

func StateSyncVersionFromU32(v uint32) StateSyncVersion {
	return StateSyncVersion{Major: uint16(v >> 16), Minor: uint16(v & 0xFFFF)}
}

func (v StateSyncVersion) ToU32() uint32 {
	return uint32(v.Major)<<16 | uint32(v.Minor)
}

func (v StateSyncVersion) IsCompatible() bool {
	return !v.Less(StateSyncVersionMin) && !StateSyncVersionSelf.Less(v)
}

func (v StateSyncVersion) Less(o StateSyncVersion) bool {
	if v.Major != o.Major {
		return v.Major < o.Major
	}
	return v.Minor < o.Minor
}

func (v StateSyncVersion) EncodeRLP(dst []byte) []byte {
	return rlp.AppendList(dst, func(p []byte) []byte {
		p = rlp.AppendUint64(p, uint64(v.Major))
		p = rlp.AppendUint64(p, uint64(v.Minor))
		return p
	})
}

func (v *StateSyncVersion) DecodeRLP(s *rlp.Stream) error {
	l, err := s.List()
	if err != nil {
		return err
	}
	maj, err := l.Uint64()
	if err != nil {
		return err
	}
	v.Major = uint16(maj)
	min, err := l.Uint64()
	if err != nil {
		return err
	}
	v.Minor = uint16(min)
	return l.Done()
}

// MaxForwardedTxsPerMessage — Rust MAX_FORWARDED_TXS_PER_MESSAGE.
const MaxForwardedTxsPerMessage = 5000

// MaxUpsertsPerResponse — Rust MAX_UPSERTS_PER_RESPONSE.
const MaxUpsertsPerResponse = 20000
