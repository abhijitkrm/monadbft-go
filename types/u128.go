package types

import (
	"bytes"
	"encoding/binary"

	"github.com/abhijitkrm/monadbft-go/rlp"
)

// U128 is an unsigned 128-bit integer stored big-endian — the Go equivalent
// of Rust's u128 for block timestamps (timestamp_ns). On the wire it encodes
// as an RLP integer (minimal big-endian bytes, no leading zeros).
type U128 [16]byte

func U128FromUint64(v uint64) U128 {
	var u U128
	binary.BigEndian.PutUint64(u[8:], v)
	return u
}

func (u U128) Hi() uint64 { return binary.BigEndian.Uint64(u[:8]) }
func (u U128) Lo() uint64 { return binary.BigEndian.Uint64(u[8:]) }

// Uint64 returns the low 64 bits (values that fit; timestamps in ns).
func (u U128) Uint64() uint64 { return u.Lo() }

func (u U128) Cmp(o U128) int { return bytes.Compare(u[:], o[:]) }
func (u U128) IsZero() bool   { return u == U128{} }

// Inc returns u + 1 (u128 addition; never overflows for real timestamps).
func (u U128) Inc() U128 {
	lo := u.Lo() + 1
	hi := u.Hi()
	if lo == 0 {
		hi++
	}
	return U128FromHiLo(hi, lo)
}

func U128FromHiLo(hi, lo uint64) U128 {
	var u U128
	binary.BigEndian.PutUint64(u[:8], hi)
	binary.BigEndian.PutUint64(u[8:], lo)
	return u
}

// CheckedSub returns u - o, or ok=false on underflow (Rust checked_sub).
func (u U128) CheckedSub(o U128) (U128, bool) {
	if u.Cmp(o) < 0 {
		return U128{}, false
	}
	return U128FromHiLo(u.Hi()-o.Hi()-borrow(u.Lo(), o.Lo()), u.Lo()-o.Lo()), true
}

func borrow(a, b uint64) uint64 {
	if a < b {
		return 1
	}
	return 0
}

// SaturatingSub — Rust saturating_sub.
func (u U128) SaturatingSub(o U128) U128 {
	if d, ok := u.CheckedSub(o); ok {
		return d
	}
	return U128{}
}

// AbsDiff — Rust abs_diff.
func (u U128) AbsDiff(o U128) U128 {
	if u.Cmp(o) >= 0 {
		d, _ := u.CheckedSub(o)
		return d
	}
	d, _ := o.CheckedSub(u)
	return d
}

// Add — wrapping u128 add (Rust uses checked/wrapping in timestamp paths;
// timestamps never approach 2^128).
func (u U128) Add(o U128) U128 {
	lo := u.Lo() + o.Lo()
	hi := u.Hi() + o.Hi()
	if lo < u.Lo() {
		hi++
	}
	return U128FromHiLo(hi, lo)
}

func (u U128) EncodeRLP(dst []byte) []byte { return rlp.AppendUint128(dst, u.Hi(), u.Lo()) }

func (u *U128) DecodeRLP(s *rlp.Stream) error {
	hi, lo, err := s.Uint128()
	if err != nil {
		return err
	}
	*u = U128FromHiLo(hi, lo)
	return nil
}
