// Package rlp implements RLP with byte-identical semantics to alloy-rlp
// (the encoder/decoder used by monad-bft). Differences from go-ethereum/rlp:
// integers encode as minimal big-endian with 0 as the empty string, and
// decoding enforces canonical form (no leading zeros, no non-canonical
// single-byte strings, long-form only for length >= 56).
package rlp

import "errors"

const (
	EmptyStringCode = 0x80
	EmptyListCode   = 0xC0
)

var (
	ErrInputTooShort          = errors.New("rlp: input too short")
	ErrInputTooLong           = errors.New("rlp: input too long")
	ErrNonCanonicalSingleByte = errors.New("rlp: non-canonical single byte")
	ErrNonCanonicalSize       = errors.New("rlp: non-canonical size (long form for short payload)")
	ErrLeadingZero            = errors.New("rlp: leading zero in integer")
	ErrOverflow               = errors.New("rlp: integer overflow")
	ErrUnexpectedString       = errors.New("rlp: expected list, found string")
	ErrUnexpectedList         = errors.New("rlp: expected string, found list")
	ErrUnexpectedLength       = errors.New("rlp: unexpected length")
	ErrListLengthMismatch     = errors.New("rlp: list payload length mismatch")
	ErrCustom                 = errors.New("rlp: decode error")
)

// Encodable is implemented by all consensus wire types.
type Encodable interface {
	// EncodeRLP appends the RLP encoding of the value to dst.
	EncodeRLP(dst []byte) []byte
}

// AppendUint64 encodes v as an RLP integer: minimal big-endian, zero as empty.
func AppendUint64(dst []byte, v uint64) []byte {
	if v == 0 {
		return append(dst, EmptyStringCode)
	}
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	i := 0
	for b[i] == 0 {
		i++
	}
	return AppendString(dst, b[i:])
}

// AppendUint8 encodes a u8 (value 0 encodes as empty string, matching alloy).
func AppendUint8(dst []byte, v uint8) []byte {
	return AppendUint64(dst, uint64(v))
}

// AppendUint32 encodes a u32.
func AppendUint32(dst []byte, v uint32) []byte {
	return AppendUint64(dst, uint64(v))
}

// AppendUint128 encodes a u128.
func AppendUint128(dst []byte, hi, lo uint64) []byte {
	if hi == 0 {
		return AppendUint64(dst, lo)
	}
	var b [16]byte
	for i := 15; i >= 8; i-- {
		b[i] = byte(lo)
		lo >>= 8
	}
	for i := 7; i >= 0; i-- {
		b[i] = byte(hi)
		hi >>= 8
	}
	i := 0
	for b[i] == 0 {
		i++
	}
	return AppendString(dst, b[i:])
}

// AppendString encodes a byte string with the RLP string header.
func AppendString(dst, s []byte) []byte {
	if len(s) == 1 && s[0] < EmptyStringCode {
		return append(dst, s[0])
	}
	dst = appendStringHeader(dst, len(s))
	return append(dst, s...)
}

func appendStringHeader(dst []byte, l int) []byte {
	if l < 56 {
		return append(dst, EmptyStringCode+byte(l))
	}
	return append(dst, appendLenPrefix(0xB7, l)...)
}

func appendListHeader(dst []byte, payloadLen int) []byte {
	if payloadLen < 56 {
		return append(dst, EmptyListCode+byte(payloadLen))
	}
	return append(dst, appendLenPrefix(0xF7, payloadLen)...)
}

func appendLenPrefix(base byte, l int) []byte {
	var b [8]byte
	i := 8
	for v := l; v > 0; v >>= 8 {
		i--
		b[i] = byte(v)
	}
	out := []byte{base + byte(8-i)}
	return append(out, b[i:]...)
}

// AppendList encodes the concatenated payload produced by build as a list.
func AppendList(dst []byte, build func(p []byte) []byte) []byte {
	payload := build(nil)
	dst = appendListHeader(dst, len(payload))
	return append(dst, payload...)
}

// AppendRaw appends pre-encoded bytes verbatim (used to splice payloads).
func AppendRaw(dst, encoded []byte) []byte { return append(dst, encoded...) }

// Encode produces the standalone encoding of v.
func Encode(v Encodable) []byte { return v.EncodeRLP(nil) }

// ---- decoding ----

// Stream decodes a byte slice sequentially.
type Stream struct {
	b []byte
}

func NewStream(b []byte) *Stream { return &Stream{b: b} }

// Remaining reports unconsumed bytes.
func (s *Stream) Remaining() int { return len(s.b) }

// Raw returns the unconsumed tail (does not advance).
func (s *Stream) Raw() []byte { return s.b }

// header parses the RLP header at the front of the stream.
func (s *Stream) header() (list bool, payloadLen int, err error) {
	if len(s.b) == 0 {
		return false, 0, ErrInputTooShort
	}
	b := s.b[0]
	switch {
	case b < EmptyStringCode:
		return false, 1, nil // single byte is its own payload
	case b <= 0xB7:
		l := int(b - EmptyStringCode)
		if len(s.b) < 1+l {
			return false, 0, ErrInputTooShort
		}
		if l == 1 && s.b[1] < EmptyStringCode {
			return false, 0, ErrNonCanonicalSingleByte
		}
		return false, l, nil
	case b >= 0xB8 && b <= 0xBF, b >= 0xF8:
		list = b >= 0xF8
		var code byte = 0xB7
		if list {
			code = 0xF7
		}
		lenOfLen := int(b - code)
		if len(s.b) < 1+lenOfLen {
			return false, 0, ErrInputTooShort
		}
		lenBytes := s.b[1 : 1+lenOfLen]
		if lenBytes[0] == 0 {
			return false, 0, ErrLeadingZero
		}
		var l uint64
		for _, c := range lenBytes {
			l = l<<8 | uint64(c)
		}
		if l < 56 {
			return false, 0, ErrNonCanonicalSize
		}
		if uint64(len(s.b)) < 1+uint64(lenOfLen)+l {
			return false, 0, ErrInputTooShort
		}
		return list, int(l), nil
	default: // 0xC0..0xF7 short list
		l := int(b - EmptyListCode)
		if len(s.b) < 1+l {
			return false, 0, ErrInputTooShort
		}
		return true, l, nil
	}
}

// Bytes decodes a byte-string item.
func (s *Stream) Bytes() ([]byte, error) {
	list, l, err := s.header()
	if err != nil {
		return nil, err
	}
	if list {
		return nil, ErrUnexpectedList
	}
	hs := headerSize(s.b, l, false)
	out := s.b[hs : hs+l]
	s.b = s.b[hs+l:]
	return out, nil
}

func headerSize(buf []byte, payloadLen int, list bool) int {
	b := buf[0]
	switch {
	case b < EmptyStringCode:
		return 0 // single byte IS the payload
	case b <= 0xB7 || (b >= 0xC0 && b <= 0xF7):
		return 1
	default:
		var code byte = 0xB7
		if b >= 0xF8 {
			code = 0xF7
		}
		return 1 + int(b-code)
	}
}

// List decodes a list item, returning a sub-stream over its payload.
func (s *Stream) List() (*Stream, error) {
	list, l, err := s.header()
	if err != nil {
		return nil, err
	}
	if !list {
		return nil, ErrUnexpectedString
	}
	hs := headerSize(s.b, l, true)
	payload := s.b[hs : hs+l]
	s.b = s.b[hs+l:]
	return &Stream{b: payload}, nil
}

// Uint64 decodes a canonical unsigned integer.
func (s *Stream) Uint64() (uint64, error) {
	b, err := s.Bytes()
	if err != nil {
		return 0, err
	}
	return leftPadUint64(b)
}

func leftPadUint64(b []byte) (uint64, error) {
	if len(b) > 8 {
		return 0, ErrOverflow
	}
	if len(b) == 0 {
		return 0, nil
	}
	if b[0] == 0 {
		return 0, ErrLeadingZero
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

// Uint128 decodes a u128.
func (s *Stream) Uint128() (hi, lo uint64, err error) {
	b, err := s.Bytes()
	if err != nil {
		return 0, 0, err
	}
	if len(b) > 16 {
		return 0, 0, ErrOverflow
	}
	if len(b) == 0 {
		return 0, 0, nil
	}
	if b[0] == 0 {
		return 0, 0, ErrLeadingZero
	}
	var v [16]byte
	copy(v[16-len(b):], b)
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(v[i])
	}
	for i := 8; i < 16; i++ {
		lo = lo<<8 | uint64(v[i])
	}
	return hi, lo, nil
}

// FixedBytes decodes a byte string of exactly n bytes.
func (s *Stream) FixedBytes(n int) ([]byte, error) {
	b, err := s.Bytes()
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, ErrUnexpectedLength
	}
	return b, nil
}

// Done checks the sub-stream was fully consumed.
func (s *Stream) Done() error {
	if len(s.b) != 0 {
		return ErrUnexpectedLength
	}
	return nil
}

// DecodeExact decodes one item and requires full consumption.
func DecodeExact(b []byte, fn func(s *Stream) error) error {
	s := NewStream(b)
	if err := fn(s); err != nil {
		return err
	}
	if s.Remaining() != 0 {
		return ErrInputTooLong
	}
	return nil
}
