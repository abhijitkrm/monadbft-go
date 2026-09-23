package validator

import "encoding/binary"

// chacha20Stream replicates rand_chacha 0.3.1 ChaCha20Rng keystream:
// standard ChaCha20 block function, 64-bit block counter at words 12-13,
// 64-bit stream id at words 14-15 (zero), key = 32-byte seed.
type chacha20Stream struct {
	state   [16]uint32
	counter uint64
	buf     [64]byte
	pos     int // bytes consumed in buf; 64 = need refill
}

func newChaCha20Stream(key [32]byte) *chacha20Stream {
	s := &chacha20Stream{pos: 64}
	s.state[0] = 0x61707865
	s.state[1] = 0x3320646e
	s.state[2] = 0x79622d32
	s.state[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		s.state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	// words 12-13 = counter (start 0), 14-15 = stream id (0)
	return s
}

func quarterRound(st *[16]uint32, a, b, c, d int) {
	st[a] += st[b]
	st[d] ^= st[a]
	st[d] = st[d]<<16 | st[d]>>16
	st[c] += st[d]
	st[b] ^= st[c]
	st[b] = st[b]<<12 | st[b]>>20
	st[a] += st[b]
	st[d] ^= st[a]
	st[d] = st[d]<<8 | st[d]>>24
	st[c] += st[d]
	st[b] ^= st[c]
	st[b] = st[b]<<7 | st[b]>>25
}

func (s *chacha20Stream) refill() {
	var w [16]uint32
	copy(w[:], s.state[:])
	for i := 0; i < 10; i++ {
		quarterRound(&w, 0, 4, 8, 12)
		quarterRound(&w, 1, 5, 9, 13)
		quarterRound(&w, 2, 6, 10, 14)
		quarterRound(&w, 3, 7, 11, 15)
		quarterRound(&w, 0, 5, 10, 15)
		quarterRound(&w, 1, 6, 11, 12)
		quarterRound(&w, 2, 7, 8, 13)
		quarterRound(&w, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(s.buf[i*4:], w[i]+s.state[i])
	}
	s.counter++
	s.state[12] = uint32(s.counter)
	s.state[13] = uint32(s.counter >> 32)
	s.pos = 0
}

// fill mirrors RngCore::fill_bytes on the keystream.
func (s *chacha20Stream) fill(dst []byte) {
	for len(dst) > 0 {
		if s.pos == 64 {
			s.refill()
		}
		n := copy(dst, s.buf[s.pos:])
		dst = dst[n:]
		s.pos += n
	}
}
