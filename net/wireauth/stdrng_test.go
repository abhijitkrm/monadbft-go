package wireauth

// Test-only reproduction of Rust's StdRng (ChaCha12) seeded via
// SeedableRng::seed_from_u64 (PCG32 expansion to a 32-byte seed), matching
// upstream's handshake trace tests byte-for-byte.

import "encoding/binary"

type stdRng struct {
	state   [16]uint32
	results [16]uint32
	index   int // next unconsumed word in results
}

func pcg32(state *uint64) uint32 {
	const mul = 6364136223846793005
	const inc = 11634580027462260723
	*state = *state*mul + inc
	s := *state
	xorshifted := uint32(((s >> 18) ^ s) >> 27)
	rot := uint32(s >> 59)
	return xorshifted>>rot | xorshifted<<(32-rot)
}

func newStdRng(seed uint64) *stdRng {
	var seedBytes [32]byte
	st := seed
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(seedBytes[i*4:], pcg32(&st))
	}

	r := &stdRng{index: 16} // force block generation on first draw
	r.state[0] = 0x61707865
	r.state[1] = 0x3320646e
	r.state[2] = 0x79622d32
	r.state[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		r.state[4+i] = binary.LittleEndian.Uint32(seedBytes[i*4:])
	}
	// words 12,13 counter = 0; words 14,15 stream = 0
	return r
}

func chachaQR(s *[16]uint32, a, b, c, d int) {
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = s[d]<<16 | s[d]>>16
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = s[b]<<12 | s[b]>>20
	s[a] += s[b]
	s[d] ^= s[a]
	s[d] = s[d]<<8 | s[d]>>24
	s[c] += s[d]
	s[b] ^= s[c]
	s[b] = s[b]<<7 | s[b]>>25
}

func (r *stdRng) generateBlock() {
	var w [16]uint32
	copy(w[:], r.state[:])
	// 12 rounds = 6 double rounds (column + diagonal)
	for i := 0; i < 6; i++ {
		chachaQR(&w, 0, 4, 8, 12)
		chachaQR(&w, 1, 5, 9, 13)
		chachaQR(&w, 2, 6, 10, 14)
		chachaQR(&w, 3, 7, 11, 15)
		chachaQR(&w, 0, 5, 10, 15)
		chachaQR(&w, 1, 6, 11, 12)
		chachaQR(&w, 2, 7, 8, 13)
		chachaQR(&w, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		r.results[i] = w[i] + r.state[i]
	}
	// increment 64-bit counter (words 12,13)
	r.state[12]++
	if r.state[12] == 0 {
		r.state[13]++
	}
	r.index = 0
}

func (r *stdRng) nextUint32() uint32 {
	if r.index >= 16 {
		r.generateBlock()
	}
	v := r.results[r.index]
	r.index++
	return v
}

func (r *stdRng) Uint64() uint64 {
	lo := uint64(r.nextUint32())
	hi := uint64(r.nextUint32())
	return lo | hi<<32
}

func (r *stdRng) Read(b []byte) (int, error) {
	n := len(b)
	var tmp [4]byte
	for len(b) > 0 {
		binary.LittleEndian.PutUint32(tmp[:], r.nextUint32())
		c := copy(b, tmp[:])
		b = b[c:]
	}
	return n, nil
}
