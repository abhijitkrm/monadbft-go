package raptorcast

import "encoding/binary"

// chaCha20Rng reproduces rand_chacha 0.3.1's ChaCha20Rng: a sequential
// u32 keystream from ChaCha20 blocks (20 rounds = 10 double rounds),
// 64-bit block counter starting at 0, 64-bit stream id of 0. rand 0.8's
// BlockRng buffers 4 blocks per generate, but consumption is sequential,
// so a per-block stream is bit-identical.
type chaCha20Rng struct {
	state   [16]uint32
	results [16]uint32
	index   int
}

func newChaCha20Rng(seed [32]byte) *chaCha20Rng {
	r := &chaCha20Rng{index: 16}
	r.state[0] = 0x61707865
	r.state[1] = 0x3320646e
	r.state[2] = 0x79622d32
	r.state[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		r.state[4+i] = binary.LittleEndian.Uint32(seed[i*4:])
	}
	return r
}

func chachaQuarterRound(s *[16]uint32, a, b, c, d int) {
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

func (r *chaCha20Rng) generateBlock() {
	var w [16]uint32
	copy(w[:], r.state[:])
	for i := 0; i < 10; i++ {
		chachaQuarterRound(&w, 0, 4, 8, 12)
		chachaQuarterRound(&w, 1, 5, 9, 13)
		chachaQuarterRound(&w, 2, 6, 10, 14)
		chachaQuarterRound(&w, 3, 7, 11, 15)
		chachaQuarterRound(&w, 0, 5, 10, 15)
		chachaQuarterRound(&w, 1, 6, 11, 12)
		chachaQuarterRound(&w, 2, 7, 8, 13)
		chachaQuarterRound(&w, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		r.results[i] = w[i] + r.state[i]
	}
	r.state[12]++
	if r.state[12] == 0 {
		r.state[13]++
	}
	r.index = 0
}

// nextU32 — RngCore::next_u32 via BlockRng buffering.
func (r *chaCha20Rng) nextU32() uint32 {
	if r.index >= 16 {
		r.generateBlock()
	}
	v := r.results[r.index]
	r.index++
	return v
}

// genRangeU32 reproduces rand 0.8.6's `gen_range(0..ubound)` for u32:
// Lemire multiply-high sampling with a conservative zone reject.
func (r *chaCha20Rng) genRangeU32(ubound uint32) uint32 {
	if ubound == 0 {
		// range wraps to 0 → any integer will do.
		return r.nextU32()
	}
	rangeV := ubound
	// zone = (range << leading_zeros(range)) - 1, wrapping.
	shift := uint(0)
	for tmp := rangeV; tmp&(1<<31) == 0; tmp <<= 1 {
		shift++
	}
	zone := (rangeV << shift) - 1
	for {
		v := r.nextU32()
		prod := uint64(v) * uint64(rangeV)
		hi := uint32(prod >> 32)
		lo := uint32(prod)
		if lo <= zone {
			return hi
		}
	}
}

// genIndex — rand 0.8.6 seq::gen_index: u32 sampling for ubound ≤ u32::MAX.
func (r *chaCha20Rng) genIndex(ubound int) int {
	if uint64(ubound) <= uint64(^uint32(0)) {
		return int(r.genRangeU32(uint32(ubound)))
	}
	// 64-bit path (identical scheme with u64 wmul); never hit for
	// realistically-sized validator sets.
	rangeV := uint64(ubound)
	shift := uint(0)
	for tmp := rangeV; tmp&(1<<63) == 0; tmp <<= 1 {
		shift++
	}
	zone := (rangeV << shift) - 1
	for {
		v := uint64(r.nextU32()) | uint64(r.nextU32())<<32
		hi, lo := mul64hiLo(v, rangeV)
		if lo <= zone {
			return int(hi)
		}
	}
}

func mul64hiLo(a, b uint64) (hi, lo uint64) {
	// Full 128-bit product via 32-bit halves.
	aLo, aHi := a&0xffffffff, a>>32
	bLo, bHi := b&0xffffffff, b>>32
	cross := (aLo * bHi) + (aHi * bLo) + ((aLo * bLo) >> 32)
	hi = aHi*bHi + (cross >> 32)
	lo = a * b
	return hi, lo
}

// shuffle — rand 0.8.6 SliceRandom::shuffle: descending Fisher-Yates.
func (r *chaCha20Rng) shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i >= 1; i-- {
		j := r.genIndex(i + 1)
		swap(i, j)
	}
}

// deriveSeed — Rust regular::derive_seed: app hash left-padded to 32 bytes.
func deriveSeed(appMessageHash AppMessageHash) [32]byte {
	var seed [32]byte
	copy(seed[:], appMessageHash[:])
	return seed
}
