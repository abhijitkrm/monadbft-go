package raptor

import "math/bits"

// Ported from monad-bft/monad-raptor/src/r10/half.rs.
// G_Half generation, RFC 5053 section 5.4.2.3 — Gray-code sequence filtered
// to words with exactly H' = (H+1)/2 set bits.

func (p *codeParameters) gHalf(setElement func(i, j int)) {
	hPrime := uint(p.numHalf()+1) >> 1

	i := uint64(0)
	mNext := func() uint64 {
		for {
			gI := i ^ (i >> 1)
			i++
			if uint(bits.OnesCount64(gI)) == hPrime {
				return gI
			}
		}
	}

	for j := 0; j < p.numSource()+p.numLDPC(); j++ {
		m := mNext()
		for h := 0; h < p.numHalf(); h++ {
			if m&(1<<uint(h)) != 0 {
				setElement(h, j)
			}
		}
	}
}
