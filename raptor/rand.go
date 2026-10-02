package raptor

// Ported from monad-bft/monad-raptor/src/r10/rand.rs.
// Random Generator function, RFC 5053 section 5.4.4.1.

// rand computes Rand[X, i, m] = (V0[(X+i) % 256] ^ V1[(floor(X/256)+i) % 256]) % m.
func rand(x uint16, i uint8, m uint32) uint32 {
	v0Index := (int(x) + int(i)) & 0xff
	v1Index := ((int(x) >> 8) + int(i)) & 0xff
	return (v0Table[v0Index] ^ v1Table[v1Index]) % m
}
