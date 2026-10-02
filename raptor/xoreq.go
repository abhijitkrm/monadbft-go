package raptor

// Ported from monad-bft/monad-raptor/src/xor_eq.rs.

// maxSources bounds the fan-in of xorEq (RFC 5053 degree cap usage site).
const maxSources = 6

func xorEqN(dst []byte, srcs ...[]byte) {
	for i := range dst {
		var acc byte
		for _, src := range srcs {
			acc ^= src[i]
		}
		dst[i] ^= acc
	}
}

// xorEq XORs every slice in srcs into dst. len(srcs) must be in [1,6].
func xorEq(dst []byte, srcs [][]byte) {
	for _, s := range srcs {
		if len(s) != len(dst) {
			panic("xorEq: length mismatch")
		}
	}
	if len(srcs) < 1 || len(srcs) > maxSources {
		panic("xorEq: source count out of range")
	}
	xorEqN(dst, srcs...)
}
