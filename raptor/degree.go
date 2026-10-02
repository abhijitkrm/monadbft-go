package raptor

// Ported from monad-bft/monad-raptor/src/r10/degree.rs.
// Degree Generator Deg(), RFC 5053 section 5.4.4.2.

const maxV uint32 = 1048576
const maxDegree = 40

func deg(v uint32) uint8 {
	switch {
	case v <= 10240:
		return 1
	case v <= 491581:
		return 2
	case v <= 712793:
		return 3
	case v <= 831694:
		return 4
	case v <= 948445:
		return 10
	case v <= 1032188:
		return 11
	case v <= 1048575:
		return 40
	default:
		panic("deg: v out of range")
	}
}
