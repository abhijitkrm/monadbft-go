package raptor

import "sort"

// Ported from monad-bft/monad-raptor/src/r10/lt.rs.
// LT sequence / Triple Generator, RFC 5053 sections 5.4.4.3-4.

const maxTriples = 65521

// trip computes Trip(), RFC 5053 section 5.4.4.4.
func (p *codeParameters) trip(encodingSymbolID uint16) (d uint8, a, b uint16) {
	if int(encodingSymbolID) >= maxTriples {
		panic("trip: encoding_symbol_id out of range")
	}
	id := int(encodingSymbolID)

	// Q = 65521, the largest prime smaller than 2^16.
	const q = 65521
	// A = (53591 + J(K)*997) % Q
	aa := (53591 + p.systematicIdx()*997) % q
	// B = 10267*(J(K)+1) % Q
	bb := (10267 * (p.systematicIdx() + 1)) % q
	// Y = (B + X*A) % Q
	y := uint16((bb + id*aa) % q)

	// d = Deg[Rand[Y, 0, 2^20]]
	d = deg(rand(y, 0, 1<<20))

	lp := uint32(p.numIntermediateSymbolsPrime)
	// a = 1 + Rand[Y, 1, L'-1]
	a = uint16(1 + rand(y, 1, lp-1))
	// b = Rand[Y, 2, L']
	b = uint16(rand(y, 2, lp))
	return d, a, b
}

// ltSequence calls setElement for each index of the LT row, RFC 5053 5.4.4.3.
func (p *codeParameters) ltSequence(encodingSymbolID int, setElement func(int)) {
	d, a, b := p.trip(uint16(encodingSymbolID))

	numSymbols := int(d)
	if l := p.numIntermediate(); numSymbols > l {
		numSymbols = l
	}

	bb := int(b)
	aa := int(a)
	symbols := make([]int, 0, numSymbols)
	for i := 0; i < numSymbols; i++ {
		for bb >= p.numIntermediate() {
			bb = (bb + aa) % p.numIntermediatePrime()
		}
		symbols = append(symbols, bb)
		bb = (bb + aa) % p.numIntermediatePrime()
	}
	sort.Ints(symbols)
	for _, s := range symbols {
		setElement(s)
	}
}

// gLT implants G_LT: row i of the bottom block, RFC 5053 5.4.4.3.
func (p *codeParameters) gLT(setElement func(i, j int), nrows int) {
	for i := 0; i < nrows; i++ {
		p.ltSequence(i, func(j int) { setElement(i, j) })
	}
}
