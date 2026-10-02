package raptor

// Ported from monad-bft/monad-raptor/src/r10/ldpc.rs.
// G_LDPC generation, RFC 5053 section 5.4.2.3.

func (p *codeParameters) ldpcTriple(sourceSymbol int) (b1, b2, b3 int) {
	s := p.numLDPC()
	a := 1 + (sourceSymbol/s)%(s-1)
	b1 = sourceSymbol % s
	b2 = (b1 + a) % s
	b3 = (b2 + a) % s
	return b1, b2, b3
}

// gLDPC implants G_LDPC: setElement(row, col) for each nonzero.
func (p *codeParameters) gLDPC(setElement func(i, j int)) {
	for i := 0; i < p.numSource(); i++ {
		b1, b2, b3 := p.ldpcTriple(i)
		b := [3]int{b1, b2, b3}
		if b[0] > b[1] {
			b[0], b[1] = b[1], b[0]
		}
		if b[1] > b[2] {
			b[1], b[2] = b[2], b[1]
		}
		if b[0] > b[1] {
			b[0], b[1] = b[1], b[0]
		}
		for _, el := range b {
			setElement(el, i)
		}
	}
}
