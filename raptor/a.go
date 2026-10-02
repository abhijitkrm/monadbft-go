package raptor

// Ported from monad-bft/monad-raptor/src/r10/a.rs.
// Constraint-matrix A implant, RFC 5053 section 5.4.2.4.2.
//
//	               K               S       H
//	  +-----------------------+-------+-------+
//	S |        G_LDPC         |  I_S  | 0_SxH |
//	  +-----------------------+-------+-------+
//	H |        G_Half                 |  I_H  |
//	  +-------------------------------+-------+
//	N |        G_LT                   |
//	  +-------------------------------+

// aCommon implants the LDPC + Half (identity-augmented) rows.
func (p *codeParameters) aCommon(setElement func(i, j int)) {
	// G_LDPC
	p.gLDPC(setElement)

	s, h := p.numLDPC(), p.numHalf()

	// I_S
	for i := 0; i < s; i++ {
		setElement(i, p.numSource()+i)
	}

	// G_Half
	p.gHalf(func(i, j int) { setElement(s+i, j) })

	// I_H
	for i := 0; i < h; i++ {
		setElement(s+i, p.numSource()+s+i)
	}
}

// aWithGLT implants aCommon plus nrows of G_LT.
func (p *codeParameters) aWithGLT(numEncodedSymbols int, setElement func(i, j int)) {
	p.aCommon(setElement)
	p.gLT(func(i, j int) {
		setElement(p.numLDPC()+p.numHalf()+i, j)
	}, numEncodedSymbols)
}

// aSystematicIntermediate implants the A matrix whose inverse produces
// intermediate symbols from the constraint symbols.
func (p *codeParameters) aSystematicIntermediate(setElement func(i, j int)) {
	p.aWithGLT(p.numSource(), setElement)
}
