package raptor

// Ported from monad-bft/monad-raptor/src/r10/parameters.rs.
// CodeParameters — RFC 5053 section 5.4.2.3 parameter computation.

import "fmt"

// codeParameters carries the per-source-block code parameters.
//
//	K  = NumSourceSymbols
//	S  = NumLDPCSymbols
//	H  = NumHalfSymbols
//	L  = NumIntermediateSymbols     = K + S + H
//	L' = NumIntermediateSymbolsPrime = smallest prime >= L
//	J(K) = SystematicIndex
type codeParameters struct {
	numSourceSymbols            uint16
	numLDPCSymbols              uint16
	numHalfSymbols              uint8
	numIntermediateSymbols      uint16
	numIntermediateSymbolsPrime uint16
	systematicIndex             uint16
}

// RFC 5053 section 5.2 suggests a minimum of 4; section 5.7 provides
// systematic indices for 4+. Upstream adds custom indices for 1, 2, 3.
const sourceSymbolsMin = 1

// RFC 5053 section 5.1.2: Kmax = 8192.
const sourceSymbolsMax = 8192

const xMin, xMax = 4, 129

// determineX: smallest positive integer X with X*(X-1) >= 2*K.
func determineX(numSourceSymbols uint16) (uint8, error) {
	x, ok := smallestIntegerSatisfying(xMin, xMax+1, func(p int) bool {
		return p*(p-1) >= int(2*numSourceSymbols)
	})
	if !ok {
		return 0, fmt.Errorf("can't find x for num_source_symbols = %d", numSourceSymbols)
	}
	return uint8(x), nil
}

func smallestPrimeGreaterOrEqual(primeMin uint16) (uint16, error) {
	i, ok := smallestIntegerSatisfying(0, len(smallPrimes), func(p int) bool {
		return smallPrimes[p] >= primeMin
	})
	if !ok {
		return 0, fmt.Errorf("can't find small prime >= %d", primeMin)
	}
	return smallPrimes[i], nil
}

// determineNumLDPCSymbols: S = smallest prime >= ceil(0.01*K) + X.
func determineNumLDPCSymbols(numSourceSymbols uint16, x uint8) (uint16, error) {
	minS := (numSourceSymbols+99)/100 + uint16(x)
	return smallestPrimeGreaterOrEqual(minS)
}

// choose computes binomial n!/(k!(n-k)!); fits u16 for the bounded n used.
func choose(n, k uint8) uint16 {
	var c uint32 = 1
	for v := int(k) + 1; v <= int(n); v++ {
		c *= uint32(v)
	}
	for v := 2; v <= int(n)-int(k); v++ {
		c /= uint32(v)
	}
	return uint16(c)
}

const halfMin, halfMax = 5, 16

// determineNumHalfSymbols: H = smallest integer with choose(H, ceil(H/2)) >= K+S.
func determineNumHalfSymbols(numSourceSymbols, numLDPCSymbols uint16) (uint8, error) {
	h, ok := smallestIntegerSatisfying(halfMin, halfMax+1, func(p int) bool {
		h := uint8(p)
		return uint32(choose(h, (h+1)/2)) >= uint32(numSourceSymbols)+uint32(numLDPCSymbols)
	})
	if !ok {
		return 0, fmt.Errorf("can't find num_half_symbols for K=%d, S=%d",
			numSourceSymbols, numLDPCSymbols)
	}
	return uint8(h), nil
}

func newCodeParameters(numSourceSymbols int) (*codeParameters, error) {
	if numSourceSymbols < sourceSymbolsMin || numSourceSymbols > sourceSymbolsMax {
		return nil, fmt.Errorf("num_source_symbols %d not in range %d..%d",
			numSourceSymbols, sourceSymbolsMin, sourceSymbolsMax)
	}
	k := uint16(numSourceSymbols)

	x, err := determineX(k)
	if err != nil {
		return nil, err
	}
	s, err := determineNumLDPCSymbols(k, x)
	if err != nil {
		return nil, err
	}
	h, err := determineNumHalfSymbols(k, s)
	if err != nil {
		return nil, err
	}
	l := k + s + uint16(h)
	lp, err := smallestPrimeGreaterOrEqual(l)
	if err != nil {
		return nil, err
	}
	j, err := determineSystematicIndex(k)
	if err != nil {
		return nil, err
	}

	return &codeParameters{
		numSourceSymbols:            k,
		numLDPCSymbols:              s,
		numHalfSymbols:              h,
		numIntermediateSymbols:      l,
		numIntermediateSymbolsPrime: lp,
		systematicIndex:             j,
	}, nil
}

func (p *codeParameters) numSource() int       { return int(p.numSourceSymbols) }
func (p *codeParameters) numLDPC() int         { return int(p.numLDPCSymbols) }
func (p *codeParameters) numHalf() int         { return int(p.numHalfSymbols) }
func (p *codeParameters) numIntermediate() int { return int(p.numIntermediateSymbols) }
func (p *codeParameters) numIntermediatePrime() int {
	return int(p.numIntermediateSymbolsPrime)
}
func (p *codeParameters) systematicIdx() int { return int(p.systematicIndex) }
