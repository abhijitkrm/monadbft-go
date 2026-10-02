package raptor

import (
	"errors"
	"fmt"
)

// Ported from monad-bft/monad-raptor/src/r10/nonsystematic/encoder.rs.
// Non-systematic RFC 5053 Raptor encoder.

// Encoder produces coded symbols for a source buffer split into fixed-length
// source symbols. Intermediate symbols i < numFullSourceSymbols come directly
// from src; i >= numFullSourceSymbols come from derivedSymbols, which holds
// (in order): the NUL-padded trailing partial source symbol, any NUL padding
// needed to reach sourceSymbolsMin, the LDPC symbols, then the Half symbols.
type Encoder struct {
	src       []byte
	symbolLen int

	params *codeParameters

	numFullSourceSymbols int
	derivedSymbols       [][]byte
}

// NewEncoder builds an Encoder for src split into symbolLen-byte symbols.
func NewEncoder(src []byte, symbolLen int) (*Encoder, error) {
	if symbolLen == 0 {
		return nil, errors.New("symbol_len == 0")
	}

	numFullSourceSymbols := len(src) / symbolLen
	numSourceSymbols := numFullSourceSymbols

	var shadowed [][]byte

	if rem := len(src) % symbolLen; rem != 0 {
		symbol := make([]byte, symbolLen)
		copy(symbol[:rem], src[numFullSourceSymbols*symbolLen:])
		shadowed = append(shadowed, symbol)
		numSourceSymbols++
	}

	for numSourceSymbols < sourceSymbolsMin {
		shadowed = append(shadowed, make([]byte, symbolLen))
		numSourceSymbols++
	}

	if numSourceSymbols > sourceSymbolsMax {
		return nil, fmt.Errorf("number of source symbols %d exceeds %d",
			numSourceSymbols, sourceSymbolsMax)
	}

	params, err := newCodeParameters(numSourceSymbols)
	if err != nil {
		return nil, fmt.Errorf("CodeParameters for %d source symbols: %w",
			numSourceSymbols, err)
	}

	// A-matrix left block (G_LDPC | G_Half-left) rows, followed by the
	// G_Half right block separately.
	gLDPCHalf := make([][]uint16, params.numLDPC()+params.numHalf())
	gHalfRight := make([][]uint16, params.numHalf())

	params.gLDPC(func(i, j int) { gLDPCHalf[i] = append(gLDPCHalf[i], uint16(j)) })
	params.gHalf(func(i, j int) {
		if j < params.numSource() {
			gLDPCHalf[params.numLDPC()+i] = append(
				gLDPCHalf[params.numLDPC()+i], uint16(j))
		} else {
			gHalfRight[i] = append(gHalfRight[i], uint16(j-params.numSource()))
		}
	})

	sourceAt := func(index int) []byte {
		if index < numFullSourceSymbols {
			return src[index*symbolLen : (index+1)*symbolLen]
		}
		return shadowed[index-numFullSourceSymbols]
	}

	makeRedundant := func(sourceSet []uint16) []byte {
		symbol := make([]byte, symbolLen)
		for start := 0; start < len(sourceSet); start += maxSources {
			end := start + maxSources
			if end > len(sourceSet) {
				end = len(sourceSet)
			}
			chunk := make([][]byte, 0, end-start)
			for _, idx := range sourceSet[start:end] {
				chunk = append(chunk, sourceAt(int(idx)))
			}
			xorEq(symbol, chunk)
		}
		return symbol
	}

	ldpcHalfSymbols := make([][]byte, len(gLDPCHalf))
	for i, set := range gLDPCHalf {
		ldpcHalfSymbols[i] = makeRedundant(set)
	}

	// Multiply the Half rows by g_half_right (serial — small).
	ldpcSymbols := ldpcHalfSymbols[:params.numLDPC()]
	halfSymbols := ldpcHalfSymbols[params.numLDPC():]
	for i := range halfSymbols {
		for start := 0; start < len(gHalfRight[i]); start += maxSources {
			end := start + maxSources
			if end > len(gHalfRight[i]) {
				end = len(gHalfRight[i])
			}
			chunk := make([][]byte, 0, end-start)
			for _, idx := range gHalfRight[i][start:end] {
				chunk = append(chunk, ldpcSymbols[idx])
			}
			xorEq(halfSymbols[i], chunk)
		}
	}

	return &Encoder{
		src:                  src,
		symbolLen:            symbolLen,
		params:               params,
		numFullSourceSymbols: numFullSourceSymbols,
		derivedSymbols:       append(shadowed, ldpcHalfSymbols...),
	}, nil
}

// NumSourceSymbols returns K for this encoding.
func (e *Encoder) NumSourceSymbols() int { return e.params.numSource() }

func (e *Encoder) buffer(index int) []byte {
	if index < e.numFullSourceSymbols {
		return e.src[index*e.symbolLen : (index+1)*e.symbolLen]
	}
	return e.derivedSymbols[index-e.numFullSourceSymbols]
}

// EncodeSymbol writes encoded symbol `encodingSymbolID` into dst, which must
// be symbolLen bytes and zero-filled on entry.
func (e *Encoder) EncodeSymbol(dst []byte, encodingSymbolID int) {
	if len(dst) != e.symbolLen {
		panic("EncodeSymbol: dst length != symbol_len")
	}
	var indices []int
	e.params.ltSequence(encodingSymbolID, func(el int) { indices = append(indices, el) })

	for start := 0; start < len(indices); start += maxSources {
		end := start + maxSources
		if end > len(indices) {
			end = len(indices)
		}
		chunk := make([][]byte, 0, end-start)
		for _, idx := range indices[start:end] {
			chunk = append(chunk, e.buffer(idx))
		}
		xorEq(dst, chunk)
	}
}
