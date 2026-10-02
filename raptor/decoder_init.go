package raptor

import (
	"fmt"
)

// Ported from monad-bft/monad-raptor/src/r10/nonsystematic/decoder/init.rs
// and receive_symbol.rs.

// newDecoder creates a decoder for numSourceSymbols with default capacity.
func newDecoder(numSourceSymbols int) (*decoder, error) {
	return decoderWithCapacity(numSourceSymbols, maxTriples)
}

// decoderWithCapacity initializes the S+H constraint buffers from the A
// matrix's LDPC/I_S/Half/I_H rows.
func decoderWithCapacity(numSourceSymbols, capacity int) (*decoder, error) {
	if numSourceSymbols < sourceSymbolsMin || numSourceSymbols > sourceSymbolsMax {
		return nil, fmt.Errorf("number of source symbols %d not in range %d..%d",
			numSourceSymbols, sourceSymbolsMin, sourceSymbolsMax)
	}
	params, err := newCodeParameters(numSourceSymbols)
	if err != nil {
		return nil, fmt.Errorf("CodeParameters for %d source symbols: %w",
			numSourceSymbols, err)
	}

	bufferState := make([]buffer, params.numLDPC()+params.numHalf())
	intermediateSymbolState := make([]intermediateSymbol, params.numIntermediate())

	append := func(bufferIndex, symbolID int) {
		bufferState[bufferIndex].appendActiveIntermediateSymbolID(symbolID)
		intermediateSymbolState[symbolID].activePush(bufferIndex)
	}

	// G_LDPC
	params.gLDPC(append)

	// I_S
	for bufferIndex := 0; bufferIndex < params.numLDPC(); bufferIndex++ {
		append(bufferIndex, params.numSource()+bufferIndex)
	}

	// G_Half
	params.gHalf(func(i, symbolID int) {
		append(params.numLDPC()+i, symbolID)
	})

	// I_H
	for i := 0; i < params.numHalf(); i++ {
		append(params.numLDPC()+i, params.numSource()+params.numLDPC()+i)
	}

	d := &decoder{
		params:                  params,
		bufferState:             bufferState,
		intermediateSymbolState: intermediateSymbolState,
	}

	for i := range bufferState {
		w := bufferState[i].activeUsedWeight
		if w == 0 {
			panic("constraint buffer with zero active weight")
		}
		d.buffersActiveUsable.insertBufferWeight(i, w)
	}

	d.check()
	return d, nil
}

// receivedEncodedSymbol registers a newly received encoded symbol: builds its
// buffer from the LT row, reduces it against already-Used buffers (emitting
// payload XORs through xorBuffers), then links the buffer into the symbol
// bookkeeping and weight maps.
func (d *decoder) receivedEncodedSymbol(encodingSymbolID int, xorBuffers func(dst, src bufferID)) {
	bufferIndex := uint16(len(d.bufferState))

	var buf buffer
	var usedBufferIndices []uint16

	d.params.ltSequence(encodingSymbolID, func(symbolID int) {
		sym := &d.intermediateSymbolState[symbolID]
		buf.appendIntermediateSymbolID(symbolID, !sym.isInactivated())
		if usedIndex, ok := sym.usedBufferIndex(); ok {
			usedBufferIndices = append(usedBufferIndices, usedIndex)
		}
	})

	// Reduce by every already-recovered (Used) intermediate symbol.
	for _, usedIndex := range usedBufferIndices {
		buf.xorEq(&d.bufferState[usedIndex])
		// The reducing buffer has active_used_weight == 1.
		buf.activeUsedWeight--
		xorBuffers(d.bufferIndexToBufferID(bufferIndex),
			d.bufferIndexToBufferID(usedIndex))
	}

	// Account buffer references on every remaining symbol.
	for _, id := range buf.intermediateSymbolIDs.items() {
		d.intermediateSymbolState[id].activeInactivatedPush(bufferIndex)
	}

	weight := buf.intermediateSymbolIDs.len()
	activeUsedWeight := buf.activeUsedWeight

	d.bufferState = append(d.bufferState, buf)

	if activeUsedWeight > 0 {
		d.buffersActiveUsable.insertBufferWeight(int(bufferIndex), activeUsedWeight)
	} else if weight > 0 {
		d.buffersInactivated.insertBufferWeight(int(bufferIndex), uint16(weight))
	} else {
		d.numRedundantBuffers++
	}

	d.check()
}

func (d *decoder) numRedundantEncodedSymbols() int {
	return int(d.numRedundantBuffers)
}
