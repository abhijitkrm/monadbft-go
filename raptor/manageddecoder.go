package raptor

import "errors"

// Ported from monad-bft/monad-raptor/src/r10/nonsystematic/decoder/
// managed_decoder.rs.

// ManagedDecoder owns the payload buffers: temp buffers for the S+H
// constraint symbols plus one buffer per received encoded symbol. It wires
// the decoder's emitted BufferId XOR operations into actual payload XORs.
type ManagedDecoder struct {
	numSourceSymbols int
	symbolLen        int
	decoder          *decoder
	bufferSet        *bufferSet
}

// Inactivation kicks in once usable received symbols >= threshold*K >> shift.
const inactivationSymbolThresholdMultiplier = 384
const inactivationSymbolThresholdShift = 8

type bufferSet struct {
	numTempBuffers int
	buffers        [][]byte
}

func newBufferSet(numTempBuffers, symbolLen int) *bufferSet {
	buffers := make([][]byte, numTempBuffers)
	for i := range buffers {
		buffers[i] = make([]byte, symbolLen)
	}
	return &bufferSet{numTempBuffers: numTempBuffers, buffers: buffers}
}

func (s *bufferSet) pushBuffer(buf []byte) { s.buffers = append(s.buffers, buf) }

func (s *bufferSet) bufferIndex(id bufferID) int {
	if id.temp {
		return id.index
	}
	return s.numTempBuffers + id.index
}

func (s *bufferSet) xorBuffers(a, b bufferID) {
	ai, bi := s.bufferIndex(a), s.bufferIndex(b)
	if ai == bi {
		panic("xorBuffers: asked to XOR buffer with itself")
	}
	dst, src := s.buffers[ai], s.buffers[bi]
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func (s *bufferSet) buffer(id bufferID) []byte { return s.buffers[s.bufferIndex(id)] }

// NewManagedDecoder builds a decoder for numSourceSymbols source symbols of
// symbolLen bytes each. encodedSymbolCapacity just preallocates bookkeeping.
func NewManagedDecoder(numSourceSymbols, encodedSymbolCapacity, symbolLen int) (*ManagedDecoder, error) {
	d, err := decoderWithCapacity(numSourceSymbols, encodedSymbolCapacity)
	if err != nil {
		return nil, err
	}
	if symbolLen <= 0 {
		return nil, errors.New("symbol_len must be positive")
	}
	return &ManagedDecoder{
		numSourceSymbols: numSourceSymbols,
		symbolLen:        symbolLen,
		decoder:          d,
		bufferSet:        newBufferSet(d.numTempBuffersRequired(), symbolLen),
	}, nil
}

// ReceivedEncodedSymbol registers a received encoded symbol payload.
func (m *ManagedDecoder) ReceivedEncodedSymbol(data []byte, encodingSymbolID int) {
	if len(data) != m.symbolLen {
		panic("ManagedDecoder: symbol length mismatch")
	}
	buf := make([]byte, len(data))
	copy(buf, data)
	m.bufferSet.pushBuffer(buf)
	m.decoder.receivedEncodedSymbol(encodingSymbolID, m.bufferSet.xorBuffers)
}

func (m *ManagedDecoder) NumSourceSymbols() int { return m.numSourceSymbols }
func (m *ManagedDecoder) SymbolLen() int        { return m.symbolLen }
func (m *ManagedDecoder) InactivationThreshold() int {
	return (inactivationSymbolThresholdMultiplier * m.numSourceSymbols) >>
		inactivationSymbolThresholdShift
}

// TryDecode advances the decode state machine; true iff all source symbols
// have been recovered.
func (m *ManagedDecoder) TryDecode() bool {
	return m.decoder.tryDecode(m.InactivationThreshold(), m.bufferSet.xorBuffers)
}

func (m *ManagedDecoder) DecodingDone() bool { return m.decoder.decodingDone() }

func (m *ManagedDecoder) NumEncodedSymbolsReceived() int {
	return m.decoder.numEncodedSymbolsReceived()
}

// ReconstructSourceData returns the decoded source symbols concatenated, or
// nil if not all are recovered.
func (m *ManagedDecoder) ReconstructSourceData() []byte {
	out := make([]byte, 0, m.numSourceSymbols*m.symbolLen)
	for i := 0; i < m.numSourceSymbols; i++ {
		id, ok := m.decoder.sourceSymbolToBufferID(i)
		if !ok {
			return nil
		}
		out = append(out, m.bufferSet.buffer(id)...)
	}
	return out
}
