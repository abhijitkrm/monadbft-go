package raptor

// Ported from monad-bft/monad-raptor/src/r10/nonsystematic/decoder/{mod,buffer,
// buffer_id,buffer_state,intermediate_symbol}.rs.
// Decoder for the non-systematic R10 code.

// decoder drives the symbol-level state machine (buffer/symbol incidence,
// peeling, inactivation). Payload XORs are delegated to the caller via a
// callback taking (dst, src) BufferIds — the decoder never touches bytes.
type decoder struct {
	params *codeParameters

	// Per-buffer bookkeeping: ordered set of intermediate-symbol ids XORd in,
	// plus state implied by activeUsedWeight/used.
	bufferState []buffer

	// Per-intermediate-symbol bookkeeping: which buffers reference it, and
	// whether it is Active/Inactivated/Used.
	intermediateSymbolState []intermediateSymbol

	// Active/Usable buffers by active_used_weight; Inactivated buffers by
	// total weight.
	buffersActiveUsable bufferWeightMap
	buffersInactivated  bufferWeightMap

	numRedundantBuffers    uint16
	numSourceSymbolsPaired int
}

// bufferID identifies a decode payload slot: either a TempBuffer (one of the
// S+H constraint-symbol slots the caller pre-allocates) or a ReceiveBuffer
// (a slot pushed per received encoded symbol).
type bufferID struct {
	temp  bool
	index int
}

func (d *decoder) numRedundantIntermediateSymbols() int {
	return d.params.numLDPC() + d.params.numHalf()
}

func (d *decoder) numTempBuffersRequired() int {
	return d.numRedundantIntermediateSymbols()
}

func (d *decoder) numEncodedSymbolsReceived() int {
	return len(d.bufferState) - d.numRedundantIntermediateSymbols()
}

func (d *decoder) bufferIndexToBufferID(index uint16) bufferID {
	i := int(index)
	if i < d.numRedundantIntermediateSymbols() {
		return bufferID{temp: true, index: i}
	}
	return bufferID{temp: false, index: i - d.numRedundantIntermediateSymbols()}
}

// bufferState enumerates the implicit state of a buffer.
type bufferStateKind int

const (
	bufferActive      bufferStateKind = iota // weight>1, active_used_weight>1
	bufferUsable                             // weight>=1, active_used_weight==1, symbol active
	bufferUsed                               // weight>=1, active_used_weight==1, symbol used
	bufferInactivated                        // weight>0, active_used_weight==0
	bufferRedundant                          // weight==0
)

type buffer struct {
	intermediateSymbolIDs orderedSet
	activeUsedWeight      uint16
	used                  bool
}

func (b *buffer) state() bufferStateKind {
	if b.activeUsedWeight > 1 {
		return bufferActive
	}
	if b.activeUsedWeight == 1 && !b.used {
		return bufferUsable
	}
	if b.activeUsedWeight == 1 && b.used {
		return bufferUsed
	}
	if b.intermediateSymbolIDs.len() > 0 {
		return bufferInactivated
	}
	return bufferRedundant
}

func (b *buffer) isPaired() bool {
	return b.state() == bufferUsed && b.intermediateSymbolIDs.len() == 1
}

func (b *buffer) isReactivatable() bool {
	return b.state() == bufferInactivated && b.intermediateSymbolIDs.len() == 1
}

func (b *buffer) appendIntermediateSymbolID(id int, incrementActiveUsedWeight bool) {
	b.intermediateSymbolIDs.append(uint16(id))
	if incrementActiveUsedWeight {
		b.activeUsedWeight++
	}
}

func (b *buffer) appendActiveIntermediateSymbolID(id int) {
	b.appendIntermediateSymbolID(id, true)
}

func (b *buffer) firstIntermediateSymbolID() uint16 {
	v, _ := b.intermediateSymbolIDs.first()
	return v
}

// xorEq toggles other's symbol ids in b. Caller handles active_used_weight.
func (b *buffer) xorEq(other *buffer) {
	for _, id := range other.intermediateSymbolIDs.items() {
		b.intermediateSymbolIDs.insertOrRemove(id)
	}
}

type symbolState int

const (
	symbolActive symbolState = iota
	symbolInactivated
	symbolUsed
)

type intermediateSymbol struct {
	state         symbolState
	bufferIndices orderedSet // Active, Inactivated
	bufferIndex   uint16     // Used
}

func (s *intermediateSymbol) isActive() bool      { return s.state == symbolActive }
func (s *intermediateSymbol) isInactivated() bool { return s.state == symbolInactivated }
func (s *intermediateSymbol) isUsed() bool        { return s.state == symbolUsed }

func (s *intermediateSymbol) usedBufferIndex() (uint16, bool) {
	if s.state == symbolUsed {
		return s.bufferIndex, true
	}
	return 0, false
}

// activePush appends bufferIndex; must exceed every element already present.
func (s *intermediateSymbol) activePush(bufferIndex int) {
	if s.state != symbolActive {
		panic("activePush on non-active symbol")
	}
	s.bufferIndices.append(uint16(bufferIndex))
}

// activeInactivatedPush appends to either an Active or Inactivated symbol.
func (s *intermediateSymbol) activeInactivatedPush(bufferIndex uint16) {
	if s.state == symbolUsed {
		panic("activeInactivatedPush on used symbol")
	}
	s.bufferIndices.append(bufferIndex)
}

// activeInactivate converts Active→Inactivated in place.
func (s *intermediateSymbol) activeInactivate() {
	if s.state != symbolActive {
		panic("activeInactivate on non-active symbol")
	}
	s.state = symbolInactivated
}

// activeMakeUsed converts Active→Used and returns the buffer-index set.
func (s *intermediateSymbol) activeMakeUsed(bufferIndex uint16) orderedSet {
	if s.state != symbolActive {
		panic("activeMakeUsed on non-active symbol")
	}
	indices := s.bufferIndices
	s.state = symbolUsed
	s.bufferIndex = bufferIndex
	s.bufferIndices = orderedSet{}
	return indices
}

func (s *intermediateSymbol) inactivatedValues() *orderedSet {
	if s.state != symbolInactivated {
		panic("inactivatedValues on non-inactivated symbol")
	}
	return &s.bufferIndices
}

func (s *intermediateSymbol) inactivatedInsert(bufferIndex uint16) {
	if s.state != symbolInactivated {
		panic("inactivatedInsert on non-inactivated symbol")
	}
	s.bufferIndices.insert(bufferIndex)
}

func (s *intermediateSymbol) inactivatedRemove(bufferIndex uint16) {
	if s.state != symbolInactivated {
		panic("inactivatedRemove on non-inactivated symbol")
	}
	s.bufferIndices.remove(bufferIndex)
}

// inactivatedMakeUsed converts Inactivated→Used and returns the buffer-index set.
func (s *intermediateSymbol) inactivatedMakeUsed(bufferIndex uint16) orderedSet {
	if s.state != symbolInactivated {
		panic("inactivatedMakeUsed on non-inactivated symbol")
	}
	indices := s.bufferIndices
	s.state = symbolUsed
	s.bufferIndex = bufferIndex
	s.bufferIndices = orderedSet{}
	return indices
}
