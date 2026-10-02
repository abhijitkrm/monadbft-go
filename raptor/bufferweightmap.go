package raptor

// Ported from monad-bft/monad-raptor/src/r10/nonsystematic/decoder/
// buffer_weight_map.rs — a min-heap over buffer indices ordered by weight.
// Weights are u16; 0 in bufferIndexToWeight means "not in heap" (all real
// weights are >= 1).

type bufferWeightMap struct {
	heapIndexToBufferIndex []uint16
	bufferIndexToWeight    []uint16 // 0 = absent
	bufferIndexToHeapIndex []uint16
}

func (m *bufferWeightMap) isEmpty() bool { return len(m.heapIndexToBufferIndex) == 0 }

func (m *bufferWeightMap) peekMin() (bufferIndex, weight uint16, ok bool) {
	if len(m.heapIndexToBufferIndex) == 0 {
		return 0, 0, false
	}
	b := m.heapIndexToBufferIndex[0]
	return b, m.bufferIndexToWeight[b], true
}

func (m *bufferWeightMap) heapIndexToWeight(heapIndex int) uint16 {
	return m.bufferIndexToWeight[m.heapIndexToBufferIndex[heapIndex]]
}

func (m *bufferWeightMap) swap(ha, hb int) {
	ba, bb := m.heapIndexToBufferIndex[ha], m.heapIndexToBufferIndex[hb]
	m.heapIndexToBufferIndex[ha], m.heapIndexToBufferIndex[hb] = bb, ba
	m.bufferIndexToHeapIndex[ba], m.bufferIndexToHeapIndex[bb] = uint16(hb), uint16(ha)
}

func (m *bufferWeightMap) pullUp(heapIndex int) {
	for heapIndex != 0 {
		parent := (heapIndex - 1) / 2
		if m.heapIndexToWeight(parent) <= m.heapIndexToWeight(heapIndex) {
			break
		}
		m.swap(heapIndex, parent)
		heapIndex = parent
	}
}

func (m *bufferWeightMap) pushDown(heapIndex int) {
	for {
		min := heapIndex
		for _, child := range []int{2*heapIndex + 1, 2*heapIndex + 2} {
			if child < len(m.heapIndexToBufferIndex) &&
				m.heapIndexToWeight(child) < m.heapIndexToWeight(min) {
				min = child
			}
		}
		if min == heapIndex {
			return
		}
		m.swap(heapIndex, min)
		heapIndex = min
	}
}

// insertBufferWeight adds bufferIndex with the given weight (must be >= 1
// and not already present).
func (m *bufferWeightMap) insertBufferWeight(bufferIndex int, weight uint16) {
	if weight == 0 {
		panic("insertBufferWeight: zero weight")
	}
	heapIndex := len(m.heapIndexToBufferIndex)
	m.heapIndexToBufferIndex = append(m.heapIndexToBufferIndex, uint16(bufferIndex))

	if len(m.bufferIndexToWeight) < bufferIndex+1 {
		for len(m.bufferIndexToWeight) < bufferIndex+1 {
			m.bufferIndexToWeight = append(m.bufferIndexToWeight, 0)
			m.bufferIndexToHeapIndex = append(m.bufferIndexToHeapIndex, 0)
		}
	}
	if m.bufferIndexToWeight[bufferIndex] != 0 {
		panic("insertBufferWeight: buffer already present")
	}
	m.bufferIndexToWeight[bufferIndex] = weight
	m.bufferIndexToHeapIndex[bufferIndex] = uint16(heapIndex)

	m.pullUp(heapIndex)
	m.check()
}

func (m *bufferWeightMap) removeHeapIndex(heapIndex int, bufferIndex uint16) {
	last := len(m.heapIndexToBufferIndex) - 1
	if heapIndex != last {
		m.swap(heapIndex, last)
	}
	m.heapIndexToBufferIndex = m.heapIndexToBufferIndex[:last]

	prevWeight := m.bufferIndexToWeight[bufferIndex]
	m.bufferIndexToWeight[bufferIndex] = 0

	if heapIndex != last {
		switch {
		case m.heapIndexToWeight(heapIndex) < prevWeight:
			m.pullUp(heapIndex)
		case m.heapIndexToWeight(heapIndex) > prevWeight:
			m.pushDown(heapIndex)
		}
	}
	m.check()
}

func (m *bufferWeightMap) removeMin() {
	m.removeHeapIndex(0, m.heapIndexToBufferIndex[0])
}

func (m *bufferWeightMap) removeBufferWeight(bufferIndex int) uint16 {
	weight := m.bufferIndexToWeight[bufferIndex]
	m.removeHeapIndex(int(m.bufferIndexToHeapIndex[bufferIndex]), uint16(bufferIndex))
	return weight
}

func (m *bufferWeightMap) updateBufferWeight(bufferIndex int, weight uint16) {
	prev := m.bufferIndexToWeight[bufferIndex]
	if prev == weight {
		return
	}
	m.bufferIndexToWeight[bufferIndex] = weight
	heapIndex := int(m.bufferIndexToHeapIndex[bufferIndex])
	if weight < prev {
		m.pullUp(heapIndex)
	} else {
		m.pushDown(heapIndex)
	}
	m.check()
}

func (m *bufferWeightMap) enumerate(fn func(bufferIndex, weight uint16)) {
	for _, b := range m.heapIndexToBufferIndex {
		fn(b, m.bufferIndexToWeight[b])
	}
}

// check verifies the heap invariants under the raptordebug build tag.
func (m *bufferWeightMap) check() { bufferWeightMapCheck(m) }
