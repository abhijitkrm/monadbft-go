//go:build raptordebug

package raptor

// Ported from monad-bft/monad-raptor/src/r10/nonsystematic/decoder/check.rs.
// Compiled only with -tags=raptordebug — mirrors Rust's cfg!(debug_assertions)
// gating of the invariant checks.

func (d *decoder) check() { d.checkForce() }

func bufferWeightMapCheck(m *bufferWeightMap) { m.checkForce() }

func (m *bufferWeightMap) checkForce() {
	// heapIndexToBufferIndex must be consistent with bufferIndexToWeight.
	seen := make([]uint16, len(m.bufferIndexToWeight))
	for _, b := range m.heapIndexToBufferIndex {
		seen[b] = m.bufferIndexToWeight[b]
	}
	for i, w := range m.bufferIndexToWeight {
		if seen[i] != w {
			panic("bufferWeightMap: weight map inconsistent with heap")
		}
	}

	// Min-heap ordering.
	for i := range m.heapIndexToBufferIndex {
		w := m.heapIndexToWeight(i)
		for _, child := range []int{2*i + 1, 2*i + 2} {
			if child < len(m.heapIndexToBufferIndex) &&
				m.heapIndexToWeight(child) < w {
				panic("bufferWeightMap: heap order violated")
			}
		}
	}

	for i, b := range m.heapIndexToBufferIndex {
		if int(m.bufferIndexToHeapIndex[b]) != i {
			panic("bufferWeightMap: heap index mapping broken")
		}
	}
}

func (d *decoder) checkForce() {
	d.checkElementsMatch()
	d.checkUsed()
	d.checkActiveUsable()
	d.checkInactivated()
	d.checkNumRedundantBuffers()
	d.checkNumSourceSymbolsPaired()
}

func (d *decoder) checkElementsMatch() {
	// buffer→symbol mapping implied by bufferState must equal the one implied
	// by intermediateSymbolState.
	for i := range d.bufferState {
		for _, j := range d.bufferState[i].intermediateSymbolIDs.items() {
			sym := &d.intermediateSymbolState[j]
			present := false
			if sym.state == symbolUsed {
				present = int(sym.bufferIndex) == i
			} else {
				present = sym.bufferIndices.contains(uint16(i))
			}
			if !present {
				panic("check: buffer lists symbol missing from symbol's buffer set")
			}
		}
	}
	for j := range d.intermediateSymbolState {
		sym := &d.intermediateSymbolState[j]
		if sym.state == symbolUsed {
			if !d.bufferState[sym.bufferIndex].intermediateSymbolIDs.contains(uint16(j)) {
				panic("check: used symbol missing from its buffer")
			}
			continue
		}
		for _, i := range sym.bufferIndices.items() {
			if !d.bufferState[i].intermediateSymbolIDs.contains(uint16(j)) {
				panic("check: symbol's buffer missing the symbol")
			}
		}
	}
}

func (d *decoder) checkUsed() {
	for i := range d.bufferState {
		if !d.bufferState[i].used {
			continue
		}
		if d.bufferState[i].activeUsedWeight != 1 {
			panic("check: used buffer weight != 1")
		}
		active := 0
		var activeID uint16
		for _, id := range d.bufferState[i].intermediateSymbolIDs.items() {
			if !d.intermediateSymbolState[id].isInactivated() {
				active++
				activeID = id
			}
		}
		if active != 1 || !d.intermediateSymbolState[activeID].isUsed() {
			panic("check: used buffer's single active symbol not used")
		}
	}
	for j := range d.intermediateSymbolState {
		if bi, ok := d.intermediateSymbolState[j].usedBufferIndex(); ok {
			if d.bufferState[bi].state() != bufferUsed {
				panic("check: used symbol's buffer not in Used state")
			}
		}
	}
}

func (d *decoder) checkActiveUsable() {
	expect := map[uint16]uint16{}
	d.buffersActiveUsable.enumerate(func(b, w uint16) { expect[b] = w })

	actual := map[uint16]uint16{}
	for i := range d.bufferState {
		var w uint16
		for _, j := range d.bufferState[i].intermediateSymbolIDs.items() {
			if !d.intermediateSymbolState[j].isInactivated() {
				w++
			}
		}
		if d.bufferState[i].activeUsedWeight != w {
			panic("check: active_used_weight mismatch")
		}
		switch d.bufferState[i].state() {
		case bufferActive, bufferUsable:
			actual[uint16(i)] = w
		}
	}
	if len(expect) != len(actual) {
		panic("check: active/usable heap size mismatch")
	}
	for b, w := range expect {
		if actual[b] != w {
			panic("check: active/usable heap weight mismatch")
		}
	}
}

func (d *decoder) checkInactivated() {
	expect := map[uint16]uint16{}
	d.buffersInactivated.enumerate(func(b, w uint16) { expect[b] = w })

	actual := map[uint16]uint16{}
	for i := range d.bufferState {
		if d.bufferState[i].state() == bufferInactivated {
			actual[uint16(i)] = uint16(d.bufferState[i].intermediateSymbolIDs.len())
		}
	}
	if len(expect) != len(actual) {
		panic("check: inactivated heap size mismatch")
	}
	for b, w := range expect {
		if actual[b] != w {
			panic("check: inactivated heap weight mismatch")
		}
	}
}

func (d *decoder) checkNumRedundantBuffers() {
	n := 0
	for i := range d.bufferState {
		if d.bufferState[i].state() == bufferRedundant {
			n++
		}
	}
	if int(d.numRedundantBuffers) != n {
		panic("check: num_redundant_buffers mismatch")
	}
}

func (d *decoder) checkNumSourceSymbolsPaired() {
	n := 0
	for i := range d.bufferState {
		if d.bufferState[i].isPaired() &&
			int(d.bufferState[i].firstIntermediateSymbolID()) < d.params.numSource() {
			n++
		}
	}
	if d.numSourceSymbolsPaired != n {
		panic("check: num_source_symbols_paired mismatch")
	}
}
