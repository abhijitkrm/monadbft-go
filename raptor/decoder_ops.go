package raptor

import "sort"

// Ported from monad-bft/monad-raptor/src/r10/nonsystematic/decoder/
// {decode,decode_peel,decode_reactivate,decode_inactivate,
// decode_inactive_gaussian,decode_finished}.rs.

// bufferFirstActiveIntermediateSymbol returns the lowest-indexed active
// symbol referenced by the buffer.
func (d *decoder) bufferFirstActiveIntermediateSymbol(bufferIndex uint16) uint16 {
	for _, id := range d.bufferState[bufferIndex].intermediateSymbolIDs.items() {
		if d.intermediateSymbolState[id].isActive() {
			return id
		}
	}
	panic("buffer has no active intermediate symbol")
}

// decrementBufferWeight lowers a buffer's active_used_weight by 1 and
// re-files it between the active/usable and inactivated weight maps.
func (d *decoder) decrementBufferWeight(bufferIndex uint16) {
	buf := &d.bufferState[bufferIndex]
	buf.activeUsedWeight--

	if buf.activeUsedWeight > 0 {
		d.buffersActiveUsable.updateBufferWeight(int(bufferIndex), buf.activeUsedWeight)
		return
	}

	// Leaving the active/usable heap: weight must have been 1.
	w := d.buffersActiveUsable.removeBufferWeight(int(bufferIndex))
	if w != 1 {
		panic("decrementBufferWeight: removed weight != 1")
	}

	if weight := buf.intermediateSymbolIDs.len(); weight > 0 {
		d.buffersInactivated.insertBufferWeight(int(bufferIndex), uint16(weight))
	} else {
		d.numRedundantBuffers++
	}
}

// bufferPeelXorEq XORs the Used buffer b's symbol ids into buffer a
// (a is Active or Usable), maintaining the per-symbol buffer lists.
func (d *decoder) bufferPeelXorEq(a, b uint16) {
	aref, bref := &d.bufferState[a], &d.bufferState[b]

	for _, symbolID := range bref.intermediateSymbolIDs.items() {
		sym := &d.intermediateSymbolState[symbolID]
		if !sym.isInactivated() {
			if !aref.intermediateSymbolIDs.remove(symbolID) {
				panic("peel: symbol missing from reducee buffer")
			}
		} else if aref.intermediateSymbolIDs.insertOrRemove(symbolID) {
			sym.inactivatedInsert(a)
		} else {
			sym.inactivatedRemove(a)
		}
	}
}

// tryPeel repeatedly takes a Usable buffer (active_used_weight==1), marks it
// Used, and reduces every other buffer containing its symbol.
func (d *decoder) tryPeel(xorBuffers func(dst, src bufferID)) bool {
	madeProgress := false

	for {
		if d.decodingDone() {
			break
		}
		reducingIndex, weight, ok := d.buffersActiveUsable.peekMin()
		if !ok || weight != 1 {
			break
		}

		if w := d.buffersActiveUsable.removeBufferWeight(int(reducingIndex)); w != weight {
			panic("tryPeel: weight mismatch")
		}

		symbolID := d.bufferFirstActiveIntermediateSymbol(reducingIndex)

		d.bufferState[reducingIndex].used = true

		reduceeIndices := d.intermediateSymbolState[symbolID].activeMakeUsed(reducingIndex)

		for _, reduceeIndex := range reduceeIndices.items() {
			if reduceeIndex == reducingIndex {
				continue
			}
			d.bufferPeelXorEq(reduceeIndex, reducingIndex)
			// The reducing buffer has active_used_weight == 1, so the
			// reducee loses exactly one active symbol.
			d.decrementBufferWeight(reduceeIndex)
			xorBuffers(
				d.bufferIndexToBufferID(reduceeIndex),
				d.bufferIndexToBufferID(reducingIndex),
			)
		}

		if d.bufferState[reducingIndex].intermediateSymbolIDs.len() == 1 &&
			int(symbolID) < d.params.numSource() {
			d.numSourceSymbolsPaired++
		}

		d.check()
		madeProgress = true
	}
	return madeProgress
}

// tryReactivateSymbols reactivates inactivated symbols that now appear as the
// sole member of a buffer (inactivated heap min-weight==1), and reduces every
// other buffer containing that symbol.
func (d *decoder) tryReactivateSymbols(xorBuffers func(dst, src bufferID)) bool {
	madeProgress := false

	for {
		if d.decodingDone() {
			break
		}
		reducingIndex, weight, ok := d.buffersInactivated.peekMin()
		if !ok || weight != 1 {
			break
		}

		d.buffersInactivated.removeBufferWeight(int(reducingIndex))

		reducing := &d.bufferState[reducingIndex]
		symbolID := reducing.firstIntermediateSymbolID()
		reducing.activeUsedWeight = 1
		reducing.used = true

		reduceeIndices := d.intermediateSymbolState[symbolID].inactivatedMakeUsed(reducingIndex)

		for _, reduceeIndex := range reduceeIndices.items() {
			if reduceeIndex == reducingIndex {
				continue
			}
			reducee := &d.bufferState[reduceeIndex]
			if !reducee.intermediateSymbolIDs.remove(symbolID) {
				panic("reactivate: symbol missing from reducee buffer")
			}

			if reducee.activeUsedWeight == 0 {
				if w := reducee.intermediateSymbolIDs.len(); w > 0 {
					d.buffersInactivated.updateBufferWeight(int(reduceeIndex), uint16(w))
				} else {
					d.buffersInactivated.removeBufferWeight(int(reduceeIndex))
					d.numRedundantBuffers++
				}
			}

			if reducee.isPaired() &&
				int(reducee.firstIntermediateSymbolID()) < d.params.numSource() {
				d.numSourceSymbolsPaired++
			}

			xorBuffers(
				d.bufferIndexToBufferID(reduceeIndex),
				d.bufferIndexToBufferID(reducingIndex),
			)
		}

		if int(symbolID) < d.params.numSource() {
			d.numSourceSymbolsPaired++
		}

		d.check()
		madeProgress = true
	}
	return madeProgress
}

// tryInactivateOneSymbol inactivates the lowest-indexed active symbol of the
// minimum-weight Active buffer.
func (d *decoder) tryInactivateOneSymbol() bool {
	bufferIndex, weight, ok := d.buffersActiveUsable.peekMin()
	if !ok || weight <= 1 {
		return false
	}

	symbolID := d.bufferFirstActiveIntermediateSymbol(bufferIndex)
	d.intermediateSymbolState[symbolID].activeInactivate()

	for _, b := range d.intermediateSymbolState[symbolID].inactivatedValues().items() {
		d.decrementBufferWeight(b)
	}

	d.check()
	return true
}

// bufferInactivatedXorEq XORs Inactivated buffer b's symbol ids into
// Inactivated buffer a, maintaining per-symbol buffer lists.
func (d *decoder) bufferInactivatedXorEq(a, b uint16) {
	aref, bref := &d.bufferState[a], &d.bufferState[b]

	for _, symbolID := range bref.intermediateSymbolIDs.items() {
		sym := &d.intermediateSymbolState[symbolID]
		if !sym.isInactivated() {
			if !aref.intermediateSymbolIDs.remove(symbolID) {
				panic("inactive gaussian: symbol missing from reducee buffer")
			}
		} else if aref.intermediateSymbolIDs.insertOrRemove(symbolID) {
			sym.inactivatedInsert(a)
		} else {
			sym.inactivatedRemove(a)
		}
	}
}

// tryInactiveGaussian runs full-pivot Gaussian elimination over the
// inactivated buffers × inactivated symbols incidence matrix.
func (d *decoder) tryInactiveGaussian(xorBuffers func(dst, src bufferID)) bool {
	if d.buffersInactivated.isEmpty() {
		return false
	}
	if _, w, _ := d.buffersInactivated.peekMin(); w == 1 {
		// Reactivatable — peel instead.
		return true
	}

	var inactivatedBufferIndices []uint16
	d.buffersInactivated.enumerate(func(b, _ uint16) {
		inactivatedBufferIndices = append(inactivatedBufferIndices, b)
	})

	symbolSet := map[uint16]struct{}{}
	for _, b := range inactivatedBufferIndices {
		for _, id := range d.bufferState[b].intermediateSymbolIDs.items() {
			symbolSet[id] = struct{}{}
		}
	}
	inactivatedSymbolIDs := make([]uint16, 0, len(symbolSet))
	for id := range symbolSet {
		inactivatedSymbolIDs = append(inactivatedSymbolIDs, id)
	}
	sort.Slice(inactivatedSymbolIDs, func(i, j int) bool {
		return inactivatedSymbolIDs[i] < inactivatedSymbolIDs[j]
	})

	if len(inactivatedBufferIndices) < len(inactivatedSymbolIDs) {
		// Need at least as many buffers as symbols to eliminate.
		return false
	}

	mat := newDenseMatrix(len(inactivatedBufferIndices), len(inactivatedSymbolIDs), false)
	for i, b := range inactivatedBufferIndices {
		for j, id := range inactivatedSymbolIDs {
			if d.bufferState[b].intermediateSymbolIDs.contains(id) {
				mat.set(i, j, true)
			}
		}
	}

	_ = mat.rowwiseEliminationGaussianFullPivot(func(op rowOperation) {
		reducee := inactivatedBufferIndices[op.i]
		reducing := inactivatedBufferIndices[op.j]
		d.bufferInactivatedXorEq(reducee, reducing)
		xorBuffers(
			d.bufferIndexToBufferID(reducee),
			d.bufferIndexToBufferID(reducing),
		)
	})

	for _, b := range inactivatedBufferIndices {
		if w := d.bufferState[b].intermediateSymbolIDs.len(); w > 0 {
			d.buffersInactivated.updateBufferWeight(int(b), uint16(w))
		} else {
			d.buffersInactivated.removeBufferWeight(int(b))
			d.numRedundantBuffers++
		}
	}

	d.check()
	return true
}

// tryDecode runs the peel → reactivate → (inactivated gaussian → inactivate)
// loop until done or stalled. inactivationSymbolThreshold gates how eagerly
// we fall back to inactivation decoding (>= K required; the managed decoder
// passes 1.5*K).
func (d *decoder) tryDecode(inactivationSymbolThreshold int, xorBuffers func(dst, src bufferID)) bool {
	if inactivationSymbolThreshold < d.params.numSource() {
		panic("inactivation_symbol_threshold < K")
	}

	// Only "try harder" (gaussian/inactivate) once we've received enough
	// usable (non-redundant) encoded symbols.
	usableBuffers := len(d.bufferState) - int(d.numRedundantBuffers)
	tryHarder := usableBuffers >= inactivationSymbolThreshold

	const (
		stateReactivate = iota
		statePeeling
		stateMaybeInactiveGaussian
		stateInactivateSymbol
		stateDone
	)
	operation := stateReactivate

	for !d.decodingDone() && operation != stateDone {
		switch operation {
		case stateReactivate:
			d.tryReactivateSymbols(xorBuffers)
			operation = statePeeling
		case statePeeling:
			if d.tryPeel(xorBuffers) {
				operation = stateReactivate
			} else {
				operation = stateMaybeInactiveGaussian
			}
		case stateMaybeInactiveGaussian:
			if !tryHarder {
				operation = stateDone
			} else if d.tryInactiveGaussian(xorBuffers) {
				operation = stateReactivate
			} else {
				operation = stateInactivateSymbol
			}
		case stateInactivateSymbol:
			if !tryHarder {
				operation = stateDone
			} else if d.tryInactivateOneSymbol() {
				operation = stateReactivate
			} else {
				operation = stateDone
			}
		}
	}

	return d.decodingDone()
}

func (d *decoder) decodingDone() bool {
	return d.numSourceSymbolsPaired == d.params.numSource()
}

// sourceSymbolToBufferID returns the paired buffer holding source symbol i,
// or false if not recovered.
func (d *decoder) sourceSymbolToBufferID(sourceSymbolID int) (bufferID, bool) {
	if sourceSymbolID >= d.params.numSource() {
		return bufferID{}, false
	}
	bufferIndex, ok := d.intermediateSymbolState[sourceSymbolID].usedBufferIndex()
	if !ok {
		return bufferID{}, false
	}
	buf := &d.bufferState[bufferIndex]
	if buf.intermediateSymbolIDs.len() != 1 {
		return bufferID{}, false
	}
	return d.bufferIndexToBufferID(bufferIndex), true
}
