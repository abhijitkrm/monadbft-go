package raptor

// Ported from monad-bft/monad-raptor/src/binary_search.rs.

// smallestIntegerSatisfying finds the smallest integer in [from, to)
// satisfying condition. Returns (value, true) or (0, false).
func smallestIntegerSatisfying(from, to int, condition func(int) bool) (int, bool) {
	lower, upper := from, to

	for lower < upper {
		pivot := (lower + upper) / 2
		if condition(pivot) {
			upper = pivot
		} else {
			lower = pivot + 1
		}
	}

	if lower == upper && upper < to {
		return upper, true
	}
	return 0, false
}
