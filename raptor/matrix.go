package raptor

import "fmt"

// Ported from monad-bft/monad-raptor/src/matrix/*.
// GF(2) dense matrix + row/column-permutation wrapper + Gaussian-elimination
// schedule generation. All arithmetic is XOR over bool cells.

// denseMatrix is a row-major bool matrix.
type denseMatrix struct {
	data  []bool
	nrows int
	ncols int
}

func newDenseMatrix(nrows, ncols int, elem bool) *denseMatrix {
	data := make([]bool, nrows*ncols)
	if elem {
		for i := range data {
			data[i] = true
		}
	}
	return &denseMatrix{data: data, nrows: nrows, ncols: ncols}
}

func (m *denseMatrix) at(i, j int) bool     { return m.data[i*m.ncols+j] }
func (m *denseMatrix) set(i, j int, v bool) { m.data[i*m.ncols+j] = v }
func (m *denseMatrix) flip(i, j int)        { m.data[i*m.ncols+j] = !m.data[i*m.ncols+j] }
func (m *denseMatrix) xorInto(i, j int, v bool) {
	m.data[i*m.ncols+j] = m.data[i*m.ncols+j] != v // ^= for bool
}

// String renders the matrix for debugging (1/0 grid).
func (m *denseMatrix) String() string {
	var b []byte
	b = append(b, '\n')
	for i := 0; i < m.nrows; i++ {
		b = append(b, "  |"...)
		for j := 0; j < m.ncols; j++ {
			if m.at(i, j) {
				b = append(b, " 1"...)
			} else {
				b = append(b, " 0"...)
			}
		}
		b = append(b, " |\n"...)
	}
	return string(b)
}

// rowOperation records a row operation in *physical* row coordinates:
// SubAssign{i, j} means physical row i ^= physical row j.
type rowOperation struct {
	i, j int
}

// rcPermutation is a virtual↔physical index permutation.
type rcPermutation struct {
	virtToPhys []uint16
	physToVirt []uint16
}

func newRCPermutation(n int) rcPermutation {
	v2p := make([]uint16, n)
	p2v := make([]uint16, n)
	for i := range v2p {
		v2p[i] = uint16(i)
		p2v[i] = uint16(i)
	}
	return rcPermutation{virtToPhys: v2p, physToVirt: p2v}
}

func (p *rcPermutation) index(a int) int { return int(p.virtToPhys[a]) }

func (p *rcPermutation) swap(a, b int) {
	p.virtToPhys[a], p.virtToPhys[b] = p.virtToPhys[b], p.virtToPhys[a]
	p.physToVirt[p.virtToPhys[a]], p.physToVirt[p.virtToPhys[b]] =
		p.physToVirt[p.virtToPhys[b]], p.physToVirt[p.virtToPhys[a]]
}

// rcSwapMatrix wraps a denseMatrix with virtual row/column permutations;
// swaps touch only the permutations, not the data.
type rcSwapMatrix struct {
	mat  *denseMatrix
	rowP rcPermutation
	colP rcPermutation
}

func newRCSwapMatrix(m *denseMatrix) *rcSwapMatrix {
	return &rcSwapMatrix{
		mat:  m,
		rowP: newRCPermutation(m.nrows),
		colP: newRCPermutation(m.ncols),
	}
}

func (a *rcSwapMatrix) nrows() int { return a.mat.nrows }
func (a *rcSwapMatrix) ncols() int { return a.mat.ncols }

func (a *rcSwapMatrix) at(i, j int) bool {
	return a.mat.at(a.rowP.index(i), a.colP.index(j))
}

func (a *rcSwapMatrix) swapRows(a1, b int)    { a.rowP.swap(a1, b) }
func (a *rcSwapMatrix) swapColumns(a1, b int) { a.colP.swap(a1, b) }

// rowSubAssign does row[a] ^= row[b] in physical coordinates.
func (a *rcSwapMatrix) rowSubAssign(a1, b int) {
	aPhys := a.rowP.index(a1)
	bPhys := a.rowP.index(b)
	for k := 0; k < a.mat.ncols; k++ {
		a.mat.xorInto(aPhys, k, a.mat.at(bPhys, k))
	}
}

// rowwiseEliminationSchedule runs Gaussian elimination on a (viewed through
// row/column permutations) and reports each row-subtraction to rowOperation.
// Elimination strategy is caller-supplied. Rows/cols are virtually swapped so
// the pivot lands at (step, step); emitted ops carry PHYSICAL row indices so a
// consumer replaying them on unpermuted rows sees correct behavior.
func (m *denseMatrix) rowwiseEliminationSchedule(
	recordOp func(rowOperation),
	eliminationStrategy func(a *rcSwapMatrix, step int) (row, col int, ok bool),
) error {
	if m.nrows < m.ncols {
		panic("rowwiseEliminationSchedule: nrows < ncols")
	}

	a := newRCSwapMatrix(m)

	for step := 0; step < a.ncols(); step++ {
		row, col, ok := eliminationStrategy(a, step)
		if !ok {
			return fmt.Errorf("elimination strategy failed at step %d", step)
		}

		if row != step {
			a.swapRows(row, step)
		}
		if col != step {
			a.swapColumns(col, step)
		}

		for i := 0; i < a.nrows(); i++ {
			if i != step && a.at(i, step) {
				a.rowSubAssign(i, step)
				recordOp(rowOperation{
					i: a.rowP.index(i),
					j: a.rowP.index(step),
				})
			}
		}
	}

	return nil
}

// rowwiseEliminationGaussian: pivot = first row below diagonal with step-col set.
func (m *denseMatrix) rowwiseEliminationGaussian(recordOp func(rowOperation)) error {
	return m.rowwiseEliminationSchedule(recordOp,
		func(a *rcSwapMatrix, step int) (int, int, bool) {
			for row := step; row < a.nrows(); row++ {
				if a.at(row, step) {
					return row, step, true
				}
			}
			return 0, 0, false
		})
}

// rowwiseEliminationGaussianPartialPivot: pivot = min row-weight row with
// step-col set (weight counted over columns >= step).
func (m *denseMatrix) rowwiseEliminationGaussianPartialPivot(recordOp func(rowOperation)) error {
	return m.rowwiseEliminationSchedule(recordOp,
		func(a *rcSwapMatrix, step int) (int, int, bool) {
			best := -1
			bestWeight := 0
			for row := step; row < a.nrows(); row++ {
				if !a.at(row, step) {
					continue
				}
				w := 0
				for i := step; i < a.ncols(); i++ {
					if a.at(row, i) {
						w++
					}
				}
				if best == -1 || w < bestWeight {
					best, bestWeight = row, w
				}
			}
			if best == -1 {
				return 0, 0, false
			}
			return best, step, true
		})
}

// rowwiseEliminationGaussianFullPivot: pivot = row with minimal nonzero
// weight over all columns; leading column = its first set column.
func (m *denseMatrix) rowwiseEliminationGaussianFullPivot(recordOp func(rowOperation)) error {
	return m.rowwiseEliminationSchedule(recordOp,
		func(a *rcSwapMatrix, step int) (int, int, bool) {
			best, bestWeight, bestCol := -1, 0, 0
			for row := step; row < a.nrows(); row++ {
				w, leadCol := 0, -1
				for col := 0; col < a.ncols(); col++ {
					if a.at(row, col) {
						w++
						if leadCol == -1 {
							leadCol = col
						}
					}
				}
				if w == 0 {
					continue
				}
				if best == -1 || w < bestWeight {
					best, bestWeight, bestCol = row, w, leadCol
				}
			}
			if best == -1 {
				return 0, 0, false
			}
			return best, bestCol, true
		})
}

// checkInvertible reports whether m is invertible over GF(2).
func (m *denseMatrix) checkInvertible() bool {
	return m.rowwiseEliminationGaussian(func(rowOperation) {}) == nil
}
