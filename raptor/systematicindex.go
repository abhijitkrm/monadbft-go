package raptor

import "fmt"

// Ported from monad-bft/monad-raptor/src/r10/systematic_index.rs.
// SYSTEMATIC_INDEX table lives in raptor_sysidx.go (generated).

func determineSystematicIndex(numSourceSymbols uint16) (uint16, error) {
	i := int(numSourceSymbols) - sourceSymbolsMin
	if i < 0 || i >= len(systematicIndexTable) {
		return 0, fmt.Errorf("can't find systematic index for num_source_symbols = %d",
			numSourceSymbols)
	}
	return systematicIndexTable[i], nil
}
