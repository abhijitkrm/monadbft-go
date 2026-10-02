//go:build !raptordebug

package raptor

// No-op in normal builds; the real invariants compile in only under
// -tags=raptordebug (mirroring Rust's debug_assertions gating).
func (d *decoder) check()                   {}
func bufferWeightMapCheck(*bufferWeightMap) {}
