package raptor

// Ported from monad-bft/monad-raptor/tests/{managed_decoder,verify_encode_decode}.rs.

import (
	"bytes"
	mathrand "math/rand"
	"testing"
)

const testSymbolLen = 4

// testBufferSet mirrors the Rust test's BufferSet — separate temp/rx vectors.
type testBufferSet struct {
	tempBuffers [][]byte
	rxBuffers   [][]byte
}

func newTestBufferSet(numTempBuffers, symbolLen int) *testBufferSet {
	temps := make([][]byte, numTempBuffers)
	for i := range temps {
		temps[i] = make([]byte, symbolLen)
	}
	return &testBufferSet{tempBuffers: temps}
}

func (s *testBufferSet) buffer(id bufferID) []byte {
	if id.temp {
		return s.tempBuffers[id.index]
	}
	return s.rxBuffers[id.index]
}

func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func (s *testBufferSet) xorBuffers(a, b bufferID) {
	xorInto(s.buffer(a), s.buffer(b))
}

// singleDecode encodes src, feeds a shuffled subset of 2K encoded symbols to
// a raw Decoder (with occasional duplicate feeds), and verifies every source
// symbol is recovered byte-exact.
func singleDecode(t *testing.T, rng *mathrand.Rand, src []byte) {
	enc, err := NewEncoder(src, testSymbolLen)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	k := enc.NumSourceSymbols()

	dec, err := newDecoder(k)
	if err != nil {
		t.Fatalf("newDecoder: %v", err)
	}
	bs := newTestBufferSet(dec.numTempBuffersRequired(), testSymbolLen)

	esis := rng.Perm(2 * k)

	var done bool
	for _, esi := range esis {
		buf := make([]byte, testSymbolLen)
		enc.EncodeSymbol(buf, esi)

		// Occasionally feed a duplicate to exercise the redundant path.
		if rng.Intn(100) == 0 {
			bs.rxBuffers = append(bs.rxBuffers, append([]byte(nil), buf...))
			dec.receivedEncodedSymbol(esi, bs.xorBuffers)
		}

		bs.rxBuffers = append(bs.rxBuffers, buf)
		dec.receivedEncodedSymbol(esi, bs.xorBuffers)

		if dec.tryDecode(k+k/4, bs.xorBuffers) {
			done = true
			break
		}
	}
	if !done && !dec.decodingDone() {
		t.Fatalf("decoding failed for %d-byte src (K=%d)", len(src), k)
	}

	// Pad src to an integer multiple of symbolLen like the Rust test does.
	padded := src
	symbols := (len(src) + testSymbolLen - 1) / testSymbolLen
	if symbols < sourceSymbolsMin {
		symbols = sourceSymbolsMin
	}
	if l := symbols * testSymbolLen; len(padded) != l {
		padded = append(append([]byte(nil), src...), make([]byte, l-len(src))...)
	}

	for i := 0; i < k; i++ {
		id, ok := dec.sourceSymbolToBufferID(i)
		if !ok {
			t.Fatalf("source symbol %d not recovered", i)
		}
		if !bytes.Equal(padded[i*testSymbolLen:(i+1)*testSymbolLen], bs.buffer(id)) {
			t.Fatalf("source symbol %d mismatch", i)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(1))
	for bytesLen := 0; bytesLen <= 128; bytesLen++ {
		src := make([]byte, bytesLen)
		rng.Read(src)
		singleDecode(t, rng, src)
	}
}

// Upstream sweeps 0..=2048 in release builds; spot-check larger sizes here so
// the inactivation and inactive-Gaussian paths are exercised.
func TestEncodeDecodeRoundTripLarge(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(3))
	for _, bytesLen := range []int{256, 512, 1024, 2048} {
		src := make([]byte, bytesLen)
		rng.Read(src)
		singleDecode(t, rng, src)
	}
}

func TestManagedDecoderRoundTripLarge(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(4))
	for _, bytesLen := range []int{256, 512, 1024, 2048} {
		src := make([]byte, bytesLen)
		rng.Read(src)

		enc, err := NewEncoder(src, testSymbolLen)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		k := enc.NumSourceSymbols()

		dec, err := NewManagedDecoder(k, 0, testSymbolLen)
		if err != nil {
			t.Fatalf("NewManagedDecoder: %v", err)
		}

		esis := rng.Perm(2 * k)
		done := false
		for _, esi := range esis {
			buf := make([]byte, testSymbolLen)
			enc.EncodeSymbol(buf, esi)
			dec.ReceivedEncodedSymbol(buf, esi)
			if dec.TryDecode() {
				done = true
				break
			}
		}
		if !done && !dec.DecodingDone() {
			t.Fatalf("decoding failed for %d-byte src", len(src))
		}

		recon := dec.ReconstructSourceData()
		if recon == nil || !bytes.Equal(src, recon[:len(src)]) {
			t.Fatalf("reconstructed data mismatch for %d-byte src", len(src))
		}
	}
}

func TestManagedDecoderRoundTrip(t *testing.T) {
	rng := mathrand.New(mathrand.NewSource(2))
	for bytesLen := 0; bytesLen <= 128; bytesLen++ {
		src := make([]byte, bytesLen)
		rng.Read(src)

		enc, err := NewEncoder(src, testSymbolLen)
		if err != nil {
			t.Fatalf("NewEncoder: %v", err)
		}
		k := enc.NumSourceSymbols()

		dec, err := NewManagedDecoder(k, 0, testSymbolLen)
		if err != nil {
			t.Fatalf("NewManagedDecoder: %v", err)
		}

		esis := rng.Perm(2 * k)
		done := false
		for _, esi := range esis {
			buf := make([]byte, testSymbolLen)
			enc.EncodeSymbol(buf, esi)
			dec.ReceivedEncodedSymbol(buf, esi)
			if rng.Intn(100) == 0 {
				dec.ReceivedEncodedSymbol(buf, esi)
			}
			if dec.TryDecode() {
				done = true
				break
			}
		}
		if !done && !dec.DecodingDone() {
			t.Fatalf("decoding failed for %d-byte src", len(src))
		}

		recon := dec.ReconstructSourceData()
		if recon == nil {
			t.Fatalf("reconstruct returned nil for %d-byte src", len(src))
		}
		recon = recon[:len(src)]
		if !bytes.Equal(src, recon) {
			t.Fatalf("reconstructed data mismatch for %d-byte src", len(src))
		}
	}
}

func TestManagedDecoderInvalidSymbolLen(t *testing.T) {
	enc, _ := NewEncoder(make([]byte, 32), testSymbolLen)
	dec, _ := NewManagedDecoder(enc.NumSourceSymbols(), 0, testSymbolLen)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on mismatched symbol length")
		}
	}()
	dec.ReceivedEncodedSymbol(make([]byte, testSymbolLen+1), 0)
}

func TestManagedDecoderOversized(t *testing.T) {
	if _, err := NewManagedDecoder(sourceSymbolsMax+1, (sourceSymbolsMax+1)*2, testSymbolLen); err == nil {
		t.Fatal("expected error for oversized symbol count")
	}
}
