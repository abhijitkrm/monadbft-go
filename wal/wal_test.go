package wal

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWALWriteRead(t *testing.T) {
	dir := t.TempDir()
	cfg := NewLoggerConfig(dir, true)
	logger, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{
		[]byte("event-0"),
		[]byte("event-1"),
		[]byte("event-2"),
	}
	for _, p := range payloads {
		if err := logger.Push(p); err != nil {
			t.Fatal(err)
		}
	}
	logger.Close()

	reader, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := reader.ReadAllRaw()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payloads) {
		t.Fatalf("read %d events, want %d", len(got), len(payloads))
	}
	for i := range payloads {
		if !bytes.Equal(got[i], payloads[i]) {
			t.Fatalf("event %d mismatch: got %q want %q", i, got[i], payloads[i])
		}
	}
}

func TestWALRotationAndRetention(t *testing.T) {
	dir := t.TempDir()
	// chunk size fits exactly 2 records of 16 bytes each (4 hdr + 12 payload).
	cfg := NewLoggerConfig(dir, false).WithChunkSize(32).WithChunks(3)
	logger, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("0123456789ab") // 12 bytes → 16B record
	for i := 0; i < 10; i++ {
		if err := logger.Push(payload); err != nil {
			t.Fatal(err)
		}
	}
	logger.Close()

	chunks, err := DiscoverChunks(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 10 records * 16B = 160B → 5 chunks; retention = 3 → only newest 3 survive.
	if len(chunks) != 3 {
		t.Fatalf("expected 3 retained chunks, got %d", len(chunks))
	}
	reader, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := reader.ReadAllRaw()
	if err != nil {
		t.Fatal(err)
	}
	// 3 chunks * 2 records each = 6 records readable (oldest 4 pruned).
	if len(got) != 6 {
		t.Fatalf("expected 6 retained records, got %d", len(got))
	}
}

func TestWALRecordTooLarge(t *testing.T) {
	dir := t.TempDir()
	cfg := NewLoggerConfig(dir, false).WithChunkSize(64)
	logger, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	if err := logger.Push(make([]byte, 100)); err == nil {
		t.Fatal("expected oversized-record error")
	}
}

func TestWALTruncatedTail(t *testing.T) {
	dir := t.TempDir()
	cfg := NewLoggerConfig(dir, false)
	logger, err := cfg.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Push([]byte("complete")); err != nil {
		t.Fatal(err)
	}
	logger.Close()

	// Append a torn record: header says 100 bytes, file ends early.
	chunks, _ := DiscoverChunks(dir)
	if len(chunks) != 1 {
		t.Fatalf("expected 1 chunk, got %d", len(chunks))
	}
	f, err := os.OpenFile(chunks[0].Path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var lenBuf [EventHeaderLen]byte
	binary.LittleEndian.PutUint32(lenBuf[:], 100)
	f.Write(lenBuf[:])
	f.Write([]byte("short"))
	f.Close()

	reader, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	first, err := reader.LoadOneRaw()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != "complete" {
		t.Fatalf("first record = %q", first)
	}
	// Torn tail must surface as UnexpectedEOF (Rust read_exact semantics).
	if _, err := reader.LoadOneRaw(); err != io.ErrUnexpectedEOF {
		t.Fatalf("expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestWALChunkNamingAndOrder(t *testing.T) {
	dir := t.TempDir()
	// Hand-craft out-of-order files to verify (timestamp, generation) sort.
	for _, name := range []string{"wal_2000.1", "wal_1000.0", "wal_1000.2", "wal_1000.1", "notwal", "wal_bad.x"} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		// write one record per file so ordering is observable
		payload := []byte(name)
		var lenBuf [EventHeaderLen]byte
		binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(payload)))
		f.Write(lenBuf[:])
		f.Write(payload)
		f.Close()
	}
	chunks, err := DiscoverChunks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) != 4 {
		t.Fatalf("expected 4 wal chunks discovered, got %d", len(chunks))
	}
	want := []string{"wal_1000.0", "wal_1000.1", "wal_1000.2", "wal_2000.1"}
	for i, c := range chunks {
		if filepath.Base(c.Path) != want[i] {
			t.Fatalf("chunk %d = %s, want %s", i, filepath.Base(c.Path), want[i])
		}
	}
	reader, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := reader.ReadAllRaw()
	if err != nil {
		t.Fatal(err)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Fatalf("event %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestWALReopenAppendsNewChunk(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewLoggerConfig(dir, false).Build()
	if err != nil {
		t.Fatal(err)
	}
	logger.Push([]byte("first-gen"))
	logger.Close()

	logger2, err := NewLoggerConfig(dir, false).Build()
	if err != nil {
		t.Fatal(err)
	}
	logger2.Push([]byte("second-gen"))
	logger2.Close()

	reader, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := reader.ReadAllRaw()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "first-gen" || string(got[1]) != "second-gen" {
		t.Fatalf("unexpected replay: %v", got)
	}
}

func TestWALEmptyRead(t *testing.T) {
	dir := t.TempDir()
	reader, err := NewReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	got, err := reader.LoadOneRaw()
	if err != nil || got != nil {
		t.Fatalf("empty wal should yield (nil, nil), got (%v, %v)", got, err)
	}
}

func TestWALZeroChunksRejected(t *testing.T) {
	dir := t.TempDir()
	_, err := NewLoggerConfig(dir, false).WithChunks(0).Build()
	if err == nil {
		t.Fatal("expected error for chunks=0")
	}
}
