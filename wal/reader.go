package wal

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
)

// walReadBufferSize — Rust WAL_READ_BUFFER_SIZE (1MB).
const walReadBufferSize = 1024 * 1024

type chunkReader struct {
	reader    *bufio.Reader
	file      *os.File
	exhausted bool
}

func newChunkReader(chunk DiscoveredChunk) (*chunkReader, error) {
	file, err := os.Open(chunk.Path)
	if err != nil {
		return nil, err
	}
	return &chunkReader{
		reader: bufio.NewReaderSize(file, walReadBufferSize),
		file:   file,
	}, nil
}

// loadOneRaw — Rust ChunkReader::load_one_raw: read one
// [u32le len][payload] record. A partially-written trailing record (crash
// mid-write) surfaces as io.ErrUnexpectedEOF, matching Rust's read_exact.
func (r *chunkReader) loadOneRaw() ([]byte, error) {
	if r.exhausted {
		return nil, nil
	}
	var lenBuf [EventHeaderLen]byte
	n, err := r.reader.Read(lenBuf[:])
	if err == io.EOF || n == 0 {
		r.exhausted = true
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(r.reader, lenBuf[n:]); err != nil {
		return nil, err
	}
	length := binary.LittleEndian.Uint32(lenBuf[:])
	buf := make([]byte, length)
	if _, err := io.ReadFull(r.reader, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Reader — Rust WALReader: replays events across chunks in
// (timestamp, generation) order.
type Reader struct {
	readers []*chunkReader
}

// NewReader — Rust WALReader::new.
func NewReader(dirPath string) (*Reader, error) {
	discovered, err := DiscoverChunks(dirPath)
	if err != nil {
		return nil, err
	}
	return ReaderFromChunks(discovered)
}

// ReaderFromChunks — Rust WALReader::from_discovered_chunks.
func ReaderFromChunks(chunks []DiscoveredChunk) (*Reader, error) {
	readers := make([]*chunkReader, 0, len(chunks))
	for _, c := range chunks {
		r, err := newChunkReader(c)
		if err != nil {
			return nil, err
		}
		readers = append(readers, r)
	}
	return &Reader{readers: readers}, nil
}

// LoadOneRaw — Rust WALReader::load_one_raw.
func (r *Reader) LoadOneRaw() ([]byte, error) {
	for len(r.readers) > 0 {
		front := r.readers[0]
		if front.exhausted {
			front.file.Close()
			r.readers = r.readers[1:]
			continue
		}
		buf, err := front.loadOneRaw()
		if err != nil {
			return nil, err
		}
		if buf == nil {
			front.file.Close()
			r.readers = r.readers[1:]
			continue
		}
		return buf, nil
	}
	return nil, nil
}

// Close releases all open chunk files.
func (r *Reader) Close() {
	for _, c := range r.readers {
		c.file.Close()
	}
	r.readers = nil
}

// ReadAllRaw drains the reader, returning every remaining payload in order.
func (r *Reader) ReadAllRaw() ([][]byte, error) {
	var out [][]byte
	for {
		buf, err := r.LoadOneRaw()
		if err != nil {
			return nil, err
		}
		if buf == nil {
			return out, nil
		}
		out = append(out, buf)
	}
}
