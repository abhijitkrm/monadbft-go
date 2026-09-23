// Package wal ports monad-wal: the write-ahead log of MonadEvents.
//
// Layout: a directory of chunk files named wal_{unix_millis}.{generation}.
// Each record is a u32 little-endian length header followed by the serialized
// event payload. Chunks rotate at chunk_size and the oldest chunks are pruned
// once the retention count is exceeded.
package wal

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// EventHeaderLen — Rust EVENT_HEADER_LEN (u32).
const EventHeaderLen = 4

// DefaultChunkSize / DefaultChunks — Rust DEFAULT_CHUNK_SIZE / DEFAULT_CHUNKS.
const (
	DefaultChunkSize uint64 = 1024 * 1024 * 1024
	DefaultChunks    uint64 = 8
)

// DiscoveredChunk — Rust DiscoveredChunk.
type DiscoveredChunk struct {
	Path       string
	Timestamp  uint64
	Generation uint64
}

type activeChunk struct {
	path       string
	generation uint64
	size       uint64
	handle     *os.File
}

// LoggerConfig — Rust WALoggerConfig.
type LoggerConfig struct {
	DirPath   string
	Sync      bool
	Chunks    uint64
	ChunkSize uint64
}

// NewLoggerConfig — Rust WALoggerConfig::new.
func NewLoggerConfig(dirPath string, sync bool) LoggerConfig {
	return LoggerConfig{
		DirPath:   dirPath,
		Sync:      sync,
		Chunks:    DefaultChunks,
		ChunkSize: DefaultChunkSize,
	}
}

func (c LoggerConfig) WithChunks(chunks uint64) LoggerConfig {
	c.Chunks = chunks
	return c
}

func (c LoggerConfig) WithChunkSize(chunkSize uint64) LoggerConfig {
	c.ChunkSize = chunkSize
	return c
}

// Build — Rust WALoggerConfig::build.
func (c LoggerConfig) Build() (*Logger, error) {
	if c.Chunks == 0 {
		return nil, fmt.Errorf("wal: chunks must be greater than zero")
	}
	if err := os.MkdirAll(c.DirPath, 0o777); err != nil {
		return nil, err
	}
	discovered, err := DiscoverChunks(c.DirPath)
	if err != nil {
		return nil, err
	}
	timestamp, current, err := createInitialChunk(c.DirPath)
	if err != nil {
		return nil, err
	}
	w := &Logger{
		dirPath:   c.DirPath,
		timestamp: timestamp,
		current:   current,
		rotated:   discovered,
		chunks:    c.Chunks,
		chunkSize: c.ChunkSize,
		sync:      c.Sync,
	}
	if err := w.trimOldestChunks(); err != nil {
		return nil, err
	}
	return w, nil
}

// Logger — Rust WALogger.
type Logger struct {
	dirPath    string
	timestamp  uint64
	generation uint64
	current    *activeChunk
	rotated    []DiscoveredChunk
	chunks     uint64
	chunkSize  uint64
	sync       bool
}

// Push — Rust WALogger::push: append one serialized event record.
func (l *Logger) Push(payload []byte) error {
	if uint64(len(payload)) > math.MaxUint32 {
		return fmt.Errorf("wal: serialized event exceeds u32 header size")
	}
	msgLen := uint64(EventHeaderLen + len(payload))
	if msgLen > l.chunkSize {
		return fmt.Errorf("wal: serialized event exceeds chunk_size")
	}
	if l.current.size+msgLen > l.chunkSize {
		if err := l.rotate(); err != nil {
			return err
		}
	}
	var lenBuf [EventHeaderLen]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(payload)))
	if _, err := l.current.handle.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := l.current.handle.Write(payload); err != nil {
		return err
	}
	l.current.size += msgLen
	if l.sync {
		return l.current.handle.Sync()
	}
	return nil
}

// Close flushes and closes the active chunk.
func (l *Logger) Close() error {
	return l.current.handle.Close()
}

func (l *Logger) rotate() error {
	l.generation++
	next, err := createChunk(l.dirPath, l.timestamp, l.generation)
	if err != nil {
		return err
	}
	previous := l.current
	l.current = next
	l.rotated = append(l.rotated, DiscoveredChunk{
		Path:       previous.path,
		Timestamp:  l.timestamp,
		Generation: previous.generation,
	})
	return l.trimOldestChunks()
}

func (l *Logger) trimOldestChunks() error {
	for uint64(len(l.rotated))+1 > l.chunks {
		oldest := l.rotated[0]
		l.rotated = l.rotated[1:]
		if err := os.Remove(oldest.Path); err != nil {
			return err
		}
	}
	return nil
}

// DiscoverChunks — Rust discover_chunks: all wal_*.{gen} files sorted by
// (timestamp, generation).
func DiscoverChunks(dirPath string) ([]DiscoveredChunk, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var chunks []DiscoveredChunk
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		chunk, ok := parseChunkName(entry.Name())
		if !ok {
			continue
		}
		chunk.Path = filepath.Join(dirPath, entry.Name())
		chunks = append(chunks, chunk)
	}
	sort.Slice(chunks, func(i, j int) bool {
		if chunks[i].Timestamp != chunks[j].Timestamp {
			return chunks[i].Timestamp < chunks[j].Timestamp
		}
		return chunks[i].Generation < chunks[j].Generation
	})
	return chunks, nil
}

func parseChunkName(name string) (DiscoveredChunk, bool) {
	suffix, ok := strings.CutPrefix(name, "wal_")
	if !ok {
		return DiscoveredChunk{}, false
	}
	tsStr, genStr, ok := strings.Cut(suffix, ".")
	if !ok {
		return DiscoveredChunk{}, false
	}
	ts, err1 := strconv.ParseUint(tsStr, 10, 64)
	gen, err2 := strconv.ParseUint(genStr, 10, 64)
	if err1 != nil || err2 != nil {
		return DiscoveredChunk{}, false
	}
	return DiscoveredChunk{Timestamp: ts, Generation: gen}, true
}

func chunkPath(dirPath string, timestamp, generation uint64) string {
	return filepath.Join(dirPath, fmt.Sprintf("wal_%d.%d", timestamp, generation))
}

func currentTimestamp() uint64 {
	return uint64(time.Now().UnixMilli())
}

func createInitialChunk(dirPath string) (uint64, *activeChunk, error) {
	for {
		timestamp := currentTimestamp()
		current, err := createChunk(dirPath, timestamp, 0)
		if err == nil {
			return timestamp, current, nil
		}
		if os.IsExist(err) {
			time.Sleep(time.Millisecond)
			continue
		}
		return 0, nil, err
	}
}

func createChunk(dirPath string, timestamp, generation uint64) (*activeChunk, error) {
	path := chunkPath(dirPath, timestamp, generation)
	handle, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_EXCL, 0o666)
	if err != nil {
		return nil, err
	}
	return &activeChunk{path: path, generation: generation, handle: handle}, nil
}

var _ = io.EOF
