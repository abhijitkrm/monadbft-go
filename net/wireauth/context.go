package wireauth

// Ported from monad-bft/monad-wireauth/src/context.rs.

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"time"
)

// Context provides time + entropy to the API. StdContext uses wall clock;
// TestContext exposes a manual clock + deterministic RNG for tests.
type Context interface {
	SystemTime() time.Time
	DurationSinceStart() time.Duration
	RNG() rng
	// convert a duration-since-start deadline to a wall-clock instant
	Deadline(d time.Duration) time.Time
}

// cryptoRNG adapts crypto/rand to the rng interface (Read + Uint64).
type cryptoRNG struct{}

func (cryptoRNG) Read(b []byte) (int, error) { return cryptorand.Read(b) }
func (cryptoRNG) Uint64() uint64 {
	var b [8]byte
	_, _ = cryptorand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

// StdContext is the production context: crypto/rand + wall clock.
type StdContext struct {
	rng   cryptoRNG
	start time.Time
}

func NewStdContext() *StdContext { return &StdContext{start: time.Now()} }

func (c *StdContext) SystemTime() time.Time             { return time.Now() }
func (c *StdContext) DurationSinceStart() time.Duration { return time.Since(c.start) }
func (c *StdContext) RNG() rng                          { return c.rng }
func (c *StdContext) Deadline(d time.Duration) time.Time {
	return c.start.Add(d)
}

// TestContext — manual clock + caller-supplied RNG (mirrors upstream's
// TestContext used to replay deterministic handshake traces).
type TestContext struct {
	RNGValue     rng
	timeOffset   time.Duration
	startTime    time.Time
	startInstant time.Time
}

func NewTestContext(r rng) *TestContext {
	return &TestContext{
		RNGValue:     r,
		startTime:    time.Unix(0, 0),
		startInstant: time.Now(),
	}
}

func (c *TestContext) AdvanceTime(d time.Duration) { c.timeOffset += d }
func (c *TestContext) RewindTime(d time.Duration) {
	c.timeOffset -= d
	if c.timeOffset < 0 {
		c.timeOffset = 0
	}
}
func (c *TestContext) SystemTime() time.Time             { return c.startTime.Add(c.timeOffset) }
func (c *TestContext) DurationSinceStart() time.Duration { return c.timeOffset }
func (c *TestContext) RNG() rng                          { return c.RNGValue }
func (c *TestContext) Deadline(d time.Duration) time.Time {
	return c.startInstant.Add(d)
}
