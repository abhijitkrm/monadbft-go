package wireauth

// Ported from monad-bft/monad-wireauth/src/error.rs — API-level errors.

import (
	"errors"
	"fmt"
	"net/netip"
)

var (
	ErrSessionNotFound       = errors.New("session not found")
	ErrSessionIndexExhausted = errors.New("session index exhausted")
	ErrInvalidReceiverIndex  = errors.New("invalid receiver index")
	ErrTimestampReplay       = errors.New("timestamp replay detected: received timestamp is not newer than expected")
	ErrConnectRateLimited    = errors.New("connect rate limited")
	ErrTooManyInitiated      = errors.New("too many initiated sessions")
	ErrBufferLimitExceeded   = errors.New("buffer limit exceeded")
	ErrSessionIndexNotFound  = errors.New("session index not found")
)

// ErrSessionNotEstablishedForAddress — no transport session for addr.
func errSessionNotEstablishedForAddress(addr netip.AddrPort) error {
	return fmt.Errorf("session not established for address %s", addr)
}

func errSessionIndexNotFound(index SessionIndex) error {
	return fmt.Errorf("%w: %d", ErrSessionIndexNotFound, uint32(index))
}

func errInvalidReceiverIndex(index SessionIndex) error {
	return fmt.Errorf("%w: %d", ErrInvalidReceiverIndex, uint32(index))
}

func errHandshakeResponseAddressMismatch(expected, actual netip.AddrPort) error {
	return fmt.Errorf("handshake response source address mismatch: expected %s, got %s", expected, actual)
}

func errConnectRateLimited(limit uint64) error {
	return fmt.Errorf("%w: limit=%d", ErrConnectRateLimited, limit)
}

func errTooManyInitiated(limit int) error {
	return fmt.Errorf("%w: limit is %d", ErrTooManyInitiated, limit)
}

func errBufferLimitExceeded(size, limit int) error {
	return fmt.Errorf("%w: %d bytes exceeds limit of %d bytes", ErrBufferLimitExceeded, size, limit)
}
