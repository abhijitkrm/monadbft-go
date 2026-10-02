package wireauth

// Ported from monad-bft/monad-wireauth/src/session/replay_filter.rs.
// WireGuard-style sliding-window replay filter.

import "fmt"

const (
	replayWindowSize = 128
	replayWindowBits = replayWindowSize * 64 // 8192
)

type replayFilter struct {
	next   uint64
	bitmap [replayWindowSize]uint64
}

func (f *replayFilter) check(counter uint64) error {
	if counter >= f.next {
		return nil
	}
	// Rust: counter.saturating_add(REPLAY_WINDOW_BITS) <= next — written
	// overflow-free since counter < next here.
	if f.next-counter >= replayWindowBits {
		return nonceOutsideWindowErr(counter, f.next)
	}
	if f.isSet(counter) {
		return fmt.Errorf("%w: %d", ErrNonceDuplicate, counter)
	}
	return nil
}

func (f *replayFilter) update(counter uint64) {
	if counter >= f.next {
		gap := counter - f.next
		if gap >= replayWindowBits {
			f.bitmap = [replayWindowSize]uint64{}
		} else {
			for i := f.next; i < counter; i++ {
				f.clear(i)
			}
		}
		f.next = counter + 1
	}
	f.set(counter)
}

func (f *replayFilter) isSet(counter uint64) bool {
	bit := counter % replayWindowBits
	return (f.bitmap[bit/64]>>(bit%64))&1 == 1
}

func (f *replayFilter) set(counter uint64) {
	bit := counter % replayWindowBits
	f.bitmap[bit/64] |= 1 << (bit % 64)
}

func (f *replayFilter) clear(counter uint64) {
	bit := counter % replayWindowBits
	f.bitmap[bit/64] &^= 1 << (bit % 64)
}
