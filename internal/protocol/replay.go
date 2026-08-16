package protocol

// ReplayWindow implements a sliding-window anti-replay filter in the style of
// RFC 6479. A packet is accepted if its sequence number is larger than any seen
// so far, or falls inside the window on a bit that is not yet set. The caller
// must call Check before decrypting and Add after a successful decryption so
// that forged frames cannot advance the window.
type ReplayWindow struct {
	size uint64
	high uint64 // highest accepted sequence number
	bits []uint64
}

// NewReplayWindow returns a window that tracks the last size sequence numbers.
// size must be a positive multiple of 64.
func NewReplayWindow(size uint64) *ReplayWindow {
	if size < 64 {
		size = 64
	}
	size &= ^uint64(63)
	return &ReplayWindow{size: size, high: ^uint64(0), bits: make([]uint64, size/64)}
}

// Check reports whether seq is acceptable (not a replay and inside the window).
func (w *ReplayWindow) Check(seq uint64) bool {
	if w.high == ^uint64(0) {
		return true // first packet: the window anchors itself at its sequence number
	}
	if seq > w.high {
		return true
	}
	diff := w.high - seq
	if diff >= w.size {
		return false
	}
	return w.bits[diff/64]&(uint64(1)<<(diff%64)) == 0
}

// Add records seq as received, sliding the window forward if necessary.
func (w *ReplayWindow) Add(seq uint64) {
	if w.high == ^uint64(0) {
		w.high = seq
		w.bits[0] |= 1 // anchor packet is at diff 0
		return
	}
	if seq <= w.high {
		diff := w.high - seq
		if diff < w.size {
			w.bits[diff/64] |= uint64(1) << (diff % 64)
		}
		return
	}
	// seq > high: slide the window forward by (seq - high).
	slide := seq - w.high
	if slide >= w.size {
		clear(w.bits)
		w.high = seq
		return
	}
	// #nosec G115 -- slide < size (checked above) and the bitmap is small.
	shiftUp(w.bits, int(slide))
	w.bits[0] |= 1
	w.high = seq
}

// shiftUp shifts the bitmap toward higher indices by n bit positions: a bit at
// position p moves to p+n, and bits that fall past the top (oldest end) are
// dropped. bit 0 is the newest (highest) sequence number.
func shiftUp(bits []uint64, n int) {
	words, rem := n/64, n%64
	nw := len(bits)
	if words >= nw {
		clear(bits)
		return
	}
	for i := nw - 1; i >= 0; i-- {
		var v uint64
		if i-words >= 0 {
			v = bits[i-words]
		}
		if rem != 0 {
			v <<= rem
			if i-words-1 >= 0 {
				v |= bits[i-words-1] >> (64 - rem)
			}
		}
		bits[i] = v
	}
}
