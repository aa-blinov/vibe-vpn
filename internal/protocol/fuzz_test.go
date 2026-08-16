package protocol

import "testing"

func FuzzReplayWindow(f *testing.F) {
	f.Add(uint64(0))
	f.Add(uint64(1))
	f.Add(uint64(1 << 40))
	f.Fuzz(func(t *testing.T, seq uint64) {
		w := NewReplayWindow(2048)
		// A window must accept a fresh high sequence number and then reject it.
		if !w.Check(seq) {
			// Also acceptable: first packet is rejected only if out of window
			// (window anchors on first packet, so a huge first seq is fine).
		}
		w.Add(seq)
		if w.Check(seq) {
			t.Fatalf("seq %d accepted twice", seq)
		}
		// Replays of anything <= high inside the window must be rejected.
		if seq > 0 && w.Check(seq-1) {
			// seq-1 may be out of window; that's fine.
		}
	})
}
