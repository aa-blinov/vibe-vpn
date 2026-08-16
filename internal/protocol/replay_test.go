package protocol

import (
	"testing"
)

func TestReplayWindowBasics(t *testing.T) {
	w := NewReplayWindow(256)

	if !w.Check(0) {
		t.Fatal("first packet (seq 0) must be accepted")
	}
	w.Add(0)

	if w.Check(0) {
		t.Fatal("replayed seq 0 must be rejected")
	}
	if !w.Check(1) {
		t.Fatal("seq 1 must be accepted")
	}
	if !w.Check(5) {
		t.Fatal("out-of-order seq 5 must be accepted")
	}
	w.Add(5)
	if w.Check(5) {
		t.Fatal("replayed seq 5 must be rejected")
	}
	w.Add(1)
	if w.Check(1) {
		t.Fatal("replayed seq 1 must be rejected")
	}
}

func TestReplayWindowSlides(t *testing.T) {
	w := NewReplayWindow(128)
	// Push the window forward with a sparse sequence (even numbers only).
	for i := 0; i < 200; i += 2 {
		if !w.Check(uint64(i)) {
			t.Fatalf("seq %d must be accepted while filling", i)
		}
		w.Add(uint64(i))
	}
	// high = 198 now; window covers 71..198.
	if w.Check(0) {
		t.Fatal("very old seq must be rejected after the window slid")
	}
	if w.Check(100) {
		t.Fatal("seen seq inside the window must be rejected")
	}
	// 101 is unseen and inside the window.
	if !w.Check(101) {
		t.Fatal("in-window unseen seq must be accepted")
	}
	w.Add(101)
	if w.Check(101) {
		t.Fatal("replayed in-window seq must be rejected")
	}
	// Large forward jump clears old state.
	if !w.Check(100000) {
		t.Fatal("large forward jump must be accepted")
	}
	w.Add(100000)
	if w.Check(90000) {
		t.Fatal("old seq below the reset window must be rejected")
	}
}

func TestReplayWindowFirstPacket(t *testing.T) {
	w := NewReplayWindow(256)
	// The window anchors on the first received packet, whatever its seq
	// (seq 0 may have been lost in transit).
	if !w.Check(5) {
		t.Fatal("first packet may have any sequence number")
	}
	w.Add(5)
	if w.Check(5) {
		t.Fatal("replayed first packet must be rejected")
	}
	if !w.Check(7) {
		t.Fatal("seq 7 must be accepted after the window anchored at 5")
	}
}
