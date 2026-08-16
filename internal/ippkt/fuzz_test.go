package ippkt

import "testing"

func FuzzParse(f *testing.F) {
	f.Add([]byte{0x45, 0x00, 0x00, 0x14})
	f.Add([]byte{0x60, 0x00})
	f.Add([]byte{0x45})
	f.Fuzz(func(t *testing.T, pkt []byte) {
		// Parse must never panic and must not read out of bounds.
		h, ok := Parse(pkt)
		if ok {
			if h.Src == nil || h.Dst == nil {
				t.Fatal("parse succeeded without addresses")
			}
		}
	})
}
