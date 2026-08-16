package ippkt

import (
	"net"
	"testing"
)

func ipv4(src, dst net.IP, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	pkt[2] = byte((len(pkt)) >> 8)
	pkt[3] = byte(len(pkt))
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

func TestParse(t *testing.T) {
	src, dst := net.ParseIP("10.0.0.1"), net.ParseIP("8.8.8.8")
	h, ok := Parse(ipv4(src, dst, []byte("hi")))
	if !ok {
		t.Fatal("valid packet rejected")
	}
	if !h.Src.Equal(src) || !h.Dst.Equal(dst) {
		t.Fatalf("bad addresses: %v -> %v", h.Src, h.Dst)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string][]byte{
		"empty":     {},
		"short":     {0x45},
		"ipv6":      {0x60, 0x00},
		"bad ihl":   {0x46, 0x00},
		"bad total": func() []byte { b := ipv4(net.IP{1}, net.IP{2}, nil); b[2] = 0xff; b[3] = 0xff; return b }(),
	}
	for name, pkt := range cases {
		if _, ok := Parse(pkt); ok {
			t.Fatalf("%s: malformed packet accepted", name)
		}
	}
}
