package framing

import (
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// BenchmarkSealOpen measures the per-frame AEAD path (the crypto ceiling of
// the tunnel, excluding transports and TUN).
func BenchmarkSealOpen(b *testing.B) {
	aead, err := chacha20poly1305.New(make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	tag := [4]byte{1, 2, 3, 4}
	payload := make([]byte, 1200) // typical MTU-sized data frame
	padding := make([]byte, 64)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		wire := Seal(aead, tag, 0x04, uint32(i), payload, padding)
		if _, err := Open(aead, wire); err != nil {
			b.Fatal(err)
		}
	}
}
