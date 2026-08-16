package framing

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func FuzzSealOpen(f *testing.F) {
	key := make([]byte, 32)
	rand.Read(key)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(byte(0x04), []byte("hello"), []byte("pad"))
	f.Add(byte(0xff), []byte{}, []byte{})
	f.Fuzz(func(t *testing.T, typ byte, payload, padding []byte) {
		tag := [4]byte{1, 2, 3, 4}
		wire := Seal(aead, tag, typ, 7, payload, padding)
		// Sealing must never panic and must round-trip.
		got, err := Open(aead, wire)
		if err != nil {
			t.Fatalf("round-trip failed: %v", err)
		}
		if got.Type != typ || got.Seq != 7 || !bytes.Equal(got.Payload, payload) || got.Tag != tag {
			t.Fatalf("round-trip mismatch: %+v", got)
		}
		// Mutate one byte: authentication must fail.
		if len(wire) > 0 {
			bad := append([]byte(nil), wire...)
			bad[len(bad)/2] ^= 0xff
			if _, err := Open(aead, bad); err == nil {
				t.Fatal("tampered frame authenticated")
			}
		}
	})
}
