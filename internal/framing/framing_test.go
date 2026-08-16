package framing

import (
	"bytes"
	"crypto/cipher"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/aa-blinov/vibe-vpn/internal/transport"
)

func testAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	a, err := chacha20poly1305.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestSealOpenRoundtrip(t *testing.T) {
	aead := testAEAD(t)
	tag := [4]byte{1, 2, 3, 4}
	payload := []byte("hello tunnel")

	wire := Seal(aead, tag, 0x04, 42, payload, nil)
	if len(wire) != NonceLen+TagLen+InnerHeaderLen+len(payload) {
		t.Fatalf("unexpected wire length %d", len(wire))
	}

	f, err := Open(aead, wire)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != 0x04 || f.Seq != 42 || !bytes.Equal(f.Payload, payload) {
		t.Fatalf("roundtrip mismatch: %+v", f)
	}
	if f.Tag != tag {
		t.Fatalf("tag mismatch: %v", f.Tag)
	}
}

func TestSealWithPadding(t *testing.T) {
	aead := testAEAD(t)
	payload := []byte("hello")
	padding := make([]byte, 100)
	for i := range padding {
		padding[i] = byte(i)
	}

	wire := Seal(aead, [4]byte{}, 0x04, 0, payload, padding)
	f, err := Open(aead, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Fatalf("padding was not trimmed: %q", f.Payload)
	}
	if len(wire) != NonceLen+TagLen+InnerHeaderLen+len(payload)+len(padding) {
		t.Fatalf("wire length %d does not include padding", len(wire))
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	aead := testAEAD(t)
	wire := Seal(aead, [4]byte{9}, 0x04, 1, []byte("data"), nil)

	// Flip a byte in the ciphertext.
	wire[len(wire)/2] ^= 0xff
	if _, err := Open(aead, wire); err != ErrAuth {
		t.Fatalf("tampered frame: got %v, want ErrAuth", err)
	}

	if _, err := Open(aead, []byte{1, 2, 3}); err != ErrShort {
		t.Fatalf("short frame: got %v, want ErrShort", err)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	a1 := testAEAD(t)
	wire := Seal(a1, [4]byte{}, 0x04, 0, []byte("x"), nil)

	key2 := make([]byte, 32)
	key2[0] = 1
	a2, err := chacha20poly1305.New(key2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(a2, wire); err != ErrAuth {
		t.Fatalf("wrong key: got %v, want ErrAuth", err)
	}
}

func TestShapingPadding(t *testing.T) {
	// "none"
	if s := (Shaping{}); s.PaddingFor(100) != 0 {
		t.Fatalf("none should not pad")
	}

	// "pad": all frames to a fixed wire size.
	s := Shaping{Padding: "pad", PadTo: 256}
	wire := s.WireLen(50)
	if wire != 256 {
		t.Fatalf("pad mode: wire=%d, want 256", wire)
	}
	if s.PaddingFor(500) != 0 {
		t.Fatalf("pad mode should not shrink larger frames")
	}

	// "bucket": wire size rounded up to a multiple.
	s = Shaping{Padding: "bucket", Bucket: 128}
	if w := s.WireLen(50); w%128 != 0 {
		t.Fatalf("bucket mode: wire=%d not a multiple of 128", w)
	}
	// innerLen=100 makes the wire exactly 128 (12+16+100).
	if w := s.WireLen(100); w != 128 {
		t.Fatalf("bucket mode should not pad exact multiples, got %d", w)
	}

	// "random": a bounded amount of padding.
	s = Shaping{Padding: "random", RandMax: 64}
	for i := 0; i < 50; i++ {
		if p := s.PaddingFor(10); p < 0 || p > 64 {
			t.Fatalf("random mode: padding %d out of range", p)
		}
	}
}

func TestShapingSafety(t *testing.T) {
	// A pad target larger than the transport cap must be clamped.
	s := Shaping{Padding: "pad", PadTo: 200000}
	if w := s.WireLen(10); w > MaxWire {
		t.Fatalf("pad mode exceeded MaxWire: %d", w)
	}
	// A bucket that would overflow must not pad.
	s = Shaping{Padding: "bucket", Bucket: 100000}
	if s.PaddingFor(100) != 0 {
		t.Fatalf("bucket mode should refuse to overflow")
	}
}

// memTransport is a minimal in-memory transport used to test decorators.
type memTransport struct {
	recv chan []byte
	done chan struct{}
	peer *memTransport
}

func (m *memTransport) Send(b []byte) error {
	select {
	case m.peer.recv <- append([]byte(nil), b...):
		return nil
	case <-m.done:
		return transportClosedErr{}
	}
}

func (m *memTransport) Receive() ([]byte, error) {
	select {
	case b := <-m.recv:
		return b, nil
	case <-m.done:
		return nil, transportClosedErr{}
	}
}

func (m *memTransport) Close() error {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	return nil
}

type transportClosedErr struct{}

func (transportClosedErr) Error() string { return "closed" }

func TestJitterDecorator(t *testing.T) {
	a := &memTransport{recv: make(chan []byte, 8), done: make(chan struct{})}
	b := &memTransport{recv: make(chan []byte, 8), done: make(chan struct{})}
	a.peer, b.peer = b, a

	// Zero jitter returns the transport unchanged.
	if Jitter(a, 0) != transport.Transport(a) {
		t.Fatal("Jitter(0) should return the transport unchanged")
	}

	j := Jitter(a, 5*time.Millisecond)
	go func() {
		if err := j.Send([]byte("hello")); err != nil {
			t.Error(err)
		}
	}()
	select {
	case got := <-b.recv:
		if string(got) != "hello" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("jittered send never arrived")
	}
}

// TestWebProfileSizes verifies that the "web" profile produces a varied,
// realistic spread of wire sizes rather than a constant size.
func TestWebProfileSizes(t *testing.T) {
	s := Shaping{Padding: "web"}
	const n = 400
	seen := make(map[int]int)
	for i := 0; i < n; i++ {
		w := s.WireLen(11) // a small inner plaintext (e.g. keepalive)
		if w < 28 || w > 1500 {
			t.Fatalf("web profile produced out-of-range wire size %d", w)
		}
		seen[w]++
	}
	if len(seen) < 50 {
		t.Fatalf("web profile sizes look static: only %d distinct sizes", len(seen))
	}
	// The distribution must be dominated by small records.
	var small, large int
	for w, c := range seen {
		if w <= 400 {
			small += c
		} else if w >= 800 {
			large += c
		}
	}
	if small == 0 || large == 0 {
		t.Fatalf("web profile should produce both small and large frames (small=%d large=%d)", small, large)
	}
	if small <= large {
		t.Fatalf("web profile should be dominated by small records (small=%d large=%d)", small, large)
	}
}

func TestWebProfileDataFrame(t *testing.T) {
	s := Shaping{Padding: "web"}
	// A full-size data frame must not be shrunk below its natural size
	// (nonce + tag + inner plaintext), and must stay within the web range.
	min := 12 + 16 + 1300
	w := s.WireLen(1300)
	if w < min {
		t.Fatalf("data frame shrunk below natural size: %d < %d", w, min)
	}
	if w > 1500 {
		t.Fatalf("data frame above web range: %d", w)
	}
}
