// Package framing implements the obfuscated wire format for session messages
// and the pluggable traffic-shaping options (padding, jitter, decoy traffic).
//
// Session messages are transmitted as:
//
//	[nonce: 12 random bytes][ciphertext]
//
// where the ciphertext is ChaCha20-Poly1305 over an inner plaintext:
//
//	[session tag: 4][type: 1][seq: 4][payload length: 2][payload][padding...]
//
// Nothing in the frame is readable before decryption: there is no fixed
// version, type or length in plaintext, and every packet begins with a fresh
// random nonce. The inner length field lets the receiver discard any padding
// the sender chose to add.
package framing

import (
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	// NonceLen is the size of the per-packet random nonce.
	NonceLen = 12
	// TagLen is the size of the ChaCha20-Poly1305 authentication tag.
	TagLen = 16
	// InnerHeaderLen is the size of the encrypted metadata header.
	InnerHeaderLen = 11

	// MaxInner is the largest inner plaintext we allow.
	MaxInner = MaxWire - NonceLen - TagLen
)

// MaxWire is the largest datagram the transport can carry.
const MaxWire = 65507

var (
	// ErrShort is returned for frames that are too small to be valid.
	ErrShort = errors.New("framing: frame too short")
	// ErrAuth is returned when the AEAD authentication fails.
	ErrAuth = errors.New("framing: authentication failed")
)

// Frame is the decrypted metadata + payload of a session message.
type Frame struct {
	Tag     [4]byte
	Type    byte
	Seq     uint32
	Payload []byte
}

// Seal builds a session frame: [nonce][ciphertext]. The returned slice is
// freshly allocated.
func Seal(aead cipher.AEAD, tag [4]byte, typ byte, seq uint32, payload, padding []byte) []byte {
	plen := InnerHeaderLen + len(payload) + len(padding)
	buf := GetWire()[:NonceLen+plen+TagLen] // pooled buffer; callers must PutWire it
	nonce := buf[:NonceLen]
	_, _ = crand.Read(nonce) // crypto/rand.Read never returns an error
	inner := buf[NonceLen : NonceLen+plen]
	copy(inner[0:4], tag[:])
	inner[4] = typ
	binary.BigEndian.PutUint32(inner[5:9], seq)
	binary.BigEndian.PutUint16(inner[9:11], uint16(len(payload))) // #nosec G115 -- payload <= MaxPayload
	copy(inner[InnerHeaderLen:], payload)
	copy(inner[InnerHeaderLen+len(payload):], padding)
	// #nosec G407 -- the nonce slice is filled from crypto/rand above before
	// it is passed as the IV; it is never a hardcoded or reused value.
	ct := aead.Seal(inner[:0], nonce, inner, nil)
	return buf[:NonceLen+len(ct)]
}

// Open authenticates and decrypts a session frame.
func Open(aead cipher.AEAD, wire []byte) (Frame, error) {
	inner, err := OpenInto(aead, wire, nil)
	if err != nil {
		return Frame{}, err
	}
	return ParseInner(inner)
}

// OpenInto authenticates and decrypts a session frame into sink, growing it as
// needed, and returns the decrypted inner plaintext. The returned slice may
// alias sink; callers that reuse sink must consume the result before the next
// call.
func OpenInto(aead cipher.AEAD, wire, sink []byte) ([]byte, error) {
	if len(wire) < NonceLen+TagLen {
		return nil, ErrShort
	}
	nonce := wire[:NonceLen]
	ct := wire[NonceLen:]
	inner, err := aead.Open(sink, nonce, ct, nil)
	if err != nil {
		return nil, ErrAuth
	}
	if len(inner) < InnerHeaderLen {
		return nil, ErrShort
	}
	return inner, nil
}

// ParseInner decodes the header and payload from a decrypted inner plaintext.
func ParseInner(inner []byte) (Frame, error) {
	if len(inner) < InnerHeaderLen {
		return Frame{}, ErrShort
	}
	var f Frame
	copy(f.Tag[:], inner[0:4])
	f.Type = inner[4]
	f.Seq = binary.BigEndian.Uint32(inner[5:9])
	plen := int(binary.BigEndian.Uint16(inner[9:11]))
	if InnerHeaderLen+plen > len(inner) {
		return Frame{}, ErrShort
	}
	f.Payload = inner[InnerHeaderLen : InnerHeaderLen+plen]
	return f, nil
}

// Shaping controls how frames are laid out on the wire. It is a per-direction
// policy: each side pads its own sends and trims the peer's padding using the
// encrypted length field, so the two directions can be tuned independently.
type Shaping struct {
	// Padding selects the padding strategy: "none" (default), "pad" (all
	// frames padded to a fixed wire size), "bucket" (wire size rounded up to
	// a multiple), or "random" (a random amount of padding added).
	Padding string
	// PadTo is the target wire size in bytes for "pad".
	PadTo int
	// Bucket is the granularity for "bucket".
	Bucket int
	// RandMax is the maximum number of random padding bytes for "random".
	RandMax int
	// DecoyInterval is how long the sender may stay silent (no real data)
	// before emitting an encrypted decoy frame. 0 disables decoys.
	DecoyInterval time.Duration
	// Jitter is the maximum random delay added before sending a frame.
	Jitter time.Duration
}

// PaddingFor returns how many padding bytes to append to an inner plaintext
// of innerLen bytes so that the resulting wire frame obeys the shaping policy.
func (s Shaping) PaddingFor(innerLen int) int {
	switch s.Padding {
	case "pad":
		if s.PadTo > 0 {
			target := s.PadTo - NonceLen - TagLen
			if target > MaxInner {
				target = MaxInner
			}
			if innerLen < target {
				return target - innerLen
			}
		}
	case "bucket":
		if s.Bucket > 0 {
			total := NonceLen + TagLen + innerLen
			if r := total % s.Bucket; r > 0 {
				if pad := s.Bucket - r; total+pad <= MaxWire {
					return pad
				}
			}
		}
	case "random":
		if s.RandMax > 0 {
			return randN(s.RandMax + 1)
		}
	case "web":
		// Pad each frame to a wire size sampled from the distribution of real
		// TLS records, so the packet-size histogram resembles ordinary HTTPS
		// instead of a constant-size tunnel. Very small inner payloads stay
		// small; large ones (data frames) keep their natural size.
		min := NonceLen + TagLen + innerLen
		if target := webWireSize(); target > min && target <= MaxWire {
			return target - min
		}
		return randN(17)
	}
	return 0
}

// webWireSize samples a plausible TLS-record wire size (typical HTTPS
// traffic): mostly small records, a few medium, rare large ones.
func webWireSize() int {
	switch r := randN(100); {
	case r < 35:
		return 53 + randN(97) // 53..149
	case r < 65:
		return 150 + randN(250) // 150..399
	case r < 85:
		return 400 + randN(400) // 400..799
	case r < 95:
		return 800 + randN(400) // 800..1199
	default:
		return 1200 + randN(300) // 1200..1499
	}
}

// fixedPool is a simple bounded freelist that, unlike sync.Pool, is not
// cleared by the garbage collector between allocations. It never grows beyond
// the peak number of in-flight buffers.
type fixedPool struct {
	mu   sync.Mutex
	free [][]byte
	cap  int
}

func (p *fixedPool) get() []byte {
	p.mu.Lock()
	if n := len(p.free); n > 0 {
		b := p.free[n-1]
		p.free = p.free[:n-1]
		p.mu.Unlock()
		return b
	}
	p.mu.Unlock()
	return make([]byte, 0, p.cap)
}

func (p *fixedPool) put(b []byte) {
	if cap(b) != p.cap {
		return
	}
	b = b[:0]
	p.mu.Lock()
	p.free = append(p.free, b)
	p.mu.Unlock()
}

// wirePool reuses seal output buffers. Callers must return them with PutWire
// exactly once after the frame has been handed to the transport.
var wirePool = fixedPool{cap: MaxWire}

// GetWire returns a reusable buffer for seal output.
func GetWire() []byte { return wirePool.get() }

// PutWire returns a seal output buffer to the pool.
func PutWire(b []byte) { wirePool.put(b) }

// randN returns a cryptographically random integer in [0, max). Traffic
// shaping uses it so even packet-size randomness does not leak through a weak
// PRNG.
func randN(max int) int {
	if max <= 0 {
		return 0
	}
	var b [4]byte
	_, _ = crand.Read(b[:]) // crypto/rand.Read never returns an error
	return int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) % max
}

// WireLen returns the resulting wire size for an inner plaintext of innerLen.
func (s Shaping) WireLen(innerLen int) int {
	return NonceLen + TagLen + innerLen + s.PaddingFor(innerLen)
}
