// Package session implements the VPN session layer: the Noise XK handshake,
// AEAD transport keys, sequence numbers, replay protection, keepalives,
// timeouts, rekeying and reconnect. It is fully transport-agnostic and only
// talks to the network through the transport.Transport interface.
//
// Session messages use the obfuscated framing defined in internal/framing:
// a random nonce followed by an AEAD ciphertext whose metadata is encrypted.
// Handshake messages are raw Noise messages with no framing at all.
package session

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"net"
	"time"

	noise "github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/aa-blinov/vibe-vpn/internal/framing"
	"github.com/aa-blinov/vibe-vpn/internal/protocol"
)

// TUN is the data plane the session moves IP packets across. It is satisfied
// by internal/tun.Tun and by fake implementations in tests.
type TUN interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
}

// Sentinel errors surfaced by the session state machine.
var (
	ErrTimeout    = errors.New("session: timeout")
	ErrPeerClosed = errors.New("session: peer closed")
	ErrReplay     = errors.New("session: replay detected")
	ErrAuth       = errors.New("session: authentication failure")
)

const replayWindowSize = 2048

// Keys holds the active AEAD state for the send and receive directions. Each
// frame carries its own random nonce; the sender's sequence counter is
// encrypted inside the frame and only used for replay protection on the
// receiver's sliding window.
type Keys struct {
	sendAEAD cipher.AEAD
	recvAEAD cipher.AEAD
	sendSeq  uint64
	replay   *protocol.ReplayWindow
}

// newKeys builds a Keys pair. c2s encrypts client->server traffic, s2c
// encrypts server->client traffic. isClient selects which of the two is "send".
func newKeys(isClient bool, c2s, s2c *noise.CipherState) *Keys {
	k := &Keys{replay: protocol.NewReplayWindow(replayWindowSize)}
	if isClient {
		k.sendAEAD = aeadFrom(c2s)
		k.recvAEAD = aeadFrom(s2c)
	} else {
		k.sendAEAD = aeadFrom(s2c)
		k.recvAEAD = aeadFrom(c2s)
	}
	return k
}

func aeadFrom(cs *noise.CipherState) cipher.AEAD {
	key := cs.UnsafeKey()
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		panic(err) // unreachable: key is always 32 bytes
	}
	return a
}

// seal encrypts a message and returns the wire bytes and the sequence number
// that was consumed.
func (k *Keys) seal(tag [4]byte, typ byte, payload, padding []byte) ([]byte, uint32) {
	// #nosec G115 -- the caller forces a rekey long before the uint32 wire
	// sequence number can wrap (see maybeRekey's hard threshold).
	seq := uint32(k.sendSeq)
	k.sendSeq++
	return framing.Seal(k.sendAEAD, tag, typ, seq, payload, padding), seq
}

// open authenticates a frame, enforces the replay window and returns the
// decrypted metadata and payload.
func (k *Keys) open(wire []byte) (framing.Frame, error) {
	f, err := framing.Open(k.recvAEAD, wire)
	if err != nil {
		if errors.Is(err, framing.ErrAuth) {
			return f, ErrAuth
		}
		return f, err
	}
	if !k.replay.Check(uint64(f.Seq)) {
		return f, ErrReplay
	}
	k.replay.Add(uint64(f.Seq))
	return f, nil
}

// Seq returns the current send counter (used to trigger rekeying).
func (k *Keys) Seq() uint64 { return k.sendSeq }

// randomTag returns a fresh opaque session tag.
func randomTag() [4]byte {
	var t [4]byte
	randRead(t[:])
	return t
}

// decoyJitter returns a random cover-traffic interval around base, so decoy
// frames do not fire like a metronome.
func decoyJitter(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	half := base / 2
	return half + time.Duration(crandInt63n(int64(base)))
}

// makePadding returns n random bytes (n <= 0 yields nil).
// crandInt63n returns a cryptographically random value in [0, n).
func crandInt63n(n int64) int64 {
	var b [8]byte
	randRead(b[:])
	// #nosec G115 -- a random value reduced modulo n; sign is irrelevant.
	return int64(binary.BigEndian.Uint64(b[:])) % n
}

func makePadding(n int) []byte {
	if n <= 0 {
		return nil
	}
	b := make([]byte, n)
	randRead(b)
	return b
}

func assignPayload(prefix int, ip, gw net.IP) []byte {
	b := make([]byte, 9)
	b[0] = byte(prefix) // #nosec G115 -- prefix is the subnet mask bit count (<= 32)
	copy(b[1:5], ip.To4())
	copy(b[5:9], gw.To4())
	return b
}

func parseAssign(b []byte) (prefix int, ip, gw net.IP, err error) {
	if len(b) != 9 {
		return 0, nil, nil, errors.New("session: malformed assignment")
	}
	prefix = int(b[0])
	ip = net.IP(append([]byte(nil), b[1:5]...))
	gw = net.IP(append([]byte(nil), b[5:9]...))
	return prefix, ip, gw, nil
}
