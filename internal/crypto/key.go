// Package crypto wraps the Noise Protocol Framework handshake and the
// symmetric primitives used for tunnel encryption. No cryptography is
// implemented here: everything delegates to well-tested standard primitives
// (X25519, ChaCha20-Poly1305, SHA-256) through the Noise framework.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	noise "github.com/flynn/noise"
)

// CipherSuite is the single suite used across the whole project:
// Noise_XK_25519_ChaChaPoly_SHA256.
var CipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// HandshakeName identifies the wire protocol in the Noise transcript.
var HandshakeName = []byte("NotVPN_1")

// Keypair is an X25519 keypair (32-byte private, 32-byte public).
type Keypair struct {
	Private []byte
	Public  []byte
}

// GenerateKeypair returns a fresh X25519 keypair from the crypto RNG.
func GenerateKeypair() (*Keypair, error) {
	kp, err := CipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Keypair{Private: kp.Private, Public: kp.Public}, nil
}

// KeypairFromPrivate reconstructs a keypair from a private key.
func KeypairFromPrivate(priv []byte) (*Keypair, error) {
	if len(priv) != 32 {
		return nil, errors.New("crypto: private key must be 32 bytes")
	}
	var base [32]byte
	base[0] = 9 // X25519 base point
	pub, err := noise.DH25519.DH(priv, base[:])
	if err != nil {
		return nil, err
	}
	return &Keypair{Private: priv, Public: pub}, nil
}

// EncodeKey encodes a 32-byte key as unpadded base64.
func EncodeKey(b []byte) string {
	return base64.RawStdEncoding.EncodeToString(b)
}

// DecodeKey decodes an unpadded base64 key.
func DecodeKey(s string) ([]byte, error) {
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("crypto: invalid key encoding: %w", err)
	}
	if len(b) != 32 {
		return nil, errors.New("crypto: key must decode to 32 bytes")
	}
	return b, nil
}
