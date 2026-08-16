package crypto

import (
	noise "github.com/flynn/noise"
)

// Handshake drives one side of an XK handshake. The pattern authenticates the
// server to the client (the client pins the server's static public key) and
// lets the server learn the client's static identity. All three messages carry
// encrypted payloads.
//
// Message flow (XK):
//
//	client -> server: e, es      (payload: requested client IP)
//	server -> client: e, ee      (payload: assigned client IP)
//	client -> server: s, se      (payload: optional)
//
// The first CipherState returned by a completed handshake encrypts
// client->server traffic, the second encrypts server->client traffic.
type Handshake struct {
	hs   *noise.HandshakeState
	done bool
}

// NewClientHandshake creates an initiator handshake. serverPublic is the
// pinned static public key of the server.
func NewClientHandshake(kp *Keypair, serverPublic []byte) (*Handshake, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   CipherSuite,
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		Prologue:      HandshakeName,
		StaticKeypair: noise.DHKey{Private: kp.Private, Public: kp.Public},
		PeerStatic:    serverPublic,
	})
	if err != nil {
		return nil, err
	}
	return &Handshake{hs: hs}, nil
}

// NewServerHandshake creates a responder handshake for a connection from an
// unknown client.
func NewServerHandshake(kp *Keypair) (*Handshake, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   CipherSuite,
		Pattern:       noise.HandshakeXK,
		Initiator:     false,
		Prologue:      HandshakeName,
		StaticKeypair: noise.DHKey{Private: kp.Private, Public: kp.Public},
	})
	if err != nil {
		return nil, err
	}
	return &Handshake{hs: hs}, nil
}

// Write produces the next handshake message, optionally carrying payload. On
// the final message the two transport CipherStates are returned (clientToServer,
// serverToClient). A nil CipherState pair means the handshake is not complete.
func (h *Handshake) Write(payload []byte) (msg []byte, c2s, s2c *noise.CipherState, err error) {
	out, a, b, err := h.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, nil, err
	}
	if a != nil || b != nil {
		h.done = true
		return out, a, b, nil
	}
	return out, nil, nil, nil
}

// Read consumes a handshake message and returns its payload. On the final
// message the two transport CipherStates are returned. A nil CipherState pair
// means the handshake is not complete.
func (h *Handshake) Read(msg []byte) (payload []byte, c2s, s2c *noise.CipherState, err error) {
	out, a, b, err := h.hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, nil, nil, err
	}
	if a != nil || b != nil {
		h.done = true
		return out, a, b, nil
	}
	return out, nil, nil, nil
}

// Done reports whether the handshake finished.
func (h *Handshake) Done() bool { return h.done }

// PeerStatic returns the remote peer's static public key learned during the
// handshake (nil before it has been received).
func (h *Handshake) PeerStatic() []byte { return h.hs.PeerStatic() }
