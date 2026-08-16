// Package transport defines the pluggable carrier between client and server.
// The session layer only depends on this interface, so alternative transports
// (TCP, TLS, QUIC, custom framing) can be dropped in without touching crypto or
// session logic.
package transport

// Transport is the interface the VPN session uses to exchange framed messages
// with the remote peer. Each call to Send transmits exactly one frame; each
// call to Receive returns exactly one frame.
type Transport interface {
	// Send delivers one frame to the remote peer. It may block.
	Send([]byte) error
	// Receive blocks until a frame from the remote peer is available.
	Receive() ([]byte, error)
	// Close tears down the transport. Concurrent and pending Receive calls
	// return an error.
	Close() error
}

// RemoteAddr returns the address of the remote peer, if the transport exposes
// it. Addresses are used only for logging and diagnostics.
type RemoteAddr interface {
	RemoteAddr() string
}
