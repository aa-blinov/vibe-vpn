// Package rawtcp provides an obfs4-inspired transport: a bare TCP connection
// whose traffic is indistinguishable from random bytes.
//
// Unlike the TLS transport there is no banner, no ALPN and no ClientHello.
// The session's Noise handshake (already random-looking messages) is carried
// directly over length-prefixed TCP. The server behaves like a black hole:
// a connection that does not complete the Noise handshake is simply closed, so
// an observer without the shared key sees only opaque random data.
//
// This is "looks like nothing" obfuscation in the spirit of obfs4/ScrambleSuit,
// not a byte-compatible obfs4 implementation (no Elligator 2 encoding).
package rawtcp

import (
	"net"
	"sync"
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/transport"
	"github.com/aa-blinov/vibe-vpn/internal/transport/framed"
)

// Dial opens a bare TCP connection to addr and packetizes it with the shared
// length-prefix framing.
func Dial(addr string) (transport.Transport, error) {
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	return framed.New(conn), nil
}

// Server accepts TCP connections and hands each one to the session layer.
type Server struct {
	ln     net.Listener
	mu     sync.Mutex
	onConn func(transport.Transport) bool
}

// Listen starts a bare TCP listener on addr.
func Listen(addr string) (*Server, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln}
	go s.acceptLoop()
	return s, nil
}

// SetOnConn installs the callback invoked for each connection. It must return
// true to accept the connection.
func (s *Server) SetOnConn(fn func(transport.Transport) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onConn = fn
}

// Addr returns the address the server is bound to.
func (s *Server) Addr() net.Addr { return s.ln.Addr() }

// Close stops the listener.
func (s *Server) Close() error { return s.ln.Close() }

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	s.mu.Lock()
	fn := s.onConn
	s.mu.Unlock()
	t := framed.New(conn)
	if fn == nil || !fn(t) {
		_ = t.Close()
	}
}
