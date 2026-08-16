// Package ctl exposes a small control channel on a unix socket so operators
// can introspect a running server or client (`vibe-vpn status --config ...`),
// in the spirit of `wg show`.
package ctl

import (
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

// Server serves a status snapshot on a unix socket.
type Server struct {
	ln     net.Listener
	path   string
	status func() string
}

// Serve listens on the unix socket at path and answers requests with the
// current status snapshot. It removes any stale socket first.
func Serve(path string, status func() string) (*Server, error) {
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// #nosec G302 -- a read-only status socket must be queryable by any local
	// user; it exposes no secrets.
	_ = os.Chmod(path, 0o666)
	s := &Server{ln: ln, path: path, status: status}
	go s.acceptLoop()
	return s, nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			buf := make([]byte, 256)
			_, _ = conn.Read(buf) // consume a bounded request, then respond
			_, _ = fmt.Fprint(conn, s.status())
		}()
	}
}

// Close stops the server and removes the socket.
func (s *Server) Close() error {
	_ = os.Remove(s.path)
	return s.ln.Close()
}

// Query connects to the socket at path and returns the status snapshot.
func Query(path string) (string, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "status\n"); err != nil {
		return "", err
	}
	data, err := io.ReadAll(conn)
	return string(data), err
}
