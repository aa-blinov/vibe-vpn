// Package udp provides a UDP transport for the tunnel.
package udp

import (
	"errors"
	"net"
	"sync"

	"github.com/aa-blinov/vibe-vpn/internal/transport"
)

// MaxDatagram is the largest UDP payload we accept (65507 = 65535 - 8 UDP hdr).
const MaxDatagram = 65507

var errClosed = errors.New("udp: transport closed")

// Client is a connected UDP transport: one socket, one remote peer. It reads
// datagrams in the background and hands them out one at a time via Receive.
type Client struct {
	conn   *net.UDPConn
	remote *net.UDPAddr

	recvCh    chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

// Dial connects to a remote UDP address, e.g. "1.2.3.4:4433".
func Dial(addr string) (*Client, error) {
	remote, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	t := &Client{
		conn:   conn,
		remote: remote,
		recvCh: make(chan []byte, 512),
		done:   make(chan struct{}),
	}
	go t.readLoop()
	return t, nil
}

func (t *Client) readLoop() {
	buf := make([]byte, MaxDatagram)
	for {
		n, err := t.conn.Read(buf)
		if err != nil {
			close(t.recvCh)
			return
		}
		if n == 0 {
			continue
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])
		select {
		case t.recvCh <- cp:
		case <-t.done:
			return
		}
	}
}

// Send writes one datagram to the remote peer.
func (t *Client) Send(b []byte) error {
	if len(b) == 0 || len(b) > MaxDatagram {
		return errors.New("udp: datagram too large")
	}
	select {
	case <-t.done:
		return errClosed
	default:
	}
	_, err := t.conn.Write(b)
	return err
}

// Receive blocks until a datagram is available or the transport is closed.
func (t *Client) Receive() ([]byte, error) {
	b, ok := <-t.recvCh
	if !ok {
		return nil, errClosed
	}
	return b, nil
}

// Close shuts down the socket and unblocks Receive.
func (t *Client) Close() error {
	t.closeOnce.Do(func() { close(t.done) })
	return t.conn.Close()
}

// RemoteAddr returns the remote peer's address.
func (t *Client) RemoteAddr() string { return t.remote.String() }

// endpoint is a single peer's receive queue on the shared server socket.
type endpoint struct {
	remote *net.UDPAddr
	ch     chan []byte
	done   chan struct{}
}

// Server is a single UDP socket serving many clients. A background loop reads
// datagrams and demultiplexes them to per-peer endpoint queues.
type Server struct {
	conn *net.UDPConn
	addr *net.UDPAddr

	// mu guards eps, closed and onNewPeer.
	mu  sync.Mutex
	eps map[string]*endpoint

	// onNewPeer is invoked (from the read loop) the first time a datagram is
	// seen from a given address. It hands the caller a Transport bound to that
	// peer; the caller is expected to keep reading from it. If the callback
	// returns false the peer is ignored.
	onNewPeer func(remote *net.UDPAddr, t transport.Transport) bool

	closed bool
}

// SetOnNewPeer installs the callback used to admit new peers. It must be
// called before the first datagram is expected.
func (s *Server) SetOnNewPeer(fn func(remote *net.UDPAddr, t transport.Transport) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onNewPeer = fn
}

// Listen binds a UDP socket on addr, e.g. "0.0.0.0:4433".
func Listen(addr string) (*Server, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	s := &Server{conn: conn, addr: conn.LocalAddr().(*net.UDPAddr), eps: make(map[string]*endpoint)}
	go s.readLoop()
	s.SetOnNewPeer(nil)
	return s, nil
}

func (s *Server) readLoop() {
	buf := make([]byte, MaxDatagram)
	for {
		n, remote, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return // socket closed
		}
		if n == 0 {
			continue
		}
		cp := make([]byte, n)
		copy(cp, buf[:n])

		key := remote.String()
		s.mu.Lock()
		ep, known := s.eps[key]
		if !known && !s.closed {
			ep = &endpoint{remote: remote, ch: make(chan []byte, 512), done: make(chan struct{})}
			s.eps[key] = ep
		}
		s.mu.Unlock()
		if !known {
			if s.closed {
				return
			}
			t := &endpointTransport{srv: s, remote: remote, ep: ep}
			s.mu.Lock()
			fn := s.onNewPeer
			s.mu.Unlock()
			if fn == nil || !fn(remote, t) {
				// Rejected: drop and remove.
				s.mu.Lock()
				delete(s.eps, key)
				s.mu.Unlock()
				close(ep.done)
				continue
			}
		}
		select {
		case ep.ch <- cp:
		case <-ep.done:
		}
	}
}

// SendTo writes a datagram to the given peer.
func (s *Server) SendTo(remote *net.UDPAddr, b []byte) error {
	if len(b) == 0 || len(b) > MaxDatagram {
		return errors.New("udp: datagram too large")
	}
	_, err := s.conn.WriteToUDP(b, remote)
	return err
}

// Addr returns the address the server is bound to.
func (s *Server) Addr() *net.UDPAddr { return s.addr }

// Close closes the socket and all endpoint queues.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	eps := s.eps
	s.eps = make(map[string]*endpoint)
	s.mu.Unlock()
	for _, ep := range eps {
		close(ep.done)
	}
	return s.conn.Close()
}

// endpointTransport adapts one peer of a Server to the transport.Transport
// interface so the session layer is identical to the client's.
type endpointTransport struct {
	srv    *Server
	remote *net.UDPAddr
	ep     *endpoint
	mu     sync.Mutex
	closed bool
}

func (t *endpointTransport) Send(b []byte) error {
	return t.srv.SendTo(t.remote, b)
}

func (t *endpointTransport) Receive() ([]byte, error) {
	select {
	case b, ok := <-t.ep.ch:
		if !ok {
			return nil, errClosed
		}
		return b, nil
	case <-t.ep.done:
		return nil, errClosed
	}
}

func (t *endpointTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	s := t.srv
	s.mu.Lock()
	if s.eps[t.remote.String()] == t.ep {
		delete(s.eps, t.remote.String())
	}
	s.mu.Unlock()
	select {
	case <-t.ep.done:
	default:
		close(t.ep.done)
	}
	return nil
}

// RemoteAddr returns the remote peer's address.
func (t *endpointTransport) RemoteAddr() string { return t.remote.String() }
