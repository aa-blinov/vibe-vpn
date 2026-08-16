// Package tlsx provides a TLS transport for the tunnel that camouflages the
// traffic as ordinary HTTPS.
//
// The transport runs inside a real TLS connection and packetizes the session's
// datagrams with a 4-byte length prefix. Two client modes are supported:
//
//   - "browser" mode (recommended): the ClientHello imitates a real browser
//     (Chrome or Firefox via uTLS), ALPN is the ordinary "http/1.1", and the
//     tunnel is separated from other HTTPS clients by a short magic sequence
//     written inside the (encrypted) TLS stream. To a passive observer the
//     connection is indistinguishable from a browser talking HTTPS.
//   - legacy mode: the custom "vibe/1" ALPN selects the tunnel directly.
//
// The server answers browsers and probes with a minimal HTTP response, so the
// port behaves like a normal web server either way.
package tlsx

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/aa-blinov/vibe-vpn/internal/transport"
	"github.com/aa-blinov/vibe-vpn/internal/transport/framed"
)

const (
	// alpnTunnel is the ALPN used by legacy clients to select the tunnel.
	alpnTunnel = "vibe/1"
	// alpnHTTP is the ALPN offered to look like a normal web server.
	alpnHTTP = "http/1.1"

	// tunnelMagic is written by browser-mode clients as the first bytes inside
	// the TLS stream so the server can tell the tunnel from other HTTPS
	// clients. It is only visible after TLS decryption.
	tunnelMagic = "NVPN"

	maxFrame = 65535
)

// LoadCertPool reads a PEM certificate bundle into a root pool for client-side
// verification of the server certificate.
func LoadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("tlsx: no certificates found in " + path)
	}
	return pool, nil
}

// Dial connects a TLS tunnel to addr. fingerprint selects the client mode:
// "" or "chrome"/"firefox" for the browser-imitation mode (uTLS), "legacy" for
// the custom-ALPN mode.
func Dial(addr, serverName string, roots *x509.CertPool, insecure bool, fingerprint string) (transport.Transport, error) {
	switch fingerprint {
	case "", "chrome", "firefox":
		return dialBrowser(addr, serverName, roots, insecure, fingerprint)
	case "legacy":
		return dialLegacy(addr, serverName, roots, insecure)
	default:
		return nil, errors.New("tlsx: unknown fingerprint " + fingerprint + " (use chrome, firefox or legacy)")
	}
}

// dialBrowser imitates a real browser ClientHello via uTLS and selects the
// tunnel with the magic sequence inside the TLS stream.
func dialBrowser(addr, serverName string, roots *x509.CertPool, insecure bool, fingerprint string) (transport.Transport, error) {
	helloID := utls.HelloChrome_Auto
	if fingerprint == "firefox" {
		helloID = utls.HelloFirefox_Auto
	}
	cfg := &utls.Config{
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: insecure,
		NextProtos:         []string{alpnHTTP},
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
	}
	raw, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	uconn := utls.UClient(raw, cfg, helloID)
	if err := uconn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := uconn.Write([]byte(tunnelMagic)); err != nil {
		uconn.Close()
		return nil, err
	}
	return framed.New(uconn), nil
}

// dialLegacy uses the standard Go TLS stack and selects the tunnel with the
// custom "vibe/1" ALPN.
func dialLegacy(addr, serverName string, roots *x509.CertPool, insecure bool) (transport.Transport, error) {
	cfg := &tls.Config{
		ServerName:         serverName,
		RootCAs:            roots,
		InsecureSkipVerify: insecure,
		NextProtos:         []string{alpnTunnel},
		MinVersion:         tls.VersionTLS12,
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	return framed.New(conn), nil
}

// Server is a TLS listener that routes connections to the tunnel or to a fake
// HTTP response.
type Server struct {
	ln     net.Listener
	mu     sync.Mutex
	onConn func(transport.Transport) bool
}

// Listen starts a TLS listener on addr using the given certificate and key.
func Listen(addr, certFile, keyFile string) (*Server, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnHTTP, alpnTunnel},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln}
	go s.acceptLoop()
	return s, nil
}

// SetOnConn installs the callback invoked for tunnel connections. It must
// return true to accept the connection.
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

func (s *Server) handleConn(raw net.Conn) {
	tconn, ok := raw.(*tls.Conn)
	if !ok {
		raw.Close()
		return
	}
	if err := tconn.Handshake(); err != nil {
		raw.Close()
		return
	}
	r := bufio.NewReader(tconn)

	// Legacy clients select the tunnel via the custom ALPN and send no magic.
	if tconn.ConnectionState().NegotiatedProtocol == alpnTunnel {
		s.acceptTunnel(tconn, r)
		return
	}

	// Browser-mode clients negotiate http/1.1 (or nothing); the tunnel is
	// identified by the magic sequence inside the encrypted stream.
	magic := make([]byte, len(tunnelMagic))
	if _, err := io.ReadFull(r, magic); err != nil {
		raw.Close()
		return
	}
	if string(magic) == tunnelMagic {
		s.acceptTunnel(tconn, r)
		return
	}
	// Anything else sees a normal web endpoint.
	serveFakeHTTP(tconn, r)
}

func (s *Server) acceptTunnel(tconn *tls.Conn, r *bufio.Reader) {
	s.mu.Lock()
	fn := s.onConn
	s.mu.Unlock()
	t := framed.NewWithReader(tconn, r)
	if fn == nil || !fn(t) {
		t.Close()
	}
}

// serveFakeHTTP answers a minimal HTTP response so the port behaves like a
// regular HTTPS server for browsers and probes.
func serveFakeHTTP(conn net.Conn, r *bufio.Reader) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	_, _ = r.Read(buf) // consume the request (or wait briefly for a probe)
	body := "<html><body>It works.</body></html>"
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" +
		body
	_, _ = conn.Write([]byte(resp))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
