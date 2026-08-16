package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/transport"
)

// writeTestCert materialises a self-signed certificate for a server.
func writeTestCert(t *testing.T, cn string) (certFile, keyFile string) {
	t.Helper()
	certPEM, keyPEM, err := GenerateSelfSigned(cn, 30)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func mustPool(t *testing.T, file string) *x509.CertPool {
	t.Helper()
	pool, err := LoadCertPool(file)
	if err != nil {
		t.Fatal(err)
	}
	return pool
}

func TestTunnelRoundtrip(t *testing.T) {
	certFile, keyFile := writeTestCert(t, "localhost")
	srv, err := Listen("127.0.0.1:0", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	got := make(chan string, 1)
	srv.SetOnConn(func(tr transport.Transport) bool {
		go func() {
			b, err := tr.Receive()
			if err != nil {
				got <- "recv err: " + err.Error()
				return
			}
			if err := tr.Send([]byte("pong:" + string(b))); err != nil {
				got <- "send err: " + err.Error()
				return
			}
			got <- "recv:" + string(b)
		}()
		return true
	})

	c, err := Dial(srv.Addr().String(), "localhost", mustPool(t, certFile), false, "chrome")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := c.Send([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-got:
		if msg != "recv:hello" {
			t.Fatalf("unexpected: %s", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server never got the frame")
	}
	reply, err := c.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "pong:hello" {
		t.Fatalf("unexpected reply %q", reply)
	}
}

func TestBrowserGetsHTTPNotTunnel(t *testing.T) {
	certFile, keyFile := writeTestCert(t, "example.com")
	srv, err := Listen("127.0.0.1:0", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	tunnelSeen := false
	srv.SetOnConn(func(tr transport.Transport) bool {
		tunnelSeen = true
		return true
	})

	// A plain TLS client negotiating http/1.1 (like a browser) must get an
	// HTTP response, not a tunnel transport.
	conn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"http/1.1"},
		RootCAs:    mustPool(t, certFile),
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n])[:12] != "HTTP/1.1 200" {
		t.Fatalf("expected HTTP response, got %q", buf[:n])
	}
	if tunnelSeen {
		t.Fatal("a browser client must not be routed to the tunnel")
	}
}

func TestCertificateVerification(t *testing.T) {
	certFile, _ := writeTestCert(t, "example.com")
	roots := mustPool(t, certFile)

	// Wrong server name: verification must fail.
	if _, err := Dial("127.0.0.1:1", "evil.example", roots, false, "legacy"); err == nil {
		t.Fatal("expected verification failure for a mismatched server name")
	}

	// Untrusted CA: verification must fail.
	other, otherKey := writeTestCert(t, "other.example")
	srv, err := Listen("127.0.0.1:0", other, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if _, err := Dial(srv.Addr().String(), "other.example", roots, false, "legacy"); err == nil {
		t.Fatal("expected verification failure for an untrusted CA")
	}
}

// TestBrowserTunnelRoundtrip verifies the browser-mode client (uTLS, http/1.1
// ALPN, magic-selected tunnel) works end to end.
func TestBrowserTunnelRoundtrip(t *testing.T) {
	certFile, keyFile := writeTestCert(t, "localhost")
	srv, err := Listen("127.0.0.1:0", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	got := make(chan string, 1)
	srv.SetOnConn(func(tr transport.Transport) bool {
		go func() {
			b, err := tr.Receive()
			if err != nil {
				got <- "recv err: " + err.Error()
				return
			}
			if err := tr.Send([]byte("pong:" + string(b))); err != nil {
				got <- "send err: " + err.Error()
				return
			}
			got <- "recv:" + string(b)
		}()
		return true
	})

	for _, fp := range []string{"chrome", "firefox"} {
		c, err := Dial(srv.Addr().String(), "localhost", mustPool(t, certFile), false, fp)
		if err != nil {
			t.Fatalf("%s: dial: %v", fp, err)
		}
		if err := c.Send([]byte("hi")); err != nil {
			c.Close()
			t.Fatalf("%s: send: %v", fp, err)
		}
		select {
		case msg := <-got:
			if msg != "recv:hi" {
				c.Close()
				t.Fatalf("%s: unexpected %s", fp, msg)
			}
		case <-time.After(5 * time.Second):
			c.Close()
			t.Fatalf("%s: no reply", fp)
		}
		reply, err := c.Receive()
		c.Close()
		if err != nil || string(reply) != "pong:hi" {
			t.Fatalf("%s: reply %q err %v", fp, reply, err)
		}
	}
}

// TestPlainTLSGetsHTTP verifies a browser-style TLS client that does not speak
// the tunnel receives an HTTP response, not a tunnel transport.
func TestPlainTLSGetsHTTP(t *testing.T) {
	certFile, keyFile := writeTestCert(t, "example.com")
	srv, err := Listen("127.0.0.1:0", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	tunnelSeen := false
	srv.SetOnConn(func(tr transport.Transport) bool {
		tunnelSeen = true
		return true
	})

	conn, err := tls.Dial("tcp", srv.Addr().String(), &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"http/1.1"},
		RootCAs:    mustPool(t, certFile),
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n])[:12] != "HTTP/1.1 200" {
		t.Fatalf("expected HTTP response, got %q", buf[:n])
	}
	if tunnelSeen {
		t.Fatal("a browser client must not be routed to the tunnel")
	}
}
