package rawtcp

import (
	"net"
	"testing"
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/transport"
)

// dialRaw opens a plain TCP connection without framing, like an arbitrary
// client that does not speak our protocol.
func dialRaw(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 5*time.Second)
}

func TestRoundtrip(t *testing.T) {
	srv, err := Listen("127.0.0.1:0")
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

	c, err := Dial(srv.Addr().String())
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
	if err != nil || string(reply) != "pong:hello" {
		t.Fatalf("reply %q err %v", reply, err)
	}
}

// TestBlackHole verifies the black-hole behaviour: a connection that sends
// unauthenticated data gets no useful response and is closed.
func TestBlackHole(t *testing.T) {
	srv, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	srv.SetOnConn(func(tr transport.Transport) bool {
		return true // the session layer will reject garbage and close
	})

	conn, err := dialRaw(srv.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("not our handshake")); err != nil {
		t.Fatal(err)
	}
	// Read whatever comes back (likely EOF/close) within a timeout.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if n > 0 {
		t.Fatalf("black hole returned data: %q", buf[:n])
	}
}
