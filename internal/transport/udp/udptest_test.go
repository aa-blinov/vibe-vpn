package udp

import (
	"net"
	"testing"
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/transport"
)

func TestLoopbackRoundtrip(t *testing.T) {
	srv, err := Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("server addr", srv.Addr())
	got := make(chan string, 1)
	srv.SetOnNewPeer(func(remote *net.UDPAddr, tr transport.Transport) bool {
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
	t.Log("client dialed", c.RemoteAddr())
	if err := c.Send([]byte("ping")); err != nil {
		t.Fatal("client send:", err)
	}
	select {
	case msg := <-got:
		t.Log("server said", msg)
	case <-time.After(3 * time.Second):
		t.Fatal("server timeout")
	}
	rb, err := c.Receive()
	if err != nil {
		t.Fatal("client receive:", err)
	}
	t.Log("client got", string(rb))
	c.Close()
	srv.Close()
}
