package framed

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// tcpPair returns a connected client/server net.Conn pair on loopback.
func tcpPair(t *testing.T) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.c, cc
}

func TestRoundtrip(t *testing.T) {
	s, c := tcpPair(t)
	defer s.Close()
	defer c.Close()

	sc := New(s)
	cc := New(c)

	got := make(chan []byte, 1)
	go func() {
		b, err := sc.Receive()
		if err != nil {
			got <- []byte("err:" + err.Error())
			return
		}
		got <- b
	}()

	if err := cc.Send([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		if string(b) != "hello" {
			t.Fatalf("got %q", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestSendTooLarge(t *testing.T) {
	s, c := tcpPair(t)
	defer s.Close()
	defer c.Close()
	cc := New(c)
	if err := cc.Send(make([]byte, MaxFrame+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	if err := cc.Send(nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge for empty frame, got %v", err)
	}
}

func TestReceiveErrors(t *testing.T) {
	s, c := tcpPair(t)
	defer s.Close()
	sc := New(s)

	// Invalid (zero) length prefix.
	if _, err := c.Write([]byte{0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Receive(); err == nil {
		t.Fatal("expected an error for a zero frame length")
	}

	// Truncated frame: header promises 10 bytes but only 2 arrive, then the
	// peer closes -> ReadFull hits EOF.
	if _, err := c.Write([]byte{0, 0, 0, 10, 1, 2}); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := sc.Receive(); err != io.ErrUnexpectedEOF && err != io.EOF {
		t.Fatalf("expected EOF on truncated frame, got %v", err)
	}
}
