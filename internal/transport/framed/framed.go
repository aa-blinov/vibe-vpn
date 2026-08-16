// Package framed packetizes a net.Conn into length-prefixed frames so any
// stream transport can be exposed to the session layer as a datagram
// Transport. Frame = [4-byte big-endian length][payload].
package framed

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// MaxFrame is the largest frame accepted.
const MaxFrame = 65535

// ErrTooLarge is returned when a frame exceeds MaxFrame.
var ErrTooLarge = errors.New("framed: frame too large")

// Conn adapts a net.Conn to transport.Transport.
type Conn struct {
	conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
}

// New wraps a connection in length-prefix framing.
func New(conn net.Conn) *Conn {
	return NewWithReader(conn, bufio.NewReader(conn))
}

// NewWithReader wraps a connection using an existing buffered reader (used
// when some bytes have already been consumed from the stream).
func NewWithReader(conn net.Conn, r *bufio.Reader) *Conn {
	return &Conn{conn: conn, r: r}
}

func (c *Conn) Send(b []byte) error {
	if len(b) == 0 || len(b) > MaxFrame {
		return ErrTooLarge
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b))) // #nosec G115 -- len(b) <= MaxFrame

	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.conn.Write(b)
	return err
}

func (c *Conn) Receive() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxFrame {
		return nil, errors.New("framed: invalid frame length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *Conn) Close() error { return c.conn.Close() }
