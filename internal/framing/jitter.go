package framing

import (
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/transport"
)

// Jitter decorates a transport with a random delay before every Send. This
// flattens burst and keepalive timing patterns. A max of zero returns the
// underlying transport unchanged.
func Jitter(t transport.Transport, max time.Duration) transport.Transport {
	if max <= 0 {
		return t
	}
	return &jitterTransport{t: t, max: max}
}

type jitterTransport struct {
	t   transport.Transport
	max time.Duration
}

func (j *jitterTransport) Send(b []byte) error {
	if j.max > 0 {
		time.Sleep(time.Duration(randN(int(j.max))))
	}
	return j.t.Send(b)
}

func (j *jitterTransport) Receive() ([]byte, error) { return j.t.Receive() }

func (j *jitterTransport) Close() error { return j.t.Close() }
