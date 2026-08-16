package session

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/crypto"
	"github.com/aa-blinov/vibe-vpn/internal/framing"
	"github.com/aa-blinov/vibe-vpn/internal/pcap"
	"github.com/aa-blinov/vibe-vpn/internal/protocol"
	"github.com/aa-blinov/vibe-vpn/internal/transport"
)

const (
	reconnectBackoff = 2 * time.Second
	// maxWireSeq is the largest wire sequence number before the uint32 field
	// wraps; a rekey is forced below it.
	maxWireSeq = uint64(1)<<32 - 1024
)

var errRekeyFailed = errors.New("session: rekey failed")

// ClientConfig configures the client side of a session.
type ClientConfig struct {
	Dial              func() (transport.Transport, error)
	Keypair           *crypto.Keypair
	ServerPublic      []byte
	MTU               int
	Keepalive         time.Duration
	SessionTimeout    time.Duration
	HandshakeTimeout  time.Duration
	RekeyAfterPackets uint64
	RekeyAfterTime    time.Duration
	ClientIP          net.IP // optional preferred address inside the server subnet
	Shaping           framing.Shaping
	Pcap              *pcap.Writer
	Log               *log.Logger
}

// Client is a VPN client session. All protocol state is mutated from a single
// run-loop goroutine, so no internal locking is needed.
type Client struct {
	cfg ClientConfig
	t   transport.Transport

	keys   *Keys
	tag    [4]byte
	ip     net.IP
	gw     net.IP
	prefix int

	requestedIP net.IP
	connected   bool
	lastRekey   time.Time
	rekeying    bool
	rekeyHs     *crypto.Handshake

	stats        Stats
	lastRecv     time.Time
	lastDataSend time.Time

	recvCh chan recvResult
	done   chan struct{}
}

type recvResult struct {
	data []byte
	err  error
}

// NewClient builds a client session.
func NewClient(cfg ClientConfig) *Client {
	return &Client{
		cfg:         cfg,
		requestedIP: cfg.ClientIP,
		done:        make(chan struct{}),
	}
}

// IP returns the address assigned by the server (valid after a successful
// handshake). The returned slice is a copy.
func (c *Client) IP() net.IP {
	if c.ip == nil {
		return nil
	}
	return append(net.IP(nil), c.ip...)
}

// Gateway returns the tunnel-side address of the server.
func (c *Client) Gateway() net.IP {
	if c.gw == nil {
		return nil
	}
	return append(net.IP(nil), c.gw...)
}

// Prefix returns the subnet prefix assigned by the server.
func (c *Client) Prefix() int { return c.prefix }

// Stats returns the session statistics.
func (c *Client) Stats() *Stats { return &c.stats }

// Run drives the session until ctx is cancelled. onAssign is invoked (from the
// run loop) after every successful handshake with the assigned addresses; the
// caller should (re)configure the TUN address and routes accordingly.
func (c *Client) Run(ctx context.Context, tun TUN, onAssign func(ip, gw net.IP, prefix int)) error {
	defer close(c.done)

	tunCh := make(chan []byte, 256)
	go func() {
		for {
			pkt, err := tun.ReadPacket()
			if err != nil {
				return
			}
			select {
			case tunCh <- pkt:
			case <-c.done:
				return
			}
		}
	}()

	// Initial connection (retrying until ctx is cancelled).
	backoff := time.NewTimer(0)
	if !backoff.Stop() {
		<-backoff.C
	}
	for {
		if err := c.connect(ctx); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-backoff.C:
		}
		backoff.Reset(reconnectBackoff)
	}
	c.lastRecv = time.Now()
	if onAssign != nil {
		onAssign(c.ip, c.gw, c.prefix)
	}

	keepalive := time.NewTicker(c.cfg.Keepalive)
	defer keepalive.Stop()

	var decoyCh <-chan time.Time
	var decoyTimer *time.Timer
	if c.cfg.Shaping.DecoyInterval > 0 {
		decoyTimer = time.NewTimer(c.cfg.Shaping.DecoyInterval)
		decoyCh = decoyTimer.C
		defer decoyTimer.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			c.sendClose()
			c.teardownTransport()
			return nil

		case pkt := <-tunCh:
			if pkt == nil {
				continue
			}
			c.sendPacket(pkt)

		case r := <-c.recvCh:
			if r.err != nil {
				c.reconnect(ctx, tun, onAssign)
				continue
			}
			c.lastRecv = time.Now()
			if err := c.handleFrame(r.data, tun); err != nil {
				if errors.Is(err, ErrPeerClosed) {
					c.reconnect(ctx, tun, onAssign)
					continue
				}
				// Malformed frames are counted and ignored.
			}

		case <-keepalive.C:
			if time.Since(c.lastRecv) > c.cfg.SessionTimeout {
				c.reconnect(ctx, tun, onAssign)
				continue
			}
			if c.connected && !c.rekeying {
				c.sendKeepalive()
				c.maybeRekey()
			}

		case <-decoyCh:
			if c.connected && !c.rekeying && time.Since(c.lastDataSend) >= c.cfg.Shaping.DecoyInterval {
				c.sendDecoy()
			}
			if decoyTimer != nil {
				decoyTimer.Reset(decoyJitter(c.cfg.Shaping.DecoyInterval))
			}
		}
	}
}

// connect establishes a fresh connection: transport, handshake, keys and IP
// assignment. It re-creates the receive channel so stale frames from a
// previous connection are discarded.
func (c *Client) connect(ctx context.Context) error {
	c.teardownTransport()
	t, err := c.cfg.Dial()
	if err != nil {
		return err
	}
	c.t = t
	c.recvCh = make(chan recvResult, 512)
	go c.transportReader(t, c.recvCh)
	return c.handshake(ctx)
}

func (c *Client) transportReader(t transport.Transport, ch chan recvResult) {
	for {
		b, err := t.Receive()
		if err != nil {
			select {
			case ch <- recvResult{err: err}:
			default:
			}
			return
		}
		select {
		case ch <- recvResult{data: b}:
		case <-c.done:
			return
		}
	}
}

// handshake performs the Noise XK handshake and waits for the address
// assignment. Handshake messages are raw Noise messages; the assignment is the
// first encrypted session frame.
func (c *Client) handshake(ctx context.Context) error {
	start := time.Now()

	tag := randomTag()
	hs, err := crypto.NewClientHandshake(c.cfg.Keypair, c.cfg.ServerPublic)
	if err != nil {
		return err
	}

	m1, _, _, err := hs.Write(tag[:])
	if err != nil {
		return err
	}
	if err := c.sendRaw(m1); err != nil {
		return err
	}
	if c.cfg.Log != nil {
		c.cfg.Log.Printf("sent handshake1 (%d bytes)", len(m1))
	}

	if err := c.waitRaw(ctx, func(msg []byte) error {
		_, _, _, err := hs.Read(msg)
		return err
	}); err != nil {
		if c.cfg.Log != nil {
			c.cfg.Log.Printf("handshake1 reply: %v", err)
		}
		return err
	}

	m3, c2s, s2c, err := hs.Write(nil)
	if err != nil {
		return err
	}
	if c2s == nil || s2c == nil {
		return errors.New("session: handshake did not complete")
	}
	if err := c.sendRaw(m3); err != nil {
		return err
	}

	c.tag = tag
	c.keys = newKeys(true, c2s, s2c)

	assign, err := c.waitAssign(ctx)
	if err != nil {
		c.keys = nil
		return err
	}
	prefix, ip, gw, err := parseAssign(assign)
	if err != nil {
		c.keys = nil
		return err
	}

	c.ip, c.gw, c.prefix = ip, gw, prefix
	c.requestedIP = ip
	c.connected = true
	c.lastRekey = time.Now()
	c.stats.Handshakes.Add(1)
	c.stats.HandshakeNanos.Store(int64(time.Since(start)))
	return nil
}

// waitRaw consumes datagrams until try() accepts one (returns nil), subject to
// a timeout. Failed attempts are discarded; the Noise state is rolled back by
// the library so a failed read does not poison the handshake.
func (c *Client) waitRaw(ctx context.Context, try func([]byte) error) error {
	t := time.NewTimer(c.cfg.HandshakeTimeout)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return ErrTimeout
		case r := <-c.recvCh:
			if r.err != nil {
				return r.err
			}
			if err := try(r.data); err == nil {
				return nil
			}
		}
	}
}

// waitAssign consumes session frames until the address assignment arrives.
func (c *Client) waitAssign(ctx context.Context) ([]byte, error) {
	t := time.NewTimer(c.cfg.HandshakeTimeout)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
			return nil, ErrTimeout
		case r := <-c.recvCh:
			if r.err != nil {
				return nil, r.err
			}
			f, err := c.keys.open(r.data)
			if err != nil {
				continue
			}
			if f.Tag != c.tag {
				continue
			}
			if f.Type == protocol.MsgAssign {
				return f.Payload, nil
			}
		}
	}
}

func (c *Client) handleFrame(data []byte, tun TUN) error {
	if c.keys == nil {
		c.stats.PacketsDropped.Add(1)
		return nil
	}
	f, err := c.keys.open(data)
	if err != nil {
		c.stats.PacketsDropped.Add(1)
		return nil
	}
	if f.Tag != c.tag {
		c.stats.PacketsDropped.Add(1)
		return nil
	}
	switch f.Type {
	case protocol.MsgData:
		return c.handleData(f.Payload, tun)

	case protocol.MsgKeepalive:
		if len(f.Payload) == 8 {
			// #nosec G115 -- a forged cookie only skews RTT and the result is clamped below.
			sent := time.Unix(0, int64(binary.BigEndian.Uint64(f.Payload)))
			if rtt := time.Since(sent); rtt > 0 && rtt < time.Minute {
				c.stats.RecordRTT(rtt)
			}
		}
		return nil

	case protocol.MsgClose:
		return ErrPeerClosed

	case protocol.MsgDecoy:
		return nil

	case protocol.MsgRekey2:
		if c.rekeying {
			return c.continueRekey(f.Payload)
		}
		return nil
	}
	return nil
}

func (c *Client) handleData(pt []byte, tun TUN) error {
	if len(pt) > c.cfg.MTU || !isIPv4(pt) {
		c.stats.PacketsDropped.Add(1)
		return nil
	}
	if c.cfg.Pcap != nil {
		c.cfg.Pcap.WritePacket(pt)
	}
	if err := tun.WritePacket(pt); err != nil {
		return nil
	}
	c.stats.PacketsReceived.Add(1)
	c.stats.BytesReceived.Add(uint64(len(pt)))
	c.stats.recordSize(len(pt))
	return nil
}

func (c *Client) sendPacket(pkt []byte) {
	if len(pkt) > c.cfg.MTU || !isIPv4(pkt) {
		c.stats.PacketsDropped.Add(1)
		return
	}
	if c.cfg.Pcap != nil {
		c.cfg.Pcap.WritePacket(pkt)
	}
	if !c.encryptSend(protocol.MsgData, pkt) {
		// Not connected or rekeying in progress: packet is lost.
		c.stats.PacketsDropped.Add(1)
	}
}

func (c *Client) sendKeepalive() {
	var cookie [8]byte
	binary.BigEndian.PutUint64(cookie[:], uint64(time.Now().UnixNano()))
	c.encryptSend(protocol.MsgKeepalive, cookie[:])
}

func (c *Client) sendDecoy() {
	payload := make([]byte, 16+cryptoRandInt(64))
	randRead(payload)
	c.encryptSend(protocol.MsgDecoy, payload)
}

func (c *Client) maybeRekey() {
	// Hard safety threshold: never let the uint32 wire sequence number wrap.
	if c.keys != nil && c.keys.Seq() >= maxWireSeq {
		c.startRekey()
		return
	}
	if c.cfg.RekeyAfterPackets > 0 && c.keys != nil && c.keys.Seq() >= c.cfg.RekeyAfterPackets {
		c.startRekey()
		return
	}
	if !c.rekeying && c.cfg.RekeyAfterTime > 0 && time.Since(c.lastRekey) >= c.cfg.RekeyAfterTime {
		c.startRekey()
	}
}

// startRekey begins a fresh Noise XK handshake inside the live session. The
// rekey messages travel inside AEAD frames; data flow pauses until the rekey
// completes or fails.
func (c *Client) startRekey() {
	hs, err := crypto.NewClientHandshake(c.cfg.Keypair, c.cfg.ServerPublic)
	if err != nil {
		return
	}
	m1, _, _, err := hs.Write(nil)
	if err != nil {
		return
	}
	if !c.encryptSend(protocol.MsgRekey1, m1) {
		return
	}
	c.rekeyHs = hs
	c.rekeying = true
}

func (c *Client) continueRekey(noiseMsg []byte) error {
	if _, _, _, err := c.rekeyHs.Read(noiseMsg); err != nil {
		return errRekeyFailed
	}
	m3, c2s, s2c, err := c.rekeyHs.Write(nil)
	if err != nil || c2s == nil || s2c == nil {
		return errRekeyFailed
	}
	if !c.encryptSend(protocol.MsgRekey3, m3) {
		return errRekeyFailed
	}
	c.keys = newKeys(true, c2s, s2c)
	c.rekeying = false
	c.rekeyHs = nil
	c.lastRekey = time.Now()
	c.stats.Rekeys.Add(1)
	return nil
}

func (c *Client) reconnect(ctx context.Context, tun TUN, onAssign func(net.IP, net.IP, int)) {
	c.stats.Reconnects.Add(1)
	c.teardownTransport()
	backoff := time.NewTimer(reconnectBackoff)
	defer backoff.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-backoff.C:
		}
		if err := c.connect(ctx); err != nil {
			c.stats.Reconnects.Add(1)
			backoff.Reset(reconnectBackoff)
			continue
		}
		c.lastRecv = time.Now()
		onAssign(c.ip, c.gw, c.prefix)
		return
	}
}

// teardownTransport closes the current transport and resets per-connection
// state. The receive channel is replaced by the next connect().
func (c *Client) teardownTransport() {
	c.connected = false
	c.rekeying = false
	c.rekeyHs = nil
	if c.t != nil {
		_ = c.t.Close()
		c.t = nil
	}
	c.keys = nil
}

func (c *Client) encryptSend(typ byte, pt []byte) bool {
	if c.keys == nil {
		return false
	}
	if c.rekeying && !protocol.IsRekey(typ) {
		return false
	}
	padding := c.cfg.Shaping.PaddingFor(framing.InnerHeaderLen + len(pt))
	wire, _ := c.keys.seal(c.tag, typ, pt, makePadding(padding))
	if err := c.t.Send(wire); err != nil {
		return false
	}
	c.stats.PacketsSent.Add(1)
	c.stats.BytesSent.Add(uint64(len(wire)))
	c.stats.recordSize(len(pt))
	if typ == protocol.MsgData {
		c.lastDataSend = time.Now()
	}
	return true
}

// sendRaw transmits a raw (unframed) message, used for the initial handshake.
func (c *Client) sendRaw(b []byte) error {
	if len(b) == 0 || len(b) > protocol.MaxPayload {
		return errors.New("session: payload too large")
	}
	return c.t.Send(b)
}

func (c *Client) sendClose() {
	if c.keys != nil && !c.rekeying {
		c.encryptSend(protocol.MsgClose, nil)
	}
}

// ForceTransportError simulates a transport failure (used by tests to trigger
// the reconnect path).
func (c *Client) ForceTransportError() {
	if c.t != nil {
		_ = c.t.Close()
	}
}

func isIPv4(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}
	return pkt[0]>>4 == 4
}

func cryptoRandInt(n int) int {
	var b [8]byte
	randRead(b[:])
	// #nosec G115 -- a random value is reduced modulo n; signedness does not
	// affect uniformity.
	v := int64(binary.BigEndian.Uint64(b[:]))
	if v < 0 {
		v = -v
	}
	return int(v % int64(n))
}
