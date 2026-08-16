package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/crypto"
	"github.com/aa-blinov/vibe-vpn/internal/framing"
	"github.com/aa-blinov/vibe-vpn/internal/ippkt"
	"github.com/aa-blinov/vibe-vpn/internal/pcap"
	"github.com/aa-blinov/vibe-vpn/internal/protocol"
	"github.com/aa-blinov/vibe-vpn/internal/transport"
)

const (
	DefaultMaxSessions = 1024
)

// ServerConfig configures the server side of the tunnel.
type ServerConfig struct {
	Keypair          *crypto.Keypair
	Subnet           *net.IPNet
	MTU              int
	Keepalive        time.Duration
	SessionTimeout   time.Duration
	HandshakeTimeout time.Duration
	Peers            map[string][]byte // allowlist by client public key; nil or empty = allow any
	MaxSessions      int
	Shaping          framing.Shaping
	Pcap             *pcap.Writer
	Log              *log.Logger
}

// ServerStats holds aggregate counters across all sessions.
type ServerStats struct {
	Sessions      atomic.Int64
	SessionsTotal atomic.Uint64
	Dropped       atomic.Uint64
	Handshakes    atomic.Uint64
}

// Manager owns all server-side sessions and the mapping between client
// addresses and session objects.
type Manager struct {
	cfg    ServerConfig
	gw     net.IP
	prefix int

	mu       sync.Mutex
	byID     map[uint32]*serverSession
	byIP     map[[4]byte]*serverSession
	byStatic map[string]*serverSession
	nextID   uint32

	peersMu sync.RWMutex
	peers   map[string][]byte // client allowlist; empty = allow any

	pool      *ipPool
	stats     ServerStats
	dataPlane TUN
}

// NewManager creates a session manager for the given subnet.
func NewManager(cfg ServerConfig) (*Manager, error) {
	if cfg.Subnet == nil {
		return nil, errors.New("session: server requires a subnet")
	}
	ones, _ := cfg.Subnet.Mask.Size()
	if ones < 2 {
		return nil, errors.New("session: subnet too small")
	}
	gw := gateway(cfg.Subnet)
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = DefaultMaxSessions
	}
	return &Manager{
		cfg:      cfg,
		gw:       gw,
		prefix:   ones,
		byID:     make(map[uint32]*serverSession),
		byIP:     make(map[[4]byte]*serverSession),
		byStatic: make(map[string]*serverSession),
		pool:     newIPPool(cfg.Subnet),
		peers:    cfg.Peers,
	}, nil
}

func gateway(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	out := make(net.IP, 4)
	copy(out, ip)
	out[3]++
	return out
}

// Gateway returns the tunnel-side address of the server.
func (m *Manager) Gateway() net.IP { return m.gw }

// Stats returns aggregate server statistics.
func (m *Manager) Stats() *ServerStats { return &m.stats }

// Active returns the number of live sessions.
func (m *Manager) Active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byID)
}

// CloseAll stops every live session (used in tests and on shutdown).
func (m *Manager) CloseAll() {
	m.mu.Lock()
	sessions := make([]*serverSession, 0, len(m.byID))
	for _, s := range m.byID {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		if s.cancel != nil {
			s.cancel()
		}
	}
}

// allowPeer reports whether a client static public key is permitted.
func (m *Manager) allowPeer(pub []byte) bool {
	m.peersMu.RLock()
	defer m.peersMu.RUnlock()
	if len(m.peers) == 0 {
		return true
	}
	_, ok := m.peers[base64.RawStdEncoding.EncodeToString(pub)]
	return ok
}

// SetPeers replaces the client allowlist at runtime (used for config reload).
// A nil or empty map allows any client.
func (m *Manager) SetPeers(peers map[string][]byte) {
	m.peersMu.Lock()
	defer m.peersMu.Unlock()
	m.peers = peers
}

// HandleTransport is called by the transport layer when a new peer appears.
// It starts a session run loop. The returned bool tells the transport whether
// to accept the peer.
func (m *Manager) HandleTransport(t transport.Transport) bool {
	m.mu.Lock()
	if len(m.byID) >= m.cfg.MaxSessions {
		m.mu.Unlock()
		m.stats.Dropped.Add(1)
		return false
	}
	id := m.allocIDLocked()
	m.mu.Unlock()

	s := &serverSession{
		mgr:      m,
		sid:      id,
		t:        t,
		created:  time.Now(),
		lastRecv: time.Now(),
	}
	m.mu.Lock()
	m.byID[id] = s
	m.stats.Sessions.Add(1)
	m.stats.SessionsTotal.Add(1)
	m.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	s.ctx = ctx
	s.cancel = cancel
	go s.run()
	return true
}

func (m *Manager) allocIDLocked() uint32 {
	for {
		m.nextID++
		if m.nextID == 0 {
			m.nextID = 1
		}
		if _, ok := m.byID[m.nextID]; !ok {
			return m.nextID
		}
	}
}

// adopt assigns the client IP after a successful handshake and registers the
// session. A reconnecting client (same static key) takes over its previous IP
// and bumps the old session.
func (m *Manager) adopt(s *serverSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := base64.RawStdEncoding.EncodeToString(s.clientKey)
	if old := m.byStatic[key]; old != nil && old != s {
		// Reconnect: reuse the previous address.
		s.ip = old.ip
		m.byIP[[4]byte(s.ip)] = s
		old.transferred = true
		if old.cancel != nil {
			old.cancel()
		}
		delete(m.byID, old.sid)
	} else {
		ip, err := m.pool.alloc(s.requestedIP)
		if err != nil {
			return err
		}
		s.ip = ip
	}
	m.byStatic[key] = s
	m.byIP[[4]byte(s.ip)] = s
	m.stats.Handshakes.Add(1)
	return nil
}

// remove releases a session's resources.
func (m *Manager) remove(s *serverSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byID[s.sid] == s {
		delete(m.byID, s.sid)
	}
	if s.ip != nil {
		k := [4]byte(s.ip)
		if m.byIP[k] == s {
			delete(m.byIP, k)
		}
		if !s.transferred {
			m.pool.release(s.ip)
		}
	}
	if s.clientKey != nil {
		key := base64.RawStdEncoding.EncodeToString(s.clientKey)
		if m.byStatic[key] == s {
			delete(m.byStatic, key)
		}
	}
	m.stats.Sessions.Add(-1)
}

// LookupIP returns the session owning an IPv4 address, or nil.
func (m *Manager) LookupIP(ip net.IP) *SessionView {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byIP[[4]byte(ip)]
	if !ok {
		return nil
	}
	return &SessionView{sid: s.sid, ip: s.ip}
}

// SessionView is a read-only snapshot of a session for the data plane.
type SessionView struct {
	sid uint32
	ip  net.IP
}

// Reply sends an IP packet from the server to a client session.
func (m *Manager) Reply(v *SessionView, pkt []byte) bool {
	m.mu.Lock()
	s, ok := m.byID[v.sid]
	m.mu.Unlock()
	if !ok {
		m.stats.Dropped.Add(1)
		return false
	}
	select {
	case s.replyCh <- pkt:
		return true
	default:
		m.stats.Dropped.Add(1)
		return false
	}
}

// TunLoop reads packets from the server's TUN and routes them to the right
// client session by destination address. It returns when ctx is cancelled.
func (m *Manager) TunLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		pkt, err := m.tun().ReadPacket()
		if err != nil {
			return
		}
		h, ok := ippkt.Parse(pkt)
		if !ok {
			m.stats.Dropped.Add(1)
			continue
		}
		if m.cfg.Pcap != nil {
			m.cfg.Pcap.WritePacket(pkt)
		}
		v := m.LookupIP(h.Dst)
		if v == nil {
			m.stats.Dropped.Add(1)
			continue
		}
		m.Reply(v, pkt)
	}
}

// tun returns the data-plane interface (set via SetTUN).
func (m *Manager) tun() TUN { return m.dataPlane }

// SetTUN installs the server's data plane.
func (m *Manager) SetTUN(t TUN) { m.dataPlane = t }

// SetDebugPcap installs a capture sink for the server TUN traffic.
func (m *Manager) SetDebugPcap(w *pcap.Writer) { m.cfg.Pcap = w }

// serverSession is one tunneled client.
type serverSession struct {
	mgr     *Manager
	sid     uint32
	t       transport.Transport
	created time.Time

	hs          *crypto.Handshake
	clientKey   []byte
	requestedIP net.IP
	ip          net.IP
	tag         [4]byte

	rekeyHs    *crypto.Handshake
	rekeying   bool
	rekeyStart time.Time
	keys       *Keys

	stats        Stats
	lastRecv     time.Time
	lastDataSend time.Time
	recvCh       chan recvResult
	replyCh      chan []byte

	ctx    context.Context
	cancel context.CancelFunc

	transferred bool
}

func (s *serverSession) run() {
	defer s.finish()
	s.recvCh = make(chan recvResult, 512)
	s.replyCh = make(chan []byte, 512)
	go s.transportReader(s.recvCh)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var decoyCh <-chan time.Time
	var decoyTimer *time.Timer
	if s.mgr.cfg.Shaping.DecoyInterval > 0 {
		decoyTimer = time.NewTimer(s.mgr.cfg.Shaping.DecoyInterval)
		decoyCh = decoyTimer.C
		defer decoyTimer.Stop()
	}

	for {
		select {
		case <-s.ctx.Done():
			return
		case r := <-s.recvCh:
			if r.err != nil {
				return
			}
			s.lastRecv = time.Now()
			if err := s.handle(r.data); err != nil {
				if errors.Is(err, errFatal) {
					return
				}
			}
		case pkt := <-s.replyCh:
			if s.keys != nil && s.ip != nil {
				s.encryptSend(protocol.MsgData, pkt)
			}
		case <-ticker.C:
			if s.keys == nil && time.Since(s.created) > s.mgr.cfg.HandshakeTimeout {
				return // handshake never completed
			}
			if time.Since(s.lastRecv) > s.mgr.cfg.SessionTimeout {
				s.sendClose()
				return
			}
			if s.rekeying && time.Since(s.rekeyStart) > s.mgr.cfg.HandshakeTimeout {
				s.rekeying = false
				s.rekeyHs = nil // keep old keys
			}
		case <-decoyCh:
			if s.keys != nil && !s.rekeying && time.Since(s.lastDataSend) >= s.mgr.cfg.Shaping.DecoyInterval {
				s.sendDecoy()
			}
			if decoyTimer != nil {
				decoyTimer.Reset(decoyJitter(s.mgr.cfg.Shaping.DecoyInterval))
			}
		}
	}
}

func (s *serverSession) transportReader(ch chan recvResult) {
	for {
		b, err := s.t.Receive()
		if err != nil {
			return
		}
		select {
		case ch <- recvResult{data: b}:
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *serverSession) finish() {
	s.mgr.remove(s)
	s.t.Close()
	s.sendCloseQuiet()
	if s.mgr.cfg.Log != nil {
		s.mgr.cfg.Log.Printf("session %d closed (%s)", s.sid, s.stats.Dump("server"))
	}
}

func (s *serverSession) sendCloseQuiet() {
	if s.keys != nil && !s.rekeying {
		s.encryptSend(protocol.MsgClose, nil)
	}
}

var errFatal = errors.New("session: fatal")

// handle dispatches one datagram. Before the handshake completes every
// datagram is treated as a raw Noise message; afterwards every datagram must
// open as an AEAD session frame.
func (s *serverSession) handle(data []byte) error {
	if s.keys == nil {
		if s.hs == nil {
			return s.handshake1(data)
		}
		return s.handshake3(data)
	}
	f, err := s.keys.open(data)
	if err != nil {
		s.stats.PacketsDropped.Add(1)
		return nil
	}
	if f.Tag != s.tag {
		s.stats.PacketsDropped.Add(1)
		return nil
	}
	switch f.Type {
	case protocol.MsgData:
		return s.handleData(f.Payload)
	case protocol.MsgKeepalive:
		return s.handleKeepalive(f.Payload)
	case protocol.MsgClose:
		return errFatal
	case protocol.MsgDecoy:
		return nil
	case protocol.MsgRekey1:
		return s.rekey1(f.Payload)
	case protocol.MsgRekey3:
		return s.rekey3(f.Payload)
	default:
		return nil // assign/others are server-invalid; ignore
	}
}

func (s *serverSession) handshake1(data []byte) error {
	if s.hs != nil || s.keys != nil {
		return nil
	}
	hs, err := crypto.NewServerHandshake(s.mgr.cfg.Keypair)
	if err != nil {
		return errFatal
	}
	payload, _, _, err := hs.Read(data)
	if err != nil {
		return errFatal // malformed handshake message
	}
	if len(payload) != 4 {
		return errFatal // first message must carry the session tag
	}
	copy(s.tag[:], payload)
	m2, _, _, err := hs.Write(nil)
	if err != nil {
		return nil
	}
	s.hs = hs
	return s.sendRaw(m2)
}

func (s *serverSession) handshake3(data []byte) error {
	if s.hs == nil {
		return nil
	}
	_, c2s, s2c, err := s.hs.Read(data)
	if err != nil {
		return errFatal // authentication failure
	}
	s.clientKey = s.hs.PeerStatic()
	if !s.mgr.allowPeer(s.clientKey) {
		return errFatal // unknown peer
	}
	if err := s.mgr.adopt(s); err != nil {
		return errFatal // no free addresses
	}
	s.keys = newKeys(false, c2s, s2c)
	s.hs = nil
	s.encryptSend(protocol.MsgAssign, assignPayload(s.mgr.prefix, s.ip, s.mgr.gw))
	return nil
}

func (s *serverSession) rekey1(noiseMsg []byte) error {
	if s.keys == nil || s.rekeying {
		return nil
	}
	hs, err := crypto.NewServerHandshake(s.mgr.cfg.Keypair)
	if err != nil {
		return nil
	}
	if _, _, _, err := hs.Read(noiseMsg); err != nil {
		return nil
	}
	m2, _, _, err := hs.Write(nil)
	if err != nil {
		return nil
	}
	s.rekeyHs = hs
	s.rekeying = true
	s.rekeyStart = time.Now()
	s.encryptSend(protocol.MsgRekey2, m2)
	return nil
}

func (s *serverSession) rekey3(noiseMsg []byte) error {
	if !s.rekeying || s.rekeyHs == nil {
		return nil
	}
	_, c2s, s2c, err := s.rekeyHs.Read(noiseMsg)
	if err != nil {
		// Abort the rekey; old keys stay in effect.
		s.rekeying = false
		s.rekeyHs = nil
		return nil
	}
	if !bytes.Equal(s.rekeyHs.PeerStatic(), s.clientKey) {
		s.rekeying = false
		s.rekeyHs = nil
		return nil
	}
	s.keys = newKeys(false, c2s, s2c)
	s.rekeying = false
	s.rekeyHs = nil
	s.stats.Rekeys.Add(1)
	return nil
}

func (s *serverSession) handleData(pt []byte) error {
	if s.keys == nil {
		return nil
	}
	if len(pt) > s.mgr.cfg.MTU || s.ip == nil {
		s.stats.PacketsDropped.Add(1)
		return nil
	}
	h, ok := ippkt.Parse(pt)
	if !ok {
		s.stats.PacketsDropped.Add(1)
		return nil
	}
	if !h.Src.Equal(s.ip) {
		s.stats.PacketsDropped.Add(1)
		return nil // spoofed source
	}
	if s.mgr.cfg.Pcap != nil {
		s.mgr.cfg.Pcap.WritePacket(pt)
	}
	if err := s.mgr.tun().WritePacket(pt); err != nil {
		return nil
	}
	s.stats.PacketsReceived.Add(1)
	s.stats.BytesReceived.Add(uint64(len(pt)))
	s.stats.recordSize(len(pt))
	return nil
}

func (s *serverSession) handleKeepalive(pt []byte) error {
	if s.keys == nil {
		return nil
	}
	s.encryptSend(protocol.MsgKeepalive, pt)
	return nil
}

func (s *serverSession) sendDecoy() {
	payload := make([]byte, 16+cryptoRandInt(64))
	randRead(payload)
	s.encryptSend(protocol.MsgDecoy, payload)
}

func (s *serverSession) encryptSend(typ byte, pt []byte) bool {
	if s.keys == nil {
		return false
	}
	if s.rekeying && !protocol.IsRekey(typ) {
		return false
	}
	padding := s.mgr.cfg.Shaping.PaddingFor(framing.InnerHeaderLen + len(pt))
	wire, _ := s.keys.seal(s.tag, typ, pt, makePadding(padding))
	if err := s.t.Send(wire); err != nil {
		return false
	}
	s.stats.PacketsSent.Add(1)
	s.stats.BytesSent.Add(uint64(len(wire)))
	s.stats.recordSize(len(pt))
	if typ == protocol.MsgData {
		s.lastDataSend = time.Now()
	}
	return true
}

// sendRaw transmits a raw (unframed) message, used for the initial handshake.
func (s *serverSession) sendRaw(b []byte) error {
	if len(b) == 0 || len(b) > protocol.MaxPayload {
		return errors.New("session: payload too large")
	}
	return s.t.Send(b)
}

func (s *serverSession) sendClose() {
	s.encryptSend(protocol.MsgClose, nil)
}

// randRead fills b from the crypto RNG.
func randRead(b []byte) {
	_, _ = rand.Read(b)
}

// ipPool allocates client addresses inside the subnet, avoiding the gateway.
type ipPool struct {
	mu      sync.Mutex
	network *net.IPNet
	gateway [4]byte
	used    map[[4]byte]bool
}

func newIPPool(n *net.IPNet) *ipPool {
	var g [4]byte
	ip := gateway(n)
	copy(g[:], ip)
	return &ipPool{network: n, gateway: g, used: make(map[[4]byte]bool)}
}

func (p *ipPool) inRange(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	if [4]byte(ip4) == p.gateway {
		return false
	}
	return p.network.Contains(ip4)
}

func (p *ipPool) alloc(preferred net.IP) (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if preferred != nil && p.inRange(preferred) {
		k := [4]byte(preferred.To4())
		if !p.used[k] {
			p.used[k] = true
			return preferred.To4(), nil
		}
	}
	// First free address above the gateway.
	base := p.network.IP.To4()
	hosts := (1 << (32 - p.prefixBits())) - 2 // minus network and broadcast
	for i := 1; i <= hosts; i++ {
		cand := make(net.IP, 4)
		copy(cand, base)
		ipu := uint32(cand[0])<<24 | uint32(cand[1])<<16 | uint32(cand[2])<<8 | uint32(cand[3])
		ipu += uint32(i)
		cand = net.IPv4(byte(ipu>>24), byte(ipu>>16), byte(ipu>>8), byte(ipu)).To4()
		k := [4]byte(cand)
		if k == p.gateway {
			continue
		}
		if !p.used[k] {
			p.used[k] = true
			return cand, nil
		}
	}
	return nil, errors.New("session: subnet exhausted")
}

func (p *ipPool) release(ip net.IP) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, [4]byte(ip4))
}

func (p *ipPool) prefixBits() int {
	ones, _ := p.network.Mask.Size()
	return ones
}
