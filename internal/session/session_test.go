package session

import (
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/crypto"
	"github.com/aa-blinov/vibe-vpn/internal/framing"
	"github.com/aa-blinov/vibe-vpn/internal/protocol"
	"github.com/aa-blinov/vibe-vpn/internal/transport"
	"github.com/aa-blinov/vibe-vpn/internal/transport/rawtcp"
	"github.com/aa-blinov/vibe-vpn/internal/transport/tlsx"
	"github.com/aa-blinov/vibe-vpn/internal/transport/udp"
)

// ---------------------------------------------------------------- test data

func testKeypair(t testing.TB) *crypto.Keypair {
	t.Helper()
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func testSubnet(t testing.TB) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR("10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func ipv4(src, dst net.IP, payload []byte) []byte {
	pkt := make([]byte, 20+len(payload))
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	copy(pkt[20:], payload)
	return pkt
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// fakeTUN acts as the TUN data plane: the test injects packets through `in`
// (what the interface would read) and collects writes through `out`.
type fakeTUN struct {
	in  chan []byte
	out chan []byte
}

func newFakeTUN() *fakeTUN {
	return &fakeTUN{in: make(chan []byte, 64), out: make(chan []byte, 64)}
}

func (f *fakeTUN) ReadPacket() ([]byte, error) {
	b, ok := <-f.in
	if !ok {
		return nil, errors.New("fake tun closed")
	}
	return b, nil
}

func (f *fakeTUN) WritePacket(b []byte) error {
	select {
	case f.out <- b:
		return nil
	default:
		return errors.New("fake tun buffer full")
	}
}

// ------------------------------------------------------------- server helper

type testServer struct {
	mgr    *Manager
	addr   string
	tun    *fakeTUN
	udpSrv *udp.Server
	cancel context.CancelFunc
}

func startServer(t testing.TB, kp *crypto.Keypair, sub *net.IPNet, mtu int, peers map[string][]byte) *testServer {
	t.Helper()
	mgr, err := NewManager(ServerConfig{
		Keypair:          kp,
		Subnet:           sub,
		MTU:              mtu,
		Keepalive:        time.Second,
		SessionTimeout:   5 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		Peers:            peers,
		Log:              log.New(discard{}, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	tun := newFakeTUN()
	mgr.SetTUN(tun)

	us, err := udp.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	us.SetOnNewPeer(func(_ *net.UDPAddr, tr transport.Transport) bool {
		return mgr.HandleTransport(tr)
	})
	ctx, cancel := context.WithCancel(context.Background())
	go mgr.TunLoop(ctx)
	t.Cleanup(func() {
		cancel()
		us.Close()
	})
	return &testServer{mgr: mgr, addr: us.Addr().String(), tun: tun, udpSrv: us, cancel: cancel}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func (s *testServer) readTUNPacket(t testing.TB) []byte {
	t.Helper()
	select {
	case pkt := <-s.tun.out:
		return pkt
	case <-time.After(5 * time.Second):
		t.Fatal("server never received a packet from the client")
		return nil
	}
}

// ------------------------------------------------------------------- helpers

func newTestClient(t testing.TB, srv *testServer, kp *crypto.Keypair, serverPub []byte, cfg ClientConfig) (*Client, *fakeTUN, chan net.IP) {
	t.Helper()
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.Keepalive == 0 {
		cfg.Keepalive = 500 * time.Millisecond
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 10 * time.Second
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 3 * time.Second
	}
	cfg.Keypair = kp
	cfg.ServerPublic = serverPub
	cfg.Dial = func() (transport.Transport, error) { return udp.Dial(srv.addr) }
	cfg.Log = log.New(discard{}, "", 0)

	client := NewClient(cfg)
	ctun := newFakeTUN()
	assigned := make(chan net.IP, 4)
	ctx, cancel := context.WithCancel(context.Background())
	go client.Run(ctx, ctun, func(ip, _ net.IP, _ int) {
		select {
		case assigned <- ip:
		default:
		}
	})
	t.Cleanup(cancel)
	return client, ctun, assigned
}

func waitAssigned(t testing.TB, ch chan net.IP) net.IP {
	t.Helper()
	select {
	case ip := <-ch:
		return ip
	case <-time.After(8 * time.Second):
		t.Fatal("client was never assigned an address")
		return nil
	}
}

func injectClientPacket(ctun *fakeTUN, src, dst net.IP, payload []byte) {
	ctun.in <- ipv4(src, dst, payload)
}

// ---------------------------------------------------------------- unit tests

// TestKeysRoundtrip verifies that the derived keys agree, support out-of-order
// delivery and reject replays and forgeries.
func TestKeysRoundtrip(t *testing.T) {
	clientKP, serverKP := testKeypair(t), testKeypair(t)
	ch, _ := crypto.NewClientHandshake(clientKP, serverKP.Public)
	sh, _ := crypto.NewServerHandshake(serverKP)

	m1, _, _, _ := ch.Write(nil)
	sh.Read(m1)
	m2, _, _, _ := sh.Write(nil)
	ch.Read(m2)
	m3, c2sC, s2cC, _ := ch.Write(nil)
	_, c2sS, s2cS, _ := sh.Read(m3)

	ck := newKeys(true, c2sC, s2cC)
	sk := newKeys(false, c2sS, s2cS)

	var tag [4]byte
	copy(tag[:], "TAG!")

	// client sends two packets (seq 0 and 1)
	w0, seq0 := ck.seal(tag, protocol.MsgData, []byte("first"), nil)
	w1, seq1 := ck.seal(tag, protocol.MsgData, []byte("second"), nil)
	if seq0 != 0 || seq1 != 1 {
		t.Fatalf("unexpected sequence numbers %d %d", seq0, seq1)
	}

	// server opens them out of order
	p1, err := sk.open(w1)
	if err != nil || string(p1.Payload) != "second" {
		t.Fatalf("open seq1: %v %q", err, p1.Payload)
	}
	p0, err := sk.open(w0)
	if err != nil || string(p0.Payload) != "first" {
		t.Fatalf("open seq0: %v %q", err, p0.Payload)
	}
	if p0.Tag != tag {
		t.Fatalf("tag mismatch: %v", p0.Tag)
	}

	// replay rejected
	if _, err := sk.open(w0); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: got %v", err)
	}

	// forgery rejected
	tampered := append([]byte(nil), w0...)
	tampered[len(tampered)-5] ^= 0xff
	if _, err := sk.open(tampered); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered payload: got %v", err)
	}

	// wrong session tag rejected (decrypt itself succeeds; caller checks tag)
	wrongTag, _ := ck.seal([4]byte{9, 9, 9, 9}, protocol.MsgData, []byte("x"), nil)
	if _, err := sk.open(wrongTag); err != nil {
		t.Fatalf("expected successful decrypt with wrong tag (tag checked by caller): %v", err)
	}
}

// -------------------------------------------------------------- e2e over UDP

func TestClientServerDataFlow(t *testing.T) {
	serverKP := testKeypair(t)
	srv := startServer(t, serverKP, testSubnet(t), 1280, nil)
	ckp := testKeypair(t)
	client, ctun, assigned := newTestClient(t, srv, ckp, serverKP.Public, ClientConfig{})
	clientIP := waitAssigned(t, assigned)
	_ = client

	injectClientPacket(ctun, clientIP, net.ParseIP("8.8.8.8"), []byte("ping"))
	pkt := srv.readTUNPacket(t)
	if !net.IP(pkt[12:16]).Equal(clientIP) || !net.IP(pkt[16:20]).Equal(net.ParseIP("8.8.8.8")) {
		t.Fatalf("server packet has unexpected addresses: src=%v dst=%v", pkt[12:16], pkt[16:20])
	}

	srv.tun.in <- ipv4(net.ParseIP("8.8.8.8"), clientIP, []byte("pong"))
	select {
	case reply := <-ctun.out:
		if !net.IP(reply[16:20]).Equal(clientIP) {
			t.Fatal("client reply has unexpected destination")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never received the reply")
	}

	if client.Stats().PacketsSent.Load() < 1 || client.Stats().PacketsReceived.Load() < 1 {
		t.Fatalf("client stats missing: %s", client.Stats().Dump("client"))
	}
	if client.Stats().Handshakes.Load() != 1 {
		t.Fatalf("expected one handshake, got %d", client.Stats().Handshakes.Load())
	}
}

func TestMultipleClients(t *testing.T) {
	serverKP := testKeypair(t)
	srv := startServer(t, serverKP, testSubnet(t), 1280, nil)

	_, c1tun, a1 := newTestClient(t, srv, testKeypair(t), serverKP.Public, ClientConfig{})
	ip1 := waitAssigned(t, a1)
	_, c2tun, a2 := newTestClient(t, srv, testKeypair(t), serverKP.Public, ClientConfig{})
	ip2 := waitAssigned(t, a2)

	if ip1.Equal(ip2) {
		t.Fatalf("two clients received the same address %v", ip1)
	}

	injectClientPacket(c1tun, ip1, net.ParseIP("8.8.8.8"), []byte("c1"))
	if pkt := srv.readTUNPacket(t); !net.IP(pkt[12:16]).Equal(ip1) {
		t.Fatalf("expected packet from %v, got %v", ip1, pkt[12:16])
	}
	injectClientPacket(c2tun, ip2, net.ParseIP("8.8.8.8"), []byte("c2"))
	if pkt := srv.readTUNPacket(t); !net.IP(pkt[12:16]).Equal(ip2) {
		t.Fatalf("expected packet from %v, got %v", ip2, pkt[12:16])
	}

	srv.tun.in <- ipv4(net.ParseIP("9.9.9.9"), ip2, []byte("for c2"))
	select {
	case r := <-c2tun.out:
		if !net.IP(r[16:20]).Equal(ip2) {
			t.Fatal("wrong client received the reply")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("c2 never got its reply")
	}
}

func TestPeerRejected(t *testing.T) {
	kp := testKeypair(t)
	allowed := testKeypair(t)
	srv := startServer(t, kp, testSubnet(t), 1280, map[string][]byte{
		crypto.EncodeKey(allowed.Public): allowed.Public,
	})

	rejected := testKeypair(t)
	client, _, _ := newTestClient(t, srv, rejected, kp.Public, ClientConfig{})
	waitFor(t, "rejected session to be cleaned up", func() bool {
		return srv.mgr.Active() == 0
	})
	if client.Stats().Handshakes.Load() != 0 {
		t.Fatal("rejected client should never complete a handshake")
	}
}

func TestRekey(t *testing.T) {
	serverKP := testKeypair(t)
	srv := startServer(t, serverKP, testSubnet(t), 1280, nil)
	client, ctun, assigned := newTestClient(t, srv, testKeypair(t), serverKP.Public, ClientConfig{
		RekeyAfterPackets: 4,
	})
	clientIP := waitAssigned(t, assigned)

	// Drive enough traffic to cross the rekey threshold. Data is deliberately
	// paused while the rekey handshake runs, so some of these packets may be
	// dropped; that is expected behaviour.
	for i := 0; i < 12; i++ {
		injectClientPacket(ctun, clientIP, net.ParseIP("8.8.8.8"), []byte{byte(i)})
		time.Sleep(50 * time.Millisecond)
	}

	waitFor(t, "rekey to complete", func() bool {
		return client.Stats().Rekeys.Load() >= 1
	})

	// Drain whatever arrived during the rekey pause.
	for len(srv.tun.out) > 0 {
		<-srv.tun.out
	}

	// Data still flows after the rekey, in both directions.
	injectClientPacket(ctun, clientIP, net.ParseIP("8.8.8.8"), []byte("after-rekey"))
	if pkt := srv.readTUNPacket(t); !net.IP(pkt[16:20]).Equal(net.ParseIP("8.8.8.8")) {
		t.Fatal("packet after rekey did not arrive")
	}
	srv.tun.in <- ipv4(net.ParseIP("8.8.8.8"), clientIP, []byte("reply"))
	select {
	case <-ctun.out:
	case <-time.After(5 * time.Second):
		t.Fatal("reply after rekey did not arrive")
	}
}

func TestReconnect(t *testing.T) {
	serverKP := testKeypair(t)
	srv := startServer(t, serverKP, testSubnet(t), 1280, nil)
	client, ctun, assigned := newTestClient(t, srv, testKeypair(t), serverKP.Public, ClientConfig{})
	clientIP := waitAssigned(t, assigned)

	client.ForceTransportError()
	waitFor(t, "client to reconnect", func() bool {
		return client.Stats().Handshakes.Load() >= 2
	})
	if client.Stats().Reconnects.Load() < 1 {
		t.Fatalf("no reconnect recorded: %s", client.Stats().Dump("client"))
	}
	waitFor(t, "IP to stabilize", func() bool {
		return client.IP() != nil && client.IP().Equal(clientIP)
	})

	injectClientPacket(ctun, clientIP, net.ParseIP("8.8.8.8"), []byte("after-reconnect"))
	if pkt := srv.readTUNPacket(t); !net.IP(pkt[16:20]).Equal(net.ParseIP("8.8.8.8")) {
		t.Fatal("data did not flow after reconnect")
	}
	srv.tun.in <- ipv4(net.ParseIP("8.8.8.8"), clientIP, []byte("reply"))
	select {
	case <-ctun.out:
	case <-time.After(5 * time.Second):
		t.Fatal("reply did not arrive after reconnect")
	}
}

func TestServerSessionTimeout(t *testing.T) {
	serverKP := testKeypair(t)
	srv := startServer(t, serverKP, testSubnet(t), 1280, nil)
	client, _, assigned := newTestClient(t, srv, testKeypair(t), serverKP.Public, ClientConfig{
		Keepalive:         10 * time.Second,
		SessionTimeout:    10 * time.Second,
		RekeyAfterTime:    0,
		RekeyAfterPackets: 0,
	})
	waitAssigned(t, assigned)

	waitFor(t, "server session to expire", func() bool {
		return srv.mgr.Active() == 0
	})
	// The client may legitimately have reconnected after the server closed its
	// session, so only require at least one completed handshake.
	if srv.mgr.Stats().Handshakes.Load() < 1 {
		t.Fatal("expected at least one completed handshake")
	}
	_ = client
}

func TestMalformedPacketDropped(t *testing.T) {
	serverKP := testKeypair(t)
	srv := startServer(t, serverKP, testSubnet(t), 1280, nil)
	_, ctun, assigned := newTestClient(t, srv, testKeypair(t), serverKP.Public, ClientConfig{})
	clientIP := waitAssigned(t, assigned)
	conn, err := net.DialUDP("udp", nil, mustResolve(t, srv.addr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 20; i++ {
		if _, err := conn.Write([]byte{0xff, 0x00, 0xde, 0xad}); err != nil {
			t.Fatal(err)
		}
	}

	time.Sleep(300 * time.Millisecond)
	if srv.mgr.Active() != 1 {
		t.Fatalf("malformed traffic killed the session: active=%d", srv.mgr.Active())
	}

	// The session still works.
	injectClientPacket(ctun, clientIP, net.ParseIP("8.8.8.8"), []byte("alive"))
	srv.readTUNPacket(t)
}

func mustResolve(t *testing.T, addr string) *net.UDPAddr {
	t.Helper()
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	return ua
}

// --------------------------------------------------------------- mem transport

// memTransport wires two endpoints directly (no sockets). It records every
// frame it sends so tests can inspect the wire format.
type memTransport struct {
	recv chan []byte
	done chan struct{}
	peer *memTransport

	mu   sync.Mutex
	sent [][]byte
}

func (m *memTransport) Send(b []byte) error {
	cp := append([]byte(nil), b...)
	m.mu.Lock()
	m.sent = append(m.sent, cp)
	m.mu.Unlock()
	select {
	case m.peer.recv <- cp:
		return nil
	case <-m.done:
		return errors.New("mem: closed")
	}
}

func (m *memTransport) Receive() ([]byte, error) {
	select {
	case b := <-m.recv:
		return b, nil
	case <-m.done:
		return nil, errors.New("mem: closed")
	}
}

func (m *memTransport) Close() error {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
	return nil
}

func (m *memTransport) captured() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte(nil), m.sent...)
}

// startMemServer builds a manager served over a memTransport.
func startMemServer(t testing.TB, kp *crypto.Keypair, cfg ServerConfig) (*Manager, *memTransport, *fakeTUN) {
	t.Helper()
	if cfg.Keypair == nil {
		cfg.Keypair = kp
	}
	if cfg.Subnet == nil {
		cfg.Subnet = testSubnet(t)
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 5 * time.Second
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 2 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = log.New(discard{}, "", 0)
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tun := newFakeTUN()
	mgr.SetTUN(tun)
	sm := &memTransport{recv: make(chan []byte, 1024), done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	go mgr.TunLoop(ctx)
	t.Cleanup(func() { cancel(); mgr.CloseAll() })
	mgr.HandleTransport(sm)
	return mgr, sm, tun
}

// memClient builds a client whose transport is wired to the server's mem
// transport, so wire frames are observable on the client side.
func memClient(t testing.TB, srv *memTransport, cfg ClientConfig) (*Client, *memTransport, *fakeTUN, chan net.IP) {
	t.Helper()
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.Keepalive == 0 {
		cfg.Keepalive = 200 * time.Millisecond
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = 10 * time.Second
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 3 * time.Second
	}
	cm := &memTransport{recv: make(chan []byte, 1024), done: make(chan struct{})}
	srv.peer = cm
	cm.peer = srv
	cfg.Dial = func() (transport.Transport, error) { return cm, nil }
	cfg.Log = log.New(discard{}, "", 0)

	client := NewClient(cfg)
	ctun := newFakeTUN()
	assigned := make(chan net.IP, 4)
	ctx, cancel := context.WithCancel(context.Background())
	go client.Run(ctx, ctun, func(ip, _ net.IP, _ int) {
		select {
		case assigned <- ip:
		default:
		}
	})
	t.Cleanup(cancel)
	return client, cm, ctun, assigned
}

// ---------------------------------------------------------- obfuscation tests

// TestPaddedFramesUniform verifies that in "pad" mode every session frame has
// the same wire size and that no fixed plaintext header is visible.
func TestPaddedFramesUniform(t *testing.T) {
	serverKP := testKeypair(t)
	_, srvMem, srvTUN := startMemServer(t, serverKP, ServerConfig{})
	_, cliMem, ctun, assigned := memClient(t, srvMem, ClientConfig{
		Keypair:      testKeypair(t),
		ServerPublic: serverKP.Public,
		Shaping:      framing.Shaping{Padding: "pad", PadTo: 256},
	})
	clientIP := waitAssigned(t, assigned)

	// Inject a real data packet and wait until it reaches the server TUN.
	injectClientPacket(ctun, clientIP, net.ParseIP("8.8.8.8"), []byte("ping"))
	waitFor(t, "padded data to arrive", func() bool { return len(srvTUN.out) > 0 })

	// Give the client time to emit a few keepalives as well.
	time.Sleep(600 * time.Millisecond)

	frames := cliMem.captured()
	var sessionFrames [][]byte
	for _, f := range frames {
		if len(f) >= 100 { // handshake messages are ~48 bytes; session frames are 256
			sessionFrames = append(sessionFrames, f)
		}
	}
	if len(sessionFrames) < 3 {
		t.Fatalf("expected several session frames, got %d", len(sessionFrames))
	}
	for i, f := range sessionFrames {
		if len(f) != 256 {
			t.Fatalf("session frame %d has wire size %d, want 256", i, len(f))
		}
	}

	// No fixed plaintext header: the leading nonce bytes must vary.
	first := sessionFrames[0][0]
	distinct := 1
	for _, f := range sessionFrames[1:] {
		if f[0] != first {
			distinct++
		}
	}
	if distinct < 2 {
		t.Fatalf("frames look static at the leading byte: %d distinct values", distinct)
	}
}

// TestBucketPaddingFlow checks that "bucket" padding still moves data correctly
// and keeps wire sizes on the requested granularity.
func TestBucketPaddingFlow(t *testing.T) {
	serverKP := testKeypair(t)
	_, srvMem, srvTUN := startMemServer(t, serverKP, ServerConfig{})
	_, cliMem, ctun, assigned := memClient(t, srvMem, ClientConfig{
		Keypair:      testKeypair(t),
		ServerPublic: serverKP.Public,
		Shaping:      framing.Shaping{Padding: "bucket", Bucket: 128},
	})
	clientIP := waitAssigned(t, assigned)

	injectClientPacket(ctun, clientIP, net.ParseIP("8.8.8.8"), []byte("ping"))
	waitFor(t, "bucketed data to arrive", func() bool { return len(srvTUN.out) > 0 })
	time.Sleep(300 * time.Millisecond)

	for _, f := range cliMem.captured() {
		if len(f) >= 100 {
			if len(f)%128 != 0 {
				t.Fatalf("bucket mode: wire size %d not a multiple of 128", len(f))
			}
		}
	}
}

// TestDecoyTraffic verifies that an idle client emits encrypted decoy frames.
func TestDecoyTraffic(t *testing.T) {
	serverKP := testKeypair(t)
	srv := startServer(t, serverKP, testSubnet(t), 1280, nil)
	client, _, assigned := newTestClient(t, srv, testKeypair(t), serverKP.Public, ClientConfig{
		Keepalive:         10 * time.Second,
		SessionTimeout:    10 * time.Second,
		RekeyAfterTime:    0,
		RekeyAfterPackets: 0,
		Shaping:           framing.Shaping{DecoyInterval: 200 * time.Millisecond},
	})
	waitAssigned(t, assigned)

	before := client.Stats().PacketsSent.Load()
	time.Sleep(1200 * time.Millisecond)
	after := client.Stats().PacketsSent.Load()
	if after-before < 3 {
		t.Fatalf("expected decoy traffic, only %d frames sent in 1.2s", after-before)
	}
}

// ------------------------------------------------------------ TLS transport

// TestClientServerOverTLS runs the full session stack over the TLS transport.
func TestClientServerOverTLS(t *testing.T) {
	serverKP := testKeypair(t)

	// Generate a certificate and start the TLS server.
	certPEM, keyPEM, err := tlsx.GenerateSelfSigned("localhost", 30)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(t.TempDir(), "srv.crt")
	keyFile := filepath.Join(t.TempDir(), "srv.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := tlsx.LoadCertPool(certFile)
	if err != nil {
		t.Fatal(err)
	}

	mgr, err := NewManager(ServerConfig{
		Keypair:          serverKP,
		Subnet:           testSubnet(t),
		MTU:              1280,
		Keepalive:        time.Second,
		SessionTimeout:   5 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		Log:              log.New(discard{}, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	srvTUN := newFakeTUN()
	mgr.SetTUN(srvTUN)
	ctx, cancel := context.WithCancel(context.Background())
	go mgr.TunLoop(ctx)
	t.Cleanup(func() { cancel(); mgr.CloseAll() })

	ts, err := tlsx.Listen("127.0.0.1:0", certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	ts.SetOnConn(func(tr transport.Transport) bool { return mgr.HandleTransport(tr) })

	client := NewClient(ClientConfig{
		Dial: func() (transport.Transport, error) {
			return tlsx.Dial(ts.Addr().String(), "localhost", roots, false, "legacy")
		},
		Keypair:          testKeypair(t),
		ServerPublic:     serverKP.Public,
		MTU:              1280,
		Keepalive:        500 * time.Millisecond,
		SessionTimeout:   10 * time.Second,
		HandshakeTimeout: 3 * time.Second,
		Log:              log.New(discard{}, "", 0),
	})
	ctun := newFakeTUN()
	assigned := make(chan net.IP, 4)
	cctx, ccancel := context.WithCancel(context.Background())
	go client.Run(cctx, ctun, func(ip, _ net.IP, _ int) {
		select {
		case assigned <- ip:
		default:
		}
	})
	t.Cleanup(ccancel)
	clientIP := waitAssigned(t, assigned)

	// Data through the TLS tunnel.
	injectClientPacket(ctun, clientIP, net.ParseIP("8.8.8.8"), []byte("ping"))
	waitFor(t, "tls data to arrive", func() bool { return len(srvTUN.out) > 0 })

	srvTUN.in <- ipv4(net.ParseIP("8.8.8.8"), clientIP, []byte("pong"))
	select {
	case <-ctun.out:
	case <-time.After(5 * time.Second):
		t.Fatal("reply over TLS did not arrive")
	}
	if client.Stats().Handshakes.Load() != 1 {
		t.Fatalf("expected one handshake, got %d", client.Stats().Handshakes.Load())
	}
}

// TestClientServerOverRaw runs the full session stack over the raw (obfs4-
// style) TCP transport.
func TestClientServerOverRaw(t *testing.T) {
	serverKP := testKeypair(t)

	mgr, err := NewManager(ServerConfig{
		Keypair:          serverKP,
		Subnet:           testSubnet(t),
		MTU:              1280,
		Keepalive:        time.Second,
		SessionTimeout:   5 * time.Second,
		HandshakeTimeout: 2 * time.Second,
		Log:              log.New(discard{}, "", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	srvTUN := newFakeTUN()
	mgr.SetTUN(srvTUN)
	ctx, cancel := context.WithCancel(context.Background())
	go mgr.TunLoop(ctx)
	t.Cleanup(func() { cancel(); mgr.CloseAll() })

	rs, err := rawtcp.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rs.Close()
	rs.SetOnConn(func(tr transport.Transport) bool { return mgr.HandleTransport(tr) })

	client := NewClient(ClientConfig{
		Dial: func() (transport.Transport, error) {
			return rawtcp.Dial(rs.Addr().String())
		},
		Keypair:          testKeypair(t),
		ServerPublic:     serverKP.Public,
		MTU:              1280,
		Keepalive:        500 * time.Millisecond,
		SessionTimeout:   10 * time.Second,
		HandshakeTimeout: 3 * time.Second,
		Log:              log.New(discard{}, "", 0),
	})
	ctun := newFakeTUN()
	assigned := make(chan net.IP, 4)
	cctx, ccancel := context.WithCancel(context.Background())
	go client.Run(cctx, ctun, func(ip, _ net.IP, _ int) {
		select {
		case assigned <- ip:
		default:
		}
	})
	t.Cleanup(ccancel)
	clientIP := waitAssigned(t, assigned)

	injectClientPacket(ctun, clientIP, net.ParseIP("8.8.8.8"), []byte("ping"))
	waitFor(t, "raw data to arrive", func() bool { return len(srvTUN.out) > 0 })

	srvTUN.in <- ipv4(net.ParseIP("8.8.8.8"), clientIP, []byte("pong"))
	select {
	case <-ctun.out:
	case <-time.After(5 * time.Second):
		t.Fatal("reply over raw transport did not arrive")
	}
	if client.Stats().Handshakes.Load() != 1 {
		t.Fatalf("expected one handshake, got %d", client.Stats().Handshakes.Load())
	}
}
