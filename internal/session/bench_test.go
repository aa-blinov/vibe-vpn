package session

import (
	"net"
	"testing"

	"time"
)

// BenchmarkSessionThroughput measures packets/s through the full client/server
// stack over loopback UDP with fake TUNs.
func BenchmarkSessionThroughput(b *testing.B) {
	serverKP := testKeypair(b)
	srv := startServer(b, serverKP, testSubnet(b), 1280, nil)
	client, ctun, assigned := newTestClient(b, srv, testKeypair(b), serverKP.Public, ClientConfig{
		Keepalive: 60 * time.Second,
	})
	clientIP := waitAssigned(b, assigned)
	dst := net.ParseIP("8.8.8.8")
	pkt := ipv4(clientIP, dst, make([]byte, 100))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctun.in <- pkt
		select {
		case <-srv.tun.out:
		case <-time.After(5 * time.Second):
			b.Fatal("packet did not traverse")
		}
	}
	_ = client
}
