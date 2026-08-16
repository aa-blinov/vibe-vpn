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

	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ctun.in <- pkt
		select {
		case <-srv.tun.out:
		case <-timeout.C:
			b.Fatal("packet did not traverse")
		}
	}
	_ = client
}

// BenchmarkSessionPipelined sends packets back-to-back without waiting for
// each to traverse; the producer is throttled by the pipeline's backpressure,
// so the measured time reflects sustained tunnel throughput.
func BenchmarkSessionPipelined(b *testing.B) {
	serverKP := testKeypair(b)
	srv := startServer(b, serverKP, testSubnet(b), 1280, nil)
	client, ctun, assigned := newTestClient(b, srv, testKeypair(b), serverKP.Public, ClientConfig{
		Keepalive: 60 * time.Second,
	})
	clientIP := waitAssigned(b, assigned)
	dst := net.ParseIP("8.8.8.8")
	pkt := ipv4(clientIP, dst, make([]byte, 100))

	// Consumer drains the server-side fake TUN in the background.
	go func() {
		for range srv.tun.out {
		}
	}()

	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	for i := 0; i < b.N; i++ {
		ctun.in <- pkt
	}
	_ = client
}
