package session

import (
	"fmt"
	"sync/atomic"
	"time"
)

// Stats holds per-session traffic and protocol counters. All fields are safe
// for concurrent reads; they are mutated from the session run loop.
type Stats struct {
	PacketsSent     atomic.Uint64
	PacketsReceived atomic.Uint64
	PacketsDropped  atomic.Uint64 // malformed / replay / oversized / unroutable
	BytesSent       atomic.Uint64
	BytesReceived   atomic.Uint64

	Handshakes     atomic.Uint64
	HandshakeNanos atomic.Int64 // last successful handshake duration
	Reconnects     atomic.Uint64
	Rekeys         atomic.Uint64
	RekeyNanos     atomic.Int64

	LastRTTNanos atomic.Int64  // last keepalive round-trip, 0 until measured
	LossTotal    atomic.Uint64 // cumulative packets detected as lost

	// rttBuckets stores cumulative RTT samples for metrics histograms.
	rttBuckets [rttBucketCount]atomic.Uint64

	SizeLE64   atomic.Uint64
	SizeLE256  atomic.Uint64
	SizeLE1024 atomic.Uint64
	SizeLE1500 atomic.Uint64
	SizeGT1500 atomic.Uint64
}

func (s *Stats) recordSize(n int) {
	switch {
	case n <= 64:
		s.SizeLE64.Add(1)
	case n <= 256:
		s.SizeLE256.Add(1)
	case n <= 1024:
		s.SizeLE1024.Add(1)
	case n <= 1500:
		s.SizeLE1500.Add(1)
	default:
		s.SizeGT1500.Add(1)
	}
}

// RTT returns the latest measured round-trip time (0 if unknown).
func (s *Stats) RTT() time.Duration {
	return time.Duration(s.LastRTTNanos.Load())
}

// HandshakeDuration returns the duration of the last handshake (0 if unknown).
func (s *Stats) HandshakeDuration() time.Duration {
	return time.Duration(s.HandshakeNanos.Load())
}

// rttBucketCount is the number of RTT histogram buckets.
const rttBucketCount = 9

// rttThresholdsMS are the upper bounds of the RTT histogram buckets.
var rttThresholdsMS = [rttBucketCount]float64{10, 25, 50, 100, 250, 500, 1000, 2000, 5000}

// RecordRTT adds a measured round-trip time to the histogram.
func (s *Stats) RecordRTT(d time.Duration) {
	ms := float64(d) / float64(time.Millisecond)
	for i, b := range rttThresholdsMS {
		if ms <= b {
			s.rttBuckets[i].Add(1)
		}
	}
	s.LastRTTNanos.Store(int64(d))
}

// RTTThresholds returns a copy of the histogram bucket upper bounds (ms).
func RTTThresholds() []float64 {
	out := make([]float64, len(rttThresholdsMS))
	copy(out, rttThresholdsMS[:])
	return out
}

// RTTBuckets returns the cumulative bucket counts (le values are
// rttThresholdsMS).
func (s *Stats) RTTBuckets() []uint64 {
	out := make([]uint64, len(rttThresholdsMS))
	for i := range out {
		out[i] = s.rttBuckets[i].Load()
	}
	return out
}

// Dump renders the statistics as a single log line.
func (s *Stats) Dump(role string) string {
	rtt := s.RTT()
	rttStr := "n/a"
	if rtt > 0 {
		rttStr = rtt.Round(time.Microsecond).String()
	}
	return fmt.Sprintf(
		"role=%s tx_pkts=%d tx_bytes=%d rx_pkts=%d rx_bytes=%d dropped=%d "+
			"handshakes=%d handshake=%s reconnects=%d rekeys=%d rtt=%s loss=%d "+
			"sizes(<=64/256/1k/1500/gt)=%d/%d/%d/%d/%d",
		role,
		s.PacketsSent.Load(), s.BytesSent.Load(),
		s.PacketsReceived.Load(), s.BytesReceived.Load(),
		s.PacketsDropped.Load(),
		s.Handshakes.Load(), s.HandshakeDuration().Round(time.Microsecond),
		s.Reconnects.Load(), s.Rekeys.Load(), rttStr, s.LossTotal.Load(),
		s.SizeLE64.Load(), s.SizeLE256.Load(), s.SizeLE1024.Load(), s.SizeLE1500.Load(), s.SizeGT1500.Load(),
	)
}
