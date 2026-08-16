// Package metrics exposes tunnel and runtime statistics in Prometheus text
// format on a local HTTP endpoint (/metrics). The endpoint is intended to be
// bound to a loopback address and scraped by a monitoring agent.
package metrics

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"sort"
	"time"
)

// Snapshot returns the current metrics as name -> value pairs. Names should
// already include the "vibe_" prefix and a gauge/counter suffix.
type Snapshot func() map[string]float64

// Server is a metrics HTTP endpoint.
type Server struct {
	ln net.Listener
	s  *http.Server
}

// Serve starts a metrics endpoint on addr (e.g. "127.0.0.1:9090"). It returns
// nil when addr is empty.
func Serve(addr string, snap Snapshot) (*Server, error) {
	if addr == "" {
		return nil, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		write(w, snap)
	})
	s := &Server{ln: ln, s: &http.Server{Handler: mux}}
	go s.s.Serve(ln)
	return s, nil
}

// Addr returns the bound address.
func (s *Server) Addr() string {
	if s == nil || s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Close stops the endpoint.
func (s *Server) Close() error {
	if s == nil || s.s == nil {
		return nil
	}
	return s.s.Close()
}

func write(w http.ResponseWriter, snap Snapshot) {
	metrics := snap()
	keys := make([]string, 0, len(metrics))
	for k := range metrics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s %g\n", k, metrics[k])
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Fprintf(w, "go_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "go_memstats_alloc_bytes %d\n", m.Alloc)
	fmt.Fprintf(w, "go_memstats_heap_objects %d\n", m.HeapObjects)
	fmt.Fprintf(w, "vibe_uptime_seconds %g\n", time.Since(start).Seconds())
}

var start = time.Now()
