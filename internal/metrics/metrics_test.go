package metrics

import (
	"net/http"
	"strings"
	"testing"
)

func TestServeMetrics(t *testing.T) {
	s, err := Serve("127.0.0.1:0", func() map[string]float64 {
		return map[string]float64{"vibe_sessions": 3, "vibe_dropped_total": 7}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Addr() == "" {
		t.Fatal("no address bound")
	}

	resp, err := http.Get("http://" + s.Addr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	for _, want := range []string{
		"vibe_sessions 3",
		"vibe_dropped_total 7",
		"go_goroutines",
		"vibe_uptime_seconds",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("metrics body missing %q:\n%s", want, body)
		}
	}
}

func TestServeEmpty(t *testing.T) {
	s, err := Serve("", nil)
	if err != nil || s != nil {
		t.Fatalf("empty address must be a no-op, got %v, %v", s, err)
	}
}

func TestServeBadAddress(t *testing.T) {
	if _, err := Serve("256.256.256.256:1", nil); err == nil {
		t.Fatal("expected an error for an invalid address")
	}
}
