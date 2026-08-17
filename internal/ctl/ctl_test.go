package ctl

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestServeQuery(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "ctl.sock")
	stopped := make(chan struct{}, 1)
	s, err := Serve(sock, func() string { return "status: ok\n" }, func() { stopped <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	got, err := Query(sock)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "status: ok") {
		t.Fatalf("unexpected status %q", got)
	}

	// The "stop" command invokes the stop handler.
	if err := Stop(sock); err != nil {
		t.Fatal(err)
	}
	select {
	case <-stopped:
	default:
		t.Fatal("stop handler was not invoked")
	}

	// Querying a missing socket fails.
	if _, err := Query(filepath.Join(t.TempDir(), "missing.sock")); err == nil {
		t.Fatal("expected an error for a missing socket")
	}

	// Re-serve on the same path (stale socket cleanup) works.
	s2, err := Serve(sock, func() string { return "second\n" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}
