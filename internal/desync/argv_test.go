package desync

import (
	"reflect"
	"testing"
)

func TestBuildNFQWSArgs(t *testing.T) {
	got := buildNFQWSArgs(8443, 0, "split2", "2", "")
	want := []string{
		"--filter-tcp=8443",
		"--dpi-desync=split2",
		"--qnum=0",
		"--dpi-desync-split-pos=2",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("split2 args:\n got %v\nwant %v", got, want)
	}

	got = buildNFQWSArgs(443, 1, "fake", "", "badseq")
	want = []string{
		"--filter-tcp=443",
		"--dpi-desync=fake",
		"--qnum=1",
		"--dpi-desync-fooling=badseq",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fake args:\n got %v\nwant %v", got, want)
	}
}

func TestStartDisabled(t *testing.T) {
	m, err := Start(Config{}, 8443, nil)
	if err != nil || m != nil {
		t.Fatalf("disabled desync must be a no-op, got %v, %v", m, err)
	}
}

func TestStartRequiresBinary(t *testing.T) {
	if _, err := Start(Config{Enabled: true}, 8443, nil); err == nil {
		t.Fatal("expected an error when the nfqws path is missing")
	}
}
