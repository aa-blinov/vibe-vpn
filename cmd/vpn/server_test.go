package main

import (
	"testing"

	"github.com/aa-blinov/vibe-vpn/internal/crypto"
)

func TestParsePeers(t *testing.T) {
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.EncodeKey(kp.Public)

	peers, err := parsePeers([]string{key})
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(peers))
	}
	if _, ok := peers[key]; !ok {
		t.Fatal("peer not indexed by its key")
	}

	// Invalid key rejected.
	if _, err := parsePeers([]string{"not-a-key"}); err == nil {
		t.Fatal("expected an error for an invalid peer key")
	}
	// Empty list is allowed (open access).
	if _, err := parsePeers(nil); err != nil {
		t.Fatal(err)
	}
}
