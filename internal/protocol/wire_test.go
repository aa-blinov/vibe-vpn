package protocol

import "testing"

func TestTypeConstants(t *testing.T) {
	types := []byte{MsgHandshake1, MsgHandshake2, MsgHandshake3, MsgData,
		MsgKeepalive, MsgClose, MsgRekey1, MsgRekey2, MsgRekey3, MsgAssign, MsgDecoy}
	seen := make(map[byte]bool)
	for _, tp := range types {
		if tp == 0 || seen[tp] {
			t.Fatalf("message types must be non-zero and unique, got 0x%x", tp)
		}
		seen[tp] = true
		if TypeName(tp) == "" {
			t.Fatalf("TypeName(%d) is empty", tp)
		}
	}
}

func TestIsHandshake(t *testing.T) {
	for _, tp := range []byte{MsgHandshake1, MsgHandshake2, MsgHandshake3} {
		if !IsHandshake(tp) {
			t.Fatalf("type %d should be a handshake message", tp)
		}
	}
	for _, tp := range []byte{MsgData, MsgKeepalive, MsgDecoy, MsgAssign, MsgRekey1} {
		if IsHandshake(tp) {
			t.Fatalf("type %d should not be a raw handshake message", tp)
		}
	}
}

func TestIsRekey(t *testing.T) {
	for _, tp := range []byte{MsgRekey1, MsgRekey2, MsgRekey3} {
		if !IsRekey(tp) {
			t.Fatalf("type %d should be a rekey message", tp)
		}
	}
	if IsRekey(MsgData) {
		t.Fatal("data should not be a rekey message")
	}
}
