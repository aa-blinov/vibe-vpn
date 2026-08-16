package crypto

import (
	"bytes"
	"strings"
	"testing"

	noise "github.com/flynn/noise"
)

// exchange runs a full XK handshake between a client and a server handshake
// object and returns the four transport cipher states.
func exchange(t *testing.T, ch, sh *Handshake) (c2sC, s2cC, c2sS, s2cS *noise.CipherState) {
	t.Helper()
	m1, _, _, err := ch.Write(nil)
	if err != nil {
		t.Fatalf("client m1: %v", err)
	}
	if _, _, _, err := sh.Read(m1); err != nil {
		t.Fatalf("server read m1: %v", err)
	}
	m2, _, _, err := sh.Write(nil)
	if err != nil {
		t.Fatalf("server m2: %v", err)
	}
	if _, _, _, err := ch.Read(m2); err != nil {
		t.Fatalf("client read m2: %v", err)
	}
	m3, c2sC, s2cC, err := ch.Write(nil)
	if err != nil {
		t.Fatalf("client m3: %v", err)
	}
	_, c2sS, s2cS, err = sh.Read(m3)
	if err != nil {
		t.Fatalf("server read m3: %v", err)
	}
	if c2sC == nil || s2cC == nil || c2sS == nil || s2cS == nil {
		t.Fatal("handshake did not complete")
	}
	return
}

func TestHandshakeKeysAgree(t *testing.T) {
	clientKP, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverKP, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	ch, err := NewClientHandshake(clientKP, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := NewServerHandshake(serverKP)
	if err != nil {
		t.Fatal(err)
	}
	c2sC, s2cC, c2sS, s2cS := exchange(t, ch, sh)

	// client->server: encrypt with client c2s, decrypt with server c2s.
	msg := []byte("hello client->server")
	ct1, err := c2sC.Encrypt(nil, nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	pt1, err := c2sS.Decrypt(nil, nil, ct1)
	if err != nil {
		t.Fatalf("server could not decrypt client message: %v", err)
	}
	if !bytes.Equal(pt1, msg) {
		t.Fatal("client->server payload mismatch")
	}

	// server->client: encrypt with server s2c, decrypt with client s2c.
	msg2 := []byte("hello server->client")
	ct2, err := s2cS.Encrypt(nil, nil, msg2)
	if err != nil {
		t.Fatal(err)
	}
	pt2, err := s2cC.Decrypt(nil, nil, ct2)
	if err != nil {
		t.Fatalf("client could not decrypt server message: %v", err)
	}
	if !bytes.Equal(pt2, msg2) {
		t.Fatal("server->client payload mismatch")
	}

	// Cross-direction must NOT decrypt.
	if _, err := s2cC.Decrypt(nil, nil, ct1); err == nil {
		t.Fatal("client accepted a message encrypted in the wrong direction")
	}
}

func TestServerAuthentication(t *testing.T) {
	clientKP, _ := GenerateKeypair()
	serverKP, _ := GenerateKeypair()
	evilKP, _ := GenerateKeypair()

	// Client pins the real server key, but a MITM with a different key answers.
	ch, err := NewClientHandshake(clientKP, serverKP.Public)
	if err != nil {
		t.Fatal(err)
	}
	evil, err := NewServerHandshake(evilKP)
	if err != nil {
		t.Fatal(err)
	}
	m1, _, _, err := ch.Write(nil)
	if err != nil {
		t.Fatal(err)
	}
	// The client's first message is already bound to the pinned key, so the
	// attacker cannot even process it; if it could, the client would reject m2.
	if _, _, _, err := evil.Read(m1); err == nil {
		m2, _, _, err := evil.Write(nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := ch.Read(m2); err == nil {
			t.Fatal("client accepted a handshake from a server it did not pin")
		}
	}
}

func TestKeypairFromPrivate(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := KeypairFromPrivate(kp.Private)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kp.Public, kp2.Public) {
		t.Fatal("derived public key does not match")
	}
	enc := EncodeKey(kp.Private)
	dec, err := DecodeKey(enc)
	if err != nil || !bytes.Equal(dec, kp.Private) {
		t.Fatalf("base64 roundtrip failed: %v", err)
	}
	if _, err := DecodeKey("tooshort"); err == nil {
		t.Fatal("decoding a short key should fail")
	}
}

func TestKeyEncryptionRoundtrip(t *testing.T) {
	kp, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := EncryptKey(kp.Private, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(blob, "v1:") {
		t.Fatalf("blob missing prefix: %q", blob)
	}
	got, err := DecryptKey(blob, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, kp.Private) {
		t.Fatal("decrypted key does not match")
	}

	// Wrong passphrase must fail.
	if _, err := DecryptKey(blob, "wrong"); err == nil {
		t.Fatal("expected failure with a wrong passphrase")
	}
	// Malformed blobs must fail.
	if _, err := DecryptKey("not-a-blob", "x"); err == nil {
		t.Fatal("expected failure for a malformed blob")
	}
	if _, err := DecryptKey("v1:abc", "x"); err == nil {
		t.Fatal("expected failure for a truncated blob")
	}
	// Empty passphrase rejected at encrypt time.
	if _, err := EncryptKey(kp.Private, ""); err == nil {
		t.Fatal("expected failure for an empty passphrase")
	}
}
