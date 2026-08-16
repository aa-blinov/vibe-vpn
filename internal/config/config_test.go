package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadClient(t *testing.T) {
	p := writeTemp(t, `client:
  server: 1.2.3.4:443
  private_key: key
  server_public_key: pub
`)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.Client == nil || f.Server != nil {
		t.Fatalf("expected only a client section")
	}
	c := f.Client
	if c.MTU != DefaultMTU {
		t.Fatalf("default mtu = %d, want %d", c.MTU, DefaultMTU)
	}
	if c.Keepalive != DefaultKeepalive || c.SessionTimeout != DefaultSessionTimeout {
		t.Fatalf("defaults not applied: keepalive=%d timeout=%d", c.Keepalive, c.SessionTimeout)
	}
	if c.RekeyAfterPackets == 0 || c.RekeyAfterSeconds == 0 {
		t.Fatal("rekey defaults not applied")
	}
}

func TestLoadServer(t *testing.T) {
	p := writeTemp(t, `server:
  private_key: key
`)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	s := f.Server
	if s.Listen != "0.0.0.0:4433" {
		t.Fatalf("default listen = %q", s.Listen)
	}
	if s.Subnet != "10.77.0.0/24" {
		t.Fatalf("default subnet = %q", s.Subnet)
	}
	if s.Interface != "vpn0" {
		t.Fatalf("default interface = %q", s.Interface)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load("/nonexistent/file.yaml"); err == nil {
		t.Fatal("expected error for a missing file")
	}
	p := writeTemp(t, `not a valid yaml: [`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for invalid yaml")
	}
	p = writeTemp(t, `foo: bar`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error when no client/server section")
	}
}

func TestClientValidate(t *testing.T) {
	base := &Client{Server: "h:443", PrivateKey: "k", ServerPublicKey: "p", MTU: DefaultMTU}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid client rejected: %v", err)
	}
	cases := []*Client{
		{Server: "", PrivateKey: "k", ServerPublicKey: "p"},
		{Server: "no-port", PrivateKey: "k", ServerPublicKey: "p"},
		{Server: "h:443", PrivateKey: "", ServerPublicKey: "p"},
		{Server: "h:443", PrivateKey: "k", ServerPublicKey: ""},
		{Server: "h:443", PrivateKey: "k", ServerPublicKey: "p", MTU: 100},
		{Server: "h:443", PrivateKey: "k", ServerPublicKey: "p", Keepalive: 10, SessionTimeout: 5},
		{Server: "h:443", PrivateKey: "k", ServerPublicKey: "p", TLS: &ClientTLS{}},
		{Server: "h:443", PrivateKey: "k", ServerPublicKey: "p", TLS: &ClientTLS{CA: "/missing/ca.pem"}},
		{Server: "h:443", PrivateKey: "k", ServerPublicKey: "p", Shaping: Shaping{Padding: "bogus"}},
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Fatalf("case %d should fail validation", i)
		}
	}
}

func TestServerValidate(t *testing.T) {
	base := &Server{PrivateKey: "k", Subnet: "10.77.0.0/24", MTU: DefaultMTU}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid server rejected: %v", err)
	}
	cases := []*Server{
		{PrivateKey: ""},
		{PrivateKey: "k", Subnet: "not-a-subnet"},
		{PrivateKey: "k", Subnet: "10.77.0.0/24", MTU: 100},
		{PrivateKey: "k", Subnet: "10.77.0.0/24", TLS: &ServerTLS{}},
	}
	for i, s := range cases {
		if err := s.Validate(); err == nil {
			t.Fatalf("case %d should fail validation", i)
		}
	}
}

func TestValidateTransport(t *testing.T) {
	for _, sel := range []string{"", "udp", "tls", "raw"} {
		if err := validateTransport(sel, true); err != nil {
			t.Fatalf("%q: %v", sel, err)
		}
	}
	if err := validateTransport("quic", true); err == nil {
		t.Fatal("unknown transport should fail")
	}
	if err := validateTransport("tls", false); err == nil {
		t.Fatal("tls transport without a tls section should fail")
	}
}

func TestValidateMetrics(t *testing.T) {
	if err := validateMetrics(""); err != nil {
		t.Fatalf("empty address must be allowed: %v", err)
	}
	for _, ok := range []string{"127.0.0.1:9090", "[::1]:9090"} {
		if err := validateMetrics(ok); err != nil {
			t.Fatalf("%q should be allowed: %v", ok, err)
		}
	}
	for _, bad := range []string{"0.0.0.0:9090", "192.168.1.5:9090", "no-port", "localhost:9090"} {
		if err := validateMetrics(bad); err == nil {
			t.Fatalf("%q should be rejected", bad)
		}
	}
}
