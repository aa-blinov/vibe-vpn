// Package config loads and validates the YAML configuration for the vpn
// client and server.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// Defaults shared by both roles.
const (
	DefaultMTU              = 1280
	DefaultKeepalive        = 20  // seconds
	DefaultSessionTimeout   = 300 // seconds
	DefaultHandshakeTimeout = 10  // seconds
	DefaultStatsInterval    = 15  // seconds
	// DefaultRekeySeconds matches WireGuard's short-lived session cadence:
	// transport keys are rotated roughly every two minutes.
	DefaultRekeySeconds = 120
)

// Client is the client side configuration.
type Client struct {
	Server              string     `yaml:"server"`
	Transport           string     `yaml:"transport,omitempty"` // udp | tls | raw
	PrivateKey          string     `yaml:"private_key"`
	PrivateKeyEncrypted string     `yaml:"private_key_encrypted,omitempty"` // passphrase-protected key blob
	ServerPublicKey     string     `yaml:"server_public_key"`
	MTU                 int        `yaml:"mtu"`
	ClientIP            string     `yaml:"client_ip,omitempty"`
	Keepalive           int        `yaml:"keepalive_interval,omitempty"`
	SessionTimeout      int        `yaml:"session_timeout,omitempty"`
	RekeyAfterPackets   uint64     `yaml:"rekey_after_packets,omitempty"`
	RekeyAfterSeconds   int        `yaml:"rekey_after_seconds,omitempty"`
	SetupRouting        bool       `yaml:"setup_routing"`
	Metrics             string     `yaml:"metrics,omitempty"` // loopback address for /metrics
	Ctl                 string     `yaml:"ctl,omitempty"`     // unix socket path for `vibe-vpn status`
	TLS                 *ClientTLS `yaml:"tls,omitempty"`
	Desync              *Desync    `yaml:"desync,omitempty"`
	Shaping             Shaping    `yaml:"shaping,omitempty"`
	Debug               string     `yaml:"debug,omitempty"`
	StatsInterval       int        `yaml:"stats_interval,omitempty"`
}

// Desync configures the nfqws-based DPI desynchronization of the tunnel's own
// TCP flow (zapret). Requires root and the nfqws binary.
type Desync struct {
	Enabled   bool   `yaml:"enabled"`
	NFQWS     string `yaml:"nfqws"`
	Queue     int    `yaml:"queue,omitempty"`
	DPIDesync string `yaml:"dpi_desync,omitempty"`
	SplitPos  string `yaml:"split_pos,omitempty"`
	Fooling   string `yaml:"fooling,omitempty"`
}

// ApplyDefaults fills in zero fields with sensible defaults.
func (d *Desync) ApplyDefaults() {
	if d.Queue == 0 {
		d.Queue = 0
	}
	if d.DPIDesync == "" {
		d.DPIDesync = "split2"
	}
	if d.SplitPos == "" {
		d.SplitPos = "2"
	}
}

// ClientTLS configures the TLS transport on the client.
type ClientTLS struct {
	ServerName  string `yaml:"server_name,omitempty"` // SNI / certificate name
	CA          string `yaml:"ca,omitempty"`          // PEM bundle of trusted server cert
	Insecure    bool   `yaml:"insecure,omitempty"`    // skip certificate verification
	Fingerprint string `yaml:"fingerprint,omitempty"` // chrome | firefox | legacy (default: browser mode)
}

// Server is the server side configuration.
type Server struct {
	Listen              string     `yaml:"listen"`
	Transport           string     `yaml:"transport,omitempty"` // udp | tls | raw
	PrivateKey          string     `yaml:"private_key"`
	PrivateKeyEncrypted string     `yaml:"private_key_encrypted,omitempty"` // passphrase-protected key blob
	Interface           string     `yaml:"interface"`
	Subnet              string     `yaml:"subnet"`
	OutboundInterface   string     `yaml:"outbound_interface,omitempty"`
	NAT                 bool       `yaml:"nat"`
	Peers               []string   `yaml:"peers,omitempty"`
	MTU                 int        `yaml:"mtu"`
	Keepalive           int        `yaml:"keepalive_interval,omitempty"`
	SessionTimeout      int        `yaml:"session_timeout,omitempty"`
	Metrics             string     `yaml:"metrics,omitempty"` // loopback address for /metrics
	Ctl                 string     `yaml:"ctl,omitempty"`     // unix socket path for `vibe-vpn status`
	TLS                 *ServerTLS `yaml:"tls,omitempty"`
	Shaping             Shaping    `yaml:"shaping,omitempty"`
	Debug               string     `yaml:"debug,omitempty"`
	StatsInterval       int        `yaml:"stats_interval,omitempty"`
}

// ServerTLS configures the TLS transport on the server.
type ServerTLS struct {
	Listen string `yaml:"listen,omitempty"`
	Cert   string `yaml:"cert,omitempty"`
	Key    string `yaml:"key,omitempty"`
}

// Shaping configures the wire-level traffic-shaping policy (padding, jitter,
// decoy traffic). See internal/framing for the semantics of each mode.
type Shaping struct {
	Padding        string `yaml:"padding,omitempty"` // none | pad | bucket | random
	PadTo          int    `yaml:"pad_to,omitempty"`
	Bucket         int    `yaml:"bucket,omitempty"`
	RandMax        int    `yaml:"rand_max,omitempty"`
	DecoyIntervalS int    `yaml:"decoy_interval_s,omitempty"`
	JitterMaxMs    int    `yaml:"jitter_max_ms,omitempty"`
}

// File is the top-level configuration document.
type File struct {
	Client *Client `yaml:"client"`
	Server *Server `yaml:"server"`
}

// Load reads a YAML file, unmarshals it and fills in defaults.
func Load(path string) (*File, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path comes from the operator
	if err != nil {
		return nil, err
	}
	f := &File{}
	if err := yaml.Unmarshal(raw, f); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if f.Client == nil && f.Server == nil {
		return nil, errors.New("config: file must contain a client or server section")
	}
	if f.Client != nil {
		f.Client.ApplyDefaults()
	}
	if f.Server != nil {
		f.Server.ApplyDefaults()
	}
	return f, nil
}

// ApplyDefaults fills in zero fields with sensible defaults.
func (c *Client) ApplyDefaults() {
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.Keepalive == 0 {
		c.Keepalive = DefaultKeepalive
	}
	if c.SessionTimeout == 0 {
		c.SessionTimeout = DefaultSessionTimeout
	}
	if c.RekeyAfterPackets == 0 {
		c.RekeyAfterPackets = 1 << 28
	}
	if c.RekeyAfterSeconds == 0 {
		c.RekeyAfterSeconds = DefaultRekeySeconds
	}
	if c.StatsInterval == 0 {
		c.StatsInterval = DefaultStatsInterval
	}
	if c.Desync != nil {
		c.Desync.ApplyDefaults()
	}
}

// ApplyDefaults fills in zero fields with sensible defaults.
func (s *Server) ApplyDefaults() {
	if s.Listen == "" {
		s.Listen = "0.0.0.0:4433"
	}
	if s.Interface == "" {
		s.Interface = "vpn0"
	}
	if s.Subnet == "" {
		s.Subnet = "10.77.0.0/24"
	}
	if s.OutboundInterface == "" {
		s.OutboundInterface = "eth0"
	}
	if s.MTU == 0 {
		s.MTU = DefaultMTU
	}
	if s.Keepalive == 0 {
		s.Keepalive = DefaultKeepalive
	}
	if s.SessionTimeout == 0 {
		s.SessionTimeout = DefaultSessionTimeout
	}
	if s.StatsInterval == 0 {
		s.StatsInterval = DefaultStatsInterval
	}
}

// Validate checks the client configuration for obvious problems.
func (c *Client) Validate() error {
	if c.Server == "" {
		return errors.New("client: server address is required")
	}
	if _, _, err := net.SplitHostPort(c.Server); err != nil {
		return fmt.Errorf("client: server %q: %w", c.Server, err)
	}
	if (c.PrivateKey == "") == (c.PrivateKeyEncrypted == "") {
		return errors.New("client: exactly one of private_key or private_key_encrypted is required")
	}
	if c.ServerPublicKey == "" {
		return errors.New("client: server_public_key is required")
	}
	if c.MTU < 576 || c.MTU > 65535 {
		return fmt.Errorf("client: mtu %d out of range [576, 65535]", c.MTU)
	}
	if c.SessionTimeout > 0 && c.Keepalive >= c.SessionTimeout {
		return fmt.Errorf("client: keepalive_interval (%ds) must be smaller than session_timeout (%ds)",
			c.Keepalive, c.SessionTimeout)
	}
	if c.TLS != nil {
		if c.TLS.CA == "" && !c.TLS.Insecure {
			return errors.New("client: tls requires ca (path to the server certificate) or insecure=true")
		}
		if c.TLS.CA != "" {
			if st, err := os.Stat(c.TLS.CA); err != nil || st.IsDir() {
				return fmt.Errorf("client: tls.ca %q: %w", c.TLS.CA, err)
			}
		}
	}
	if err := validateTransport(c.Transport, c.TLS != nil); err != nil {
		return err
	}
	if err := validateMetrics(c.Metrics); err != nil {
		return err
	}
	if err := c.Shaping.Validate(); err != nil {
		return err
	}
	return nil
}

// Validate checks the server configuration for obvious problems.
func (s *Server) Validate() error {
	if (s.PrivateKey == "") == (s.PrivateKeyEncrypted == "") {
		return errors.New("server: exactly one of private_key or private_key_encrypted is required")
	}
	if _, _, err := net.ParseCIDR(s.Subnet); err != nil {
		return fmt.Errorf("server: subnet %q: %w", s.Subnet, err)
	}
	if s.MTU < 576 || s.MTU > 65535 {
		return fmt.Errorf("server: mtu %d out of range [576, 65535]", s.MTU)
	}
	if s.SessionTimeout > 0 && s.Keepalive >= s.SessionTimeout {
		return fmt.Errorf("server: keepalive_interval (%ds) must be smaller than session_timeout (%ds)",
			s.Keepalive, s.SessionTimeout)
	}
	if s.TLS != nil {
		if s.TLS.Listen == "" || s.TLS.Cert == "" || s.TLS.Key == "" {
			return errors.New("server: tls requires listen, cert and key")
		}
		if st, err := os.Stat(s.TLS.Cert); err != nil || st.IsDir() {
			return fmt.Errorf("server: tls.cert %q: %w", s.TLS.Cert, err)
		}
		if st, err := os.Stat(s.TLS.Key); err != nil || st.IsDir() {
			return fmt.Errorf("server: tls.key %q: %w", s.TLS.Key, err)
		}
	}
	if err := validateTransport(s.Transport, s.TLS != nil); err != nil {
		return err
	}
	if err := validateMetrics(s.Metrics); err != nil {
		return err
	}
	if err := s.Shaping.Validate(); err != nil {
		return err
	}
	return nil
}

// validateMetrics requires the metrics endpoint to be on a loopback address so
// it is never exposed unintentionally.
func validateMetrics(addr string) error {
	if addr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("metrics: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("metrics: address must be a loopback IP (e.g. 127.0.0.1:9090), got %q", addr)
	}
	return nil
}

// validateTransport checks the transport selector. An empty value falls back
// to tls when a tls section is present, otherwise udp.
func validateTransport(sel string, tlsPresent bool) error {
	switch sel {
	case "", "udp", "tls", "raw":
	default:
		return fmt.Errorf("transport: unknown %q (use udp|tls|raw)", sel)
	}
	if sel == "tls" && !tlsPresent {
		return errors.New("transport: tls requires a tls section")
	}
	return nil
}

// Validate checks the shaping policy.
func (s *Shaping) Validate() error {
	switch s.Padding {
	case "", "none", "pad", "bucket", "random", "web":
	default:
		return fmt.Errorf("shaping: unknown padding %q (use none|pad|bucket|random|web)", s.Padding)
	}
	if s.Padding == "pad" && s.PadTo <= 0 {
		return errors.New("shaping: pad mode requires pad_to > 0")
	}
	if s.Padding == "bucket" && s.Bucket <= 0 {
		return errors.New("shaping: bucket mode requires bucket > 0")
	}
	if s.Padding == "random" && s.RandMax < 0 {
		return errors.New("shaping: rand_max must be >= 0")
	}
	return nil
}
