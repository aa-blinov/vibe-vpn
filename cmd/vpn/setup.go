package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/aa-blinov/vibe-vpn/internal/config"
	"github.com/aa-blinov/vibe-vpn/internal/crypto"
	"github.com/aa-blinov/vibe-vpn/internal/transport/tlsx"
)

// runSetup generates a complete working configuration directory for one role
// and prints the start command. The server setup runs first; its output
// directory (peer.txt, server.crt, server.pub) is the client's -peer input.
//
// Usage: vibe-vpn setup server|client [flags]
func runSetup(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("setup: usage: vibe-vpn setup server|client [flags]")
	}
	switch args[0] {
	case "server":
		return setupServerCmd(args[1:])
	case "client":
		return setupClientCmd(args[1:])
	default:
		return fmt.Errorf("setup: usage: vibe-vpn setup server|client [flags]")
	}
}

func setupServerCmd(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	out := fs.String("out", ".", "output directory")
	domain := fs.String("domain", "", "certificate name / SNI (DNS name or IP)")
	tlsListen := fs.String("tls-listen", "0.0.0.0:443", "TLS listen address")
	listen := fs.String("listen", "0.0.0.0:4433", "UDP listen (unused with TLS)")
	subnet := fs.String("subnet", "10.77.0.0/24", "tunnel subnet")
	iface := fs.String("interface", "vpn0", "server tun interface")
	_ = fs.Parse(args)

	path, err := setupServerDir(*out, *domain, *tlsListen, *listen, *subnet, *iface)
	if err != nil {
		return err
	}
	fmt.Printf("server setup wrote to %s\n", path)
	fmt.Printf("start: sudo ./bin/vibe-vpn server --config %s\n", path)
	fmt.Printf("copy the directory %s (peer.txt, server.crt, server.pub) to the client and use it as -peer\n",
		filepath.Dir(path))
	return nil
}

func setupClientCmd(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	out := fs.String("out", ".", "output directory")
	serverAddr := fs.String("server", "", "server host:port (TLS port)")
	peer := fs.String("peer", "", "peer directory copied from server setup")
	desync := fs.Bool("desync", false, "enable nfqws desync")
	desyncBin := fs.String("nfqws", "/usr/local/bin/nfqws", "path to the nfqws binary")
	_ = fs.Parse(args)

	path, err := setupClientDir(*out, *serverAddr, *peer, *desync, *desyncBin)
	if err != nil {
		return err
	}
	fmt.Printf("client setup wrote to %s\n", path)
	fmt.Printf("start: sudo ./bin/vibe-vpn client --config %s\n", path)
	return nil
}

// setupServerDir generates server keys, a TLS certificate and server.yaml in
// out, and returns the path to server.yaml.
func setupServerDir(out, domain, tlsListen, listen, subnet, iface string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("-domain is required (DNS name or IP of the server)")
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return "", err
	}
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return "", err
	}
	certPEM, keyPEM, err := tlsx.GenerateSelfSigned(domain, 825)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	files := map[string]string{
		"server.key":     crypto.EncodeKey(kp.Private) + "\n",
		"server.pub":     crypto.EncodeKey(kp.Public) + "\n",
		"server.crt":     string(certPEM),
		"server.key.pem": string(keyPEM),
		"peer.txt":       "domain=" + domain + "\npublic_key=" + crypto.EncodeKey(kp.Public) + "\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(abs, name), []byte(data), 0o600); err != nil {
			return "", err
		}
	}
	srv := &config.Server{
		Listen:            listen,
		PrivateKey:        crypto.EncodeKey(kp.Private),
		Interface:         iface,
		Subnet:            subnet,
		OutboundInterface: "eth0",
		NAT:               true,
		MTU:               config.DefaultMTU,
		Keepalive:         10, // fresh NAT state and fewer DPI idle-cuts than the 20s default
		SessionTimeout:    config.DefaultSessionTimeout,
		// Quality default: pad server->client bulk to fixed buckets and emit
		// decoy frames when idle, so the flow resists passive fingerprinting.
		Shaping: config.Shaping{Padding: "bucket", Bucket: 128, DecoyIntervalS: 2},
		Ctl:     filepath.Join(abs, "server.sock"),
		TLS: &config.ServerTLS{
			Listen: tlsListen,
			Cert:   filepath.Join(abs, "server.crt"),
			Key:    filepath.Join(abs, "server.key.pem"),
		},
	}
	path := filepath.Join(abs, "server.yaml")
	if err := writeYAML(path, map[string]interface{}{"server": srv}); err != nil {
		return "", err
	}
	return path, nil
}

// setupClientDir generates client keys and client.yaml in out from the peer
// directory produced by the server setup, and returns the path to client.yaml.
func setupClientDir(out, serverAddr, peer string, desync bool, nfqws string) (string, error) {
	if serverAddr == "" {
		return "", fmt.Errorf("-server is required (host:port)")
	}
	if peer == "" {
		return "", fmt.Errorf("-peer is required (the server setup directory)")
	}
	domain, pubKey, err := readPeer(peer)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return "", err
	}
	kp, err := crypto.GenerateKeypair()
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(abs, "client.key"), []byte(crypto.EncodeKey(kp.Private)+"\n"), 0o600); err != nil {
		return "", err
	}
	cli := &config.Client{
		Server:            serverAddr,
		PrivateKey:        crypto.EncodeKey(kp.Private),
		ServerPublicKey:   pubKey,
		MTU:               config.DefaultMTU,
		Keepalive:         10, // fresh NAT state and fewer DPI idle-cuts than the 20s default
		SessionTimeout:    config.DefaultSessionTimeout,
		SetupRouting:      true,
		RekeyAfterPackets: 1 << 28,
		RekeyAfterSeconds: 180, // fresh keys for DPI, without rekeying every 2 minutes
		// Quality default: HTTPS-shaped packet sizes, cover traffic while idle
		// and light timing jitter to resist passive fingerprinting.
		Shaping: config.Shaping{Padding: "web", DecoyIntervalS: 2, JitterMaxMs: 20},
		Ctl:     filepath.Join(abs, "client.sock"),
		TLS: &config.ClientTLS{
			ServerName: domain,
			CA:         filepath.Join(peer, "server.crt"),
		},
	}
	if desync {
		cli.Desync = &config.Desync{Enabled: true, NFQWS: nfqws, DPIDesync: "split2", SplitPos: "2"}
	}
	path := filepath.Join(abs, "client.yaml")
	if err := writeYAML(path, map[string]interface{}{"client": cli}); err != nil {
		return "", err
	}
	return path, nil
}

func readPeer(dir string) (domain, pubKey string, err error) {
	raw, err := os.ReadFile(filepath.Join(dir, "peer.txt")) // #nosec G304 -- operator-supplied peer directory
	if err != nil {
		return "", "", fmt.Errorf("peer: %w", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "domain="):
			domain = strings.TrimPrefix(line, "domain=")
		case strings.HasPrefix(line, "public_key="):
			pubKey = strings.TrimPrefix(line, "public_key=")
		}
	}
	if domain == "" || pubKey == "" {
		return "", "", fmt.Errorf("peer: peer.txt is incomplete")
	}
	return domain, pubKey, nil
}

func writeYAML(path string, v interface{}) error {
	data, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}
