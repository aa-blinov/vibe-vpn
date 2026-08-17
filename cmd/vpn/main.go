// Command vibe-vpn is the CLI for the research VPN prototype.
//
// Usage:
//
//	vibe-vpn server --config server.yaml
//	vibe-vpn client --config client.yaml
//	vibe-vpn keygen
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/config"
	"github.com/aa-blinov/vibe-vpn/internal/framing"
)

// shaping converts the YAML shaping section into the framing policy.
func shaping(c config.Shaping) framing.Shaping {
	return framing.Shaping{
		Padding:       c.Padding,
		PadTo:         c.PadTo,
		Bucket:        c.Bucket,
		RandMax:       c.RandMax,
		DecoyInterval: time.Duration(c.DecoyIntervalS) * time.Second,
		Jitter:        time.Duration(c.JitterMaxMs) * time.Millisecond,
	}
}

// Build metadata. All three are set via -ldflags at build time. Defaults
// match an unstripped `go build` so the binary still works without flags.
var (
	version   = "0.1.0"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(os.Args[2:])
	case "client":
		err = runClient(os.Args[2:])
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "certgen":
		err = runCertgen(os.Args[2:])
	case "setup":
		err = runSetup(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "quick":
		err = runQuick(os.Args[2:])
	case "version", "--version", "-V":
		fmt.Printf("vibe-vpn %s (commit %s, built %s)\n", version, commit, buildTime)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vibe-vpn - research VPN prototype

Usage:
  vibe-vpn server --config server.yaml [flags]   run the server
  vibe-vpn client --config client.yaml [flags]   run the client
  vibe-vpn keygen                                generate an X25519 keypair
  vibe-vpn setup server -out dir -domain vpn.example.com [--tls-listen 0.0.0.0:443] [--raw-listen 0.0.0.0:4444]
  vibe-vpn setup client -out dir -server host:443 -peer <server-dir> [--raw-server host:4444]
                                            generate keys, certificate and configs
  ./vibe-vpn.sh server|client                interactive setup
  vibe-vpn version                               print the version
  vibe-vpn certgen -out server -cn vpn.example.com
                                            generate a self-signed TLS certificate
  vibe-vpn quick up|down|status --config client.yaml
                                            wg-quick-style client lifecycle (daemon)

Flags:
  -config string       path to YAML configuration file
  -stats-interval int  override the statistics logging interval (seconds)
  -debug               force debug/pcap capture on
  -no-routing          skip automatic host routing setup (client)
  -no-nat              skip automatic nftables NAT setup (server)
`)
}
