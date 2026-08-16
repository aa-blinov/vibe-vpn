package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aa-blinov/vibe-vpn/internal/config"
	"github.com/aa-blinov/vibe-vpn/internal/crypto"
	"github.com/aa-blinov/vibe-vpn/internal/framing"
	"github.com/aa-blinov/vibe-vpn/internal/metrics"
	"github.com/aa-blinov/vibe-vpn/internal/pcap"
	"github.com/aa-blinov/vibe-vpn/internal/routing"
	"github.com/aa-blinov/vibe-vpn/internal/session"
	"github.com/aa-blinov/vibe-vpn/internal/transport"
	"github.com/aa-blinov/vibe-vpn/internal/transport/rawtcp"
	"github.com/aa-blinov/vibe-vpn/internal/transport/tlsx"
	"github.com/aa-blinov/vibe-vpn/internal/transport/udp"
	"github.com/aa-blinov/vibe-vpn/internal/tun"
)

func runServer(args []string) error {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to server YAML configuration")
	statsInterval := fs.Int("stats-interval", 0, "override statistics logging interval (seconds)")
	debug := fs.Bool("debug", false, "force debug capture on")
	noNAT := fs.Bool("no-nat", false, "skip automatic nftables NAT setup")
	sDomain := fs.String("domain", "", "auto-setup: certificate name / SNI")
	sTLSListen := fs.String("tls-listen", "0.0.0.0:443", "auto-setup: TLS listen address")
	sListen := fs.String("listen", "0.0.0.0:4433", "auto-setup: UDP listen (unused with TLS)")
	sSubnet := fs.String("subnet", "10.77.0.0/24", "auto-setup: tunnel subnet")
	sIface := fs.String("interface", "vpn0", "auto-setup: server tun interface")
	sOut := fs.String("out", "./vibe-vpn-server", "auto-setup: output directory")
	fs.Parse(args)

	if *cfgPath == "" {
		// One-command mode: generate everything, then run.
		generated, err := setupServerDir(*sOut, *sDomain, *sTLSListen, *sListen, *sSubnet, *sIface)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "generated config %s\n", generated)
		*cfgPath = generated
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	sc := cfg.Server
	if sc == nil {
		return fmt.Errorf("config file has no server section")
	}
	if err := sc.Validate(); err != nil {
		return err
	}
	if *statsInterval > 0 {
		sc.StatsInterval = *statsInterval
	}

	logger := log.New(os.Stderr, "vibe-vpn-server ", log.LstdFlags)
	priv, err := loadPrivateKey(sc.PrivateKey, sc.PrivateKeyEncrypted)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	kp, err := crypto.KeypairFromPrivate(priv)
	if err != nil {
		return err
	}

	subnet, err := parseCIDR(sc.Subnet)
	if err != nil {
		return err
	}
	peers, err := parsePeers(sc.Peers)
	if err != nil {
		return err
	}

	// Data plane: open the server TUN and configure the gateway address.
	iface, err := tun.Open(sc.Interface, sc.MTU)
	if err != nil {
		return err
	}
	defer iface.Close()
	logger.Printf("tun interface %s ready (mtu %d)", iface.Name(), sc.MTU)

	if err := routing.EnableIPForward(); err != nil {
		logger.Printf("warning: enable ip_forward: %v", err)
	}
	ones, _ := subnet.Mask.Size()
	gw := gatewayIP(subnet)
	if err := routing.SetupServerTUN(iface.Name(), gw, ones, sc.MTU); err != nil {
		logger.Printf("warning: server tun setup: %v (run the ip commands manually, see README)", err)
	}
	if sc.NAT && !*noNAT {
		if err := routing.SetupServerNAT(subnet.String(), sc.OutboundInterface); err != nil {
			logger.Printf("warning: NAT setup: %v (run the nftables commands manually, see README)", err)
		} else {
			logger.Printf("nftables masquerade installed for %s via %s", subnet, sc.OutboundInterface)
		}
	}

	mgr, err := session.NewManager(session.ServerConfig{
		Keypair:          kp,
		Subnet:           subnet,
		MTU:              sc.MTU,
		Keepalive:        time.Duration(sc.Keepalive) * time.Second,
		SessionTimeout:   time.Duration(sc.SessionTimeout) * time.Second,
		HandshakeTimeout: time.Duration(config.DefaultHandshakeTimeout) * time.Second,
		Peers:            peers,
		MaxSessions:      session.DefaultMaxSessions,
		Shaping:          shaping(sc.Shaping),
		Log:              logger,
	})
	if err != nil {
		return err
	}
	mgr.SetTUN(iface)

	// Optional Prometheus metrics endpoint on a loopback address.
	var metricsSrv *metrics.Server
	if sc.Metrics != "" {
		metricsSrv, err = metrics.Serve(sc.Metrics, func() map[string]float64 {
			st := mgr.Stats()
			return map[string]float64{
				"vibe_sessions":         float64(st.Sessions.Load()),
				"vibe_handshakes_total": float64(st.Handshakes.Load()),
				"vibe_dropped_total":    float64(st.Dropped.Load()),
			}
		})
		if err != nil {
			return err
		}
		defer metricsSrv.Close()
		logger.Printf("metrics on http://%s/metrics", metricsSrv.Addr())
	}

	var pcapWriter *pcap.Writer
	if *debug || sc.Debug != "" {
		path := sc.Debug
		if path == "" {
			path = "/tmp/vibe-vpn-server"
		}
		pcapWriter, err = pcap.Open(path + ".pcap")
		if err != nil {
			return fmt.Errorf("debug capture: %w", err)
		}
		mgr.SetDebugPcap(pcapWriter)
		defer pcapWriter.Close()
		logger.Printf("debug capture enabled: %s.pcap", path)
	}

	// SIGHUP reloads the config and applies the peer allowlist at runtime.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			reloaded, err := config.Load(*cfgPath)
			if err != nil {
				logger.Printf("config reload failed: %v", err)
				continue
			}
			if reloaded.Server == nil {
				logger.Printf("config reload: no server section")
				continue
			}
			np, err := parsePeers(reloaded.Server.Peers)
			if err != nil {
				logger.Printf("config reload: %v", err)
				continue
			}
			mgr.SetPeers(np)
			logger.Printf("config reloaded (%d peers)", len(np))
		}
	}()

	// Control plane: bind the transport (raw TCP, TLS or UDP).
	shp := shaping(sc.Shaping)
	if sc.Transport == "raw" {
		rs, err := rawtcp.Listen(sc.Listen)
		if err != nil {
			return err
		}
		defer rs.Close()
		rs.SetOnConn(func(t transport.Transport) bool {
			return mgr.HandleTransport(framing.Jitter(t, shp.Jitter))
		})
		logger.Printf("raw listening on %s (subnet %s)", sc.Listen, subnet)
	} else if sc.TLS != nil {
		ts, err := tlsx.Listen(sc.TLS.Listen, sc.TLS.Cert, sc.TLS.Key)
		if err != nil {
			return err
		}
		defer ts.Close()
		ts.SetOnConn(func(t transport.Transport) bool {
			return mgr.HandleTransport(framing.Jitter(t, shp.Jitter))
		})
		logger.Printf("tls listening on %s (subnet %s)", sc.TLS.Listen, subnet)
	} else {
		us, err := udp.Listen(sc.Listen)
		if err != nil {
			return err
		}
		defer us.Close()
		us.SetOnNewPeer(func(_ *net.UDPAddr, t transport.Transport) bool {
			return mgr.HandleTransport(framing.Jitter(t, shp.Jitter))
		})
		logger.Printf("listening on %s (subnet %s)", sc.Listen, subnet)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGUSR1 dumps current statistics on demand.
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	go func() {
		for range usr1 {
			st := mgr.Stats()
			logger.Printf("stats: sessions=%d handshakes=%d dropped=%d",
				st.Sessions.Load(), st.Handshakes.Load(), st.Dropped.Load())
		}
	}()

	go mgr.TunLoop(ctx)

	// Statistics reporter.
	if sc.StatsInterval > 0 {
		go func() {
			t := time.NewTicker(time.Duration(sc.StatsInterval) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					st := mgr.Stats()
					logger.Printf("sessions=%d handshakes=%d dropped=%d",
						st.Sessions.Load(), st.Handshakes.Load(), st.Dropped.Load())
				}
			}
		}()
	}

	<-ctx.Done()
	logger.Printf("shutting down")
	return nil
}

func parseCIDR(s string) (*net.IPNet, error) {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("subnet %q: %w", s, err)
	}
	return n, nil
}

// parsePeers converts a config peer list into the allowlist map.
func parsePeers(list []string) (map[string][]byte, error) {
	peers := make(map[string][]byte)
	for _, p := range list {
		key, err := crypto.DecodeKey(p)
		if err != nil {
			return nil, fmt.Errorf("peers: %w", err)
		}
		peers[crypto.EncodeKey(key)] = key
	}
	return peers, nil
}

func gatewayIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	g := make(net.IP, 4)
	copy(g, ip)
	g[3]++
	return g
}
