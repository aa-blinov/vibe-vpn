package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"crypto/x509"

	"github.com/aa-blinov/vibe-vpn/internal/config"
	"github.com/aa-blinov/vibe-vpn/internal/crypto"
	"github.com/aa-blinov/vibe-vpn/internal/ctl"
	"github.com/aa-blinov/vibe-vpn/internal/desync"
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

func runClient(args []string) error {
	fs := flag.NewFlagSet("client", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to client YAML configuration")
	statsInterval := fs.Int("stats-interval", 0, "override statistics logging interval (seconds)")
	debug := fs.Bool("debug", false, "force debug capture on")
	noRouting := fs.Bool("no-routing", false, "skip automatic host routing setup")
	cServer := fs.String("server", "", "auto-setup: server host:port (TLS port)")
	cPeer := fs.String("peer", "", "auto-setup: peer directory from server setup")
	cDesync := fs.Bool("desync", false, "auto-setup: enable nfqws desync")
	cNfqws := fs.String("nfqws", "/usr/local/bin/nfqws", "auto-setup: path to nfqws")
	cOut := fs.String("out", "./vibe-vpn-client", "auto-setup: output directory")
	_ = fs.Parse(args)

	if *cfgPath == "" {
		// One-command mode: generate everything, then run.
		generated, err := setupClientDir(*cOut, *cServer, *cPeer, *cDesync, *cNfqws)
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
	cc := cfg.Client
	if cc == nil {
		return fmt.Errorf("config file has no client section")
	}
	if err := cc.Validate(); err != nil {
		return err
	}
	if *statsInterval > 0 {
		cc.StatsInterval = *statsInterval
	}

	logger := log.New(os.Stderr, "vibe-vpn-client ", log.LstdFlags)
	priv, err := loadPrivateKey(cc.PrivateKey, cc.PrivateKeyEncrypted)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	kp, err := crypto.KeypairFromPrivate(priv)
	if err != nil {
		return err
	}
	serverPub, err := crypto.DecodeKey(cc.ServerPublicKey)
	if err != nil {
		return fmt.Errorf("server_public_key: %w", err)
	}

	// Optional DPI desync of the tunnel's own TCP flow (nfqws/zapret).
	var desyncMgr *desync.Manager
	if cc.Desync != nil && cc.Desync.Enabled {
		_, dport, err := net.SplitHostPort(cc.Server)
		if err != nil {
			return fmt.Errorf("server address: %w", err)
		}
		dportN, err := strconv.Atoi(dport)
		if err != nil {
			return fmt.Errorf("server port: %w", err)
		}
		dm, err := desync.Start(desync.Config{
			Enabled:   true,
			NFQWS:     cc.Desync.NFQWS,
			Queue:     cc.Desync.Queue,
			DPIDesync: cc.Desync.DPIDesync,
			SplitPos:  cc.Desync.SplitPos,
			Fooling:   cc.Desync.Fooling,
		}, dportN, os.Stderr)
		if err != nil {
			logger.Printf("warning: DPI desync disabled: %v", err)
		} else {
			logger.Printf("DPI desync active for tcp/%d via %s (mode %s)", dportN, cc.Desync.NFQWS, cc.Desync.DPIDesync)
			desyncMgr = dm
		}
	}

	var clientIP net.IP
	if cc.ClientIP != "" {
		clientIP = net.ParseIP(cc.ClientIP)
		if clientIP == nil || clientIP.To4() == nil {
			return fmt.Errorf("client_ip %q is not a valid IPv4 address", cc.ClientIP)
		}
	}

	// Data plane: open the client TUN (address and routes are configured after
	// the server assigns us an IP during the handshake).
	iface, err := tun.Open("vibe%d", cc.MTU)
	if err != nil {
		return err
	}
	defer iface.Close()
	logger.Printf("tun interface %s ready (mtu %d)", iface.Name(), cc.MTU)

	var pcapWriter *pcap.Writer
	if *debug || cc.Debug != "" {
		path := cc.Debug
		if path == "" {
			path = "/tmp/vibe-vpn-client"
		}
		pcapWriter, err = pcap.Open(path + ".pcap")
		if err != nil {
			return fmt.Errorf("debug capture: %w", err)
		}
		defer pcapWriter.Close()
		logger.Printf("debug capture enabled: %s.pcap", path)
	}

	shp := shaping(cc.Shaping)
	dial, err := clientDial(cc, logger)
	if err != nil {
		return err
	}
	client := session.NewClient(session.ClientConfig{
		Dial: func() (transport.Transport, error) {
			t, err := dial()
			if err != nil {
				return nil, err
			}
			return framing.Jitter(t, shp.Jitter), nil
		},
		Keypair:           kp,
		ServerPublic:      serverPub,
		MTU:               cc.MTU,
		Keepalive:         time.Duration(cc.Keepalive) * time.Second,
		SessionTimeout:    time.Duration(cc.SessionTimeout) * time.Second,
		HandshakeTimeout:  time.Duration(config.DefaultHandshakeTimeout) * time.Second,
		RekeyAfterPackets: cc.RekeyAfterPackets,
		RekeyAfterTime:    time.Duration(cc.RekeyAfterSeconds) * time.Second,
		ClientIP:          clientIP,
		Shaping:           shp,
		Pcap:              pcapWriter,
		Log:               logger,
	})

	// Optional control socket for `vibe-vpn status`.
	var ctlSrv *ctl.Server
	if cc.Ctl != "" {
		ctlSrv, err = ctl.Serve(cc.Ctl, func() string {
			return client.Stats().Dump("client")
		})
		if err != nil {
			return err
		}
		defer ctlSrv.Close()
		logger.Printf("control socket on %s", cc.Ctl)
	}

	// Optional Prometheus metrics endpoint on a loopback address.
	var metricsSrv *metrics.Server
	if cc.Metrics != "" {
		metricsSrv, err = metrics.Serve(cc.Metrics, func() map[string]float64 {
			st := client.Stats()
			m := map[string]float64{
				"vibe_tx_packets":       float64(st.PacketsSent.Load()),
				"vibe_tx_bytes":         float64(st.BytesSent.Load()),
				"vibe_rx_packets":       float64(st.PacketsReceived.Load()),
				"vibe_rx_bytes":         float64(st.BytesReceived.Load()),
				"vibe_dropped_total":    float64(st.PacketsDropped.Load()),
				"vibe_reconnects_total": float64(st.Reconnects.Load()),
				"vibe_rekeys_total":     float64(st.Rekeys.Load()),
				"vibe_loss_total":       float64(st.LossTotal.Load()),
				"vibe_rtt_seconds":      st.RTT().Seconds(),
			}
			// Cumulative RTT histogram (Prometheus buckets).
			buckets := st.RTTBuckets()
			thresholds := session.RTTThresholds()
			for i, count := range buckets {
				label := fmt.Sprintf("%.0fms", thresholds[i])
				m["vibe_rtt_bucket{le=\""+label+"\"}"] = float64(count)
			}
			return m
		})
		if err != nil {
			return err
		}
		defer metricsSrv.Close()
		logger.Printf("metrics on http://%s/metrics", metricsSrv.Addr())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGUSR1 dumps current statistics on demand.
	usr1 := statsSignals()
	go func() {
		for range usr1 {
			logger.Print(client.Stats().Dump("client"))
		}
	}()

	setupRouting := cc.SetupRouting && !*noRouting
	onAssign := func(ip, gw net.IP, prefix int) {
		logger.Printf("assigned %s/%d (gateway %s)", ip, prefix, gw)
		if setupRouting {
			if err := routing.SetupClientTUN(iface.Name(), ip, prefix, gw, cc.Server, cc.MTU); err != nil {
				logger.Printf("warning: client routing setup: %v (configure routes manually)", err)
			}
		}
	}

	// Statistics reporter.
	if cc.StatsInterval > 0 {
		go func() {
			t := time.NewTicker(time.Duration(cc.StatsInterval) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					logger.Print(client.Stats().Dump("client"))
				}
			}
		}()
	}

	if desyncMgr != nil {
		defer desyncMgr.Stop()
	}

	if err := client.Run(ctx, iface, onAssign); err != nil && ctx.Err() == nil {
		return err
	}
	logger.Printf("shutting down")
	return nil
}

// clientDial returns the transport dialer for the configured transport: the
// TLS transport if a tls section is present, otherwise plain UDP.
func clientDial(cc *config.Client, logger *log.Logger) (func() (transport.Transport, error), error) {
	if cc.Transport == "raw" {
		logger.Printf("raw transport to %s (obfs4-style, no TLS)", cc.Server)
		return func() (transport.Transport, error) { return rawtcp.Dial(cc.Server) }, nil
	}
	if cc.TLS == nil {
		return func() (transport.Transport, error) { return udp.Dial(cc.Server) }, nil
	}
	var roots *x509.CertPool
	insecure := false
	if cc.TLS.CA != "" {
		pool, err := tlsx.LoadCertPool(cc.TLS.CA)
		if err != nil {
			return nil, fmt.Errorf("tls.ca: %w", err)
		}
		roots = pool
	} else {
		insecure = cc.TLS.Insecure
	}
	serverName := cc.TLS.ServerName
	if serverName == "" {
		host, _, err := net.SplitHostPort(cc.Server)
		if err != nil {
			return nil, fmt.Errorf("server address: %w", err)
		}
		serverName = host
	}
	if roots == nil && !insecure {
		return nil, fmt.Errorf("tls: set ca or insecure=true")
	}
	logger.Printf("tls transport to %s (sni %s)", cc.Server, serverName)
	fp := cc.TLS.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	logger.Printf("tls transport to %s (sni %s, fingerprint %s)", cc.Server, serverName, fp)
	return func() (transport.Transport, error) {
		return tlsx.Dial(cc.Server, serverName, roots, insecure, fp)
	}, nil
}
