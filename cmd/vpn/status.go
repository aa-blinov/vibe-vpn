package main

import (
	"flag"
	"fmt"

	"github.com/aa-blinov/vibe-vpn/internal/config"
	"github.com/aa-blinov/vibe-vpn/internal/ctl"
)

// runStatus connects to a running server/client via its control socket and
// prints the current status snapshot (like `wg show`).
func runStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to the configuration file of the running daemon")
	_ = fs.Parse(args)
	if *cfgPath == "" {
		return fmt.Errorf("status requires -config")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	sock := ""
	if cfg.Server != nil {
		sock = cfg.Server.Ctl
	}
	if cfg.Client != nil {
		sock = cfg.Client.Ctl
	}
	if sock == "" {
		return fmt.Errorf("no control socket configured (set ctl: in the config)")
	}
	s, err := ctl.Query(sock)
	if err != nil {
		return fmt.Errorf("cannot reach daemon: %w", err)
	}
	fmt.Print(s)
	return nil
}
