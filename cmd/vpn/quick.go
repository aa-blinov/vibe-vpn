package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/aa-blinov/vibe-vpn/internal/config"
	"github.com/aa-blinov/vibe-vpn/internal/ctl"
)

// runQuick implements a wg-quick-like lifecycle for the client:
//
//	vibe-vpn quick up     --config client.yaml   start the client as a daemon
//	vibe-vpn quick down   --config client.yaml   stop the daemon gracefully
//	vibe-vpn quick status --config client.yaml   show the daemon status
//
// It uses the client's control socket as the running marker: `up` fails if a
// daemon is already listening, `down` asks that daemon to stop via the socket,
// and `status` queries it.
func runQuick(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("quick: usage: vibe-vpn quick up|down|status [flags]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("quick "+sub, flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to the client YAML configuration")
	_ = fs.Parse(args[1:])
	if *cfgPath == "" {
		return fmt.Errorf("quick: -config is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	cc := cfg.Client
	if cc == nil {
		return fmt.Errorf("quick: config file has no client section")
	}
	if err := cc.Validate(); err != nil {
		return err
	}
	if cc.Ctl == "" {
		return fmt.Errorf("quick: the client config must set ctl: (control socket) for up/down/status")
	}

	switch sub {
	case "up":
		return quickUp(cc, *cfgPath)
	case "down":
		if err := ctl.Stop(cc.Ctl); err != nil {
			return fmt.Errorf("quick: down: %w", err)
		}
		fmt.Println("stopped")
		return nil
	case "status":
		return quickStatus(cc)
	default:
		return fmt.Errorf("quick: unknown %q (use up|down|status)", sub)
	}
}

// quickUp starts the client in the background unless one is already running on
// the control socket.
func quickUp(cc *config.Client, cfgPath string) error {
	if s, err := ctl.Query(cc.Ctl); err == nil {
		return fmt.Errorf("quick: a client is already running:\n%s", s)
	}

	absCfg, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logPath := cc.Ctl + ".log"
	// #nosec G304,G703 -- logPath is derived from the operator's config ctl
	// socket (path comes from the operator, never from untrusted input).
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()

	// #nosec G204,G702 -- exe is the running binary and the args are fixed;
	// both are operator-controlled, never from untrusted input.
	cmd := exec.Command(exe, "client", "--config", absCfg)
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = detachAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	// Release the child so it outlives this process.
	_ = cmd.Process.Release()
	fmt.Printf("started client (pid %d), logs: %s\n", cmd.Process.Pid, logPath)
	return nil
}

// quickStatus queries the running client's control socket.
func quickStatus(cc *config.Client) error {
	s, err := ctl.Query(cc.Ctl)
	if err != nil {
		return fmt.Errorf("quick: not running: %w", err)
	}
	fmt.Print(s)
	return nil
}
