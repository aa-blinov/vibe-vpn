// Package desync integrates the nfqws-based DPI desynchronization (zapret)
// into the client: it creates an nftables queue rule for the tunnel's TCP
// flow and runs nfqws to modify those packets so a passive DPI cannot
// recognize the connection. Everything is torn down on Stop.
//
// This is packet-level work that belongs to the client host (it needs root
// and the nfqws binary built from https://github.com/bol-van/zapret); the
// session layer is not involved.
package desync

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// Config describes the desync policy for the tunnel's TCP flow.
type Config struct {
	Enabled   bool
	NFQWS     string // path to the nfqws binary
	Queue     int    // NFQUEUE number
	DPIDesync string // value for --dpi-desync (e.g. "split2", "fake")
	SplitPos  string // value for --dpi-desync-split-pos (e.g. "2", "tlsclienthello+1")
	Fooling   string // value for --dpi-desync-fooling (e.g. "badseq")
}

const table = "vibe-desync"

// Manager owns the nftables rule and the nfqws process for one tunnel.
type Manager struct {
	cfg   Config
	dport int
	cmd   *exec.Cmd
}

// Start brings up the desync policy for outbound TCP to dport. It returns nil
// (and does nothing) when disabled.
func Start(cfg Config, dport int, log io.Writer) (*Manager, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	if cfg.NFQWS == "" {
		return nil, errors.New("desync: nfqws binary path is required")
	}
	m := &Manager{cfg: cfg, dport: dport}
	if err := m.setupNft(); err != nil {
		return nil, err
	}
	cmd, err := m.nfqwsCmd(log)
	if err != nil {
		m.teardownNft()
		return nil, err
	}
	m.cmd = cmd
	return m, nil
}

func (m *Manager) setupNft() error {
	nft := func(args ...string) error {
		// #nosec G204 -- fixed "nft" binary with config-derived arguments.
		cmd := exec.Command("nft", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	// Idempotent setup in a dedicated table.
	_ = exec.Command("nft", "delete", "table", "inet", table).Run()
	if err := nft("add", "table", "inet", table); err != nil {
		return err
	}
	if err := nft("add", "chain", "inet", table, "out", "{ type filter hook output priority 0; }"); err != nil {
		return err
	}
	return nft("add", "rule", "inet", table, "out",
		"tcp", "dport", strconv.Itoa(m.dport),
		"queue", "num", strconv.Itoa(m.cfg.Queue))
}

func (m *Manager) nfqwsCmd(log io.Writer) (*exec.Cmd, error) {
	args := buildNFQWSArgs(m.dport, m.cfg.Queue, m.cfg.DPIDesync, m.cfg.SplitPos, m.cfg.Fooling)
	cmd := exec.Command(m.cfg.NFQWS, args...) // #nosec G204 -- operator-configured binary
	if log != nil {
		cmd.Stdout = log
		cmd.Stderr = log
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("desync: start nfqws: %w", err)
	}
	go cmd.Wait()
	return cmd, nil
}

// buildNFQWSArgs assembles the nfqws command line for a strategy.
func buildNFQWSArgs(dport, queue int, dpidesync, splitPos, fooling string) []string {
	args := []string{
		"--filter-tcp=" + strconv.Itoa(dport),
		"--dpi-desync=" + dpidesync,
		"--qnum=" + strconv.Itoa(queue),
	}
	if splitPos != "" {
		args = append(args, "--dpi-desync-split-pos="+splitPos)
	}
	if fooling != "" {
		args = append(args, "--dpi-desync-fooling="+fooling)
	}
	return args
}

// Stop kills nfqws and removes the nftables rule.
func (m *Manager) Stop() {
	if m == nil {
		return
	}
	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
	}
	m.teardownNft()
}

func (m *Manager) teardownNft() {
	_ = exec.Command("nft", "delete", "table", "inet", table).Run()
}
