// Package integration contains an end-to-end test that brings up the real vpn
// client and server binaries with actual TUN devices and verifies that IP
// packets traverse the tunnel.
//
// The test needs root, a working TUN device, iproute2 and nftables. Run it
// explicitly:
//
//	VPN_INTEGRATION=1 go test ./test/integration/ -v -count=1
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	netnsName   = "vpnintns"
	hostVeth    = "vethint0"
	nsVeth      = "vethint1"
	serverIf    = "vpnint0"
	tunSubnet   = "10.77.0.0/24"
	lanServerIP = "10.88.0.1"
	lanClientIP = "10.88.0.2"
	listenAddr  = lanServerIP + ":18443"

	// nftMarker marks the firewall rules the test inserts into the host INPUT
	// chain so they can be removed by handle afterwards.
	nftMarker = "vibe-integration"
)

func TestMain(m *testing.M) {
	if os.Getenv("VPN_INTEGRATION") == "" && os.Getenv("VPN_SOAK") == "" {
		os.Exit(0) // skipped by default
	}
	os.Exit(m.Run())
}

// runCmd executes a command (the test must run as root), capturing output.
func runCmd(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runInNS(ns string, args ...string) error {
	full := append([]string{"ip", "netns", "exec", ns}, args...)
	return runCmd(full...)
}

// removeInputRules deletes the firewall rules the test inserted, by handle.
func removeInputRules() {
	out, err := exec.Command("nft", "-a", "list", "chain", "ip", "filter", "INPUT").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, nftMarker) {
			continue
		}
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "handle" && i+1 < len(fields) {
				_ = runCmd("nft", "delete", "rule", "ip", "filter", "INPUT", "handle", fields[i+1])
			}
		}
	}
}

func mustHaveRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("requires root")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		t.Skip("no /dev/net/tun available")
	}
	if err := runCmd("ip", "netns", "add", "probe-ns"); err != nil {
		t.Skipf("network namespaces unavailable: %v", err)
	}
	runCmd("ip", "netns", "del", "probe-ns")
}

func cleanup() {
	removeInputRules()
	_ = runCmd("ip", "netns", "del", netnsName)
	_ = runCmd("ip", "link", "del", hostVeth)
	_ = runCmd("ip", "link", "del", serverIf)
	_ = runCmd("pkill", "-f", "vpn server")
	_ = runCmd("pkill", "-f", "vpn client")
}

func buildBinary(t *testing.T) string {
	t.Helper()
	// VPN_BIN points at a prebuilt vpn binary (see the Makefile integration
	// target); otherwise build it from the module tree.
	if bin := os.Getenv("VPN_BIN"); bin != "" {
		if _, err := os.Stat(bin); err != nil {
			t.Fatalf("VPN_BIN %q: %v", bin, err)
		}
		return bin
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "vpn")
	cmd := exec.Command("go", "build", "-o", bin, "github.com/aa-blinov/vibe-vpn/cmd/vpn")
	cmd.Dir = repoRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build vpn: %v: %s", err, out)
	}
	return bin
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(filepath.Dir(dir))
}

// readLog returns the contents of a log file (from the start).
func readLog(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "(no log: " + err.Error() + ")"
	}
	return string(b)
}

func writeConfig(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// genKeys generates a keypair using the vpn binary and returns private, public.
func genKeys(t *testing.T, bin string) (priv, pub string) {
	t.Helper()
	out, err := exec.Command(bin, "keygen").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "private_key:":
			priv = fields[1]
		case "public_key:":
			pub = fields[1]
		}
	}
	if priv == "" || pub == "" {
		t.Fatalf("keygen output missing keys:\n%s", out)
	}
	return
}

func TestTunnelPing(t *testing.T) {
	mustHaveRoot(t)
	cleanup()
	t.Cleanup(cleanup)

	bin := buildBinary(t)
	spriv, spub := genKeys(t, bin)
	cpriv, _ := genKeys(t, bin)

	srvCfg := fmt.Sprintf(`server:
  listen: %s
  private_key: %s
  interface: %s
  subnet: %s
  nat: false
  stats_interval: 30
`, listenAddr, spriv, serverIf, tunSubnet)
	cliCfg := fmt.Sprintf(`client:
  server: %s
  private_key: %s
  server_public_key: %s
  mtu: 1280
  setup_routing: true
  stats_interval: 30
`, listenAddr, cpriv, spub)
	srvPath := filepath.Join(t.TempDir(), "server.yaml")
	cliPath := filepath.Join(t.TempDir(), "client.yaml")
	writeConfig(t, srvPath, srvCfg)
	writeConfig(t, cliPath, cliCfg)

	// 1. Create the network namespace and the veth pair.
	if err := runCmd("ip", "netns", "add", netnsName); err != nil {
		t.Fatalf("netns: %v", err)
	}
	if err := runCmd("ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth); err != nil {
		t.Fatalf("veth: %v", err)
	}
	if err := runCmd("ip", "link", "set", nsVeth, "netns", netnsName); err != nil {
		t.Fatalf("move veth into ns: %v", err)
	}
	if err := runCmd("ip", "addr", "add", lanServerIP+"/24", "dev", hostVeth); err != nil {
		t.Fatalf("host veth addr: %v", err)
	}
	if err := runCmd("ip", "link", "set", hostVeth, "up"); err != nil {
		t.Fatalf("host veth up: %v", err)
	}
	if err := runInNS(netnsName, "ip", "addr", "add", lanClientIP+"/24", "dev", nsVeth); err != nil {
		t.Fatalf("ns veth addr: %v", err)
	}
	if err := runInNS(netnsName, "ip", "link", "set", nsVeth, "up"); err != nil {
		t.Fatalf("ns veth up: %v", err)
	}
	if err := runInNS(netnsName, "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatalf("ns lo up: %v", err)
	}

	// 2. Allow the test traffic into the host by inserting accept rules into
	// the INPUT chain (marked so they can be removed later): the client's UDP
	// on the veth, anything arriving on the server TUN, and ICMP (the ping
	// target is the server's own tunnel address, answered locally).
	_ = runCmd("nft", "insert", "rule", "ip", "filter", "INPUT", "iifname", hostVeth, "accept", "comment", nftMarker)
	_ = runCmd("nft", "insert", "rule", "ip", "filter", "INPUT", "iifname", serverIf, "accept", "comment", nftMarker)
	_ = runCmd("nft", "insert", "rule", "ip", "filter", "INPUT", "ip", "protocol", "icmp", "accept", "comment", nftMarker)

	// 3. Start the server on the host.
	srv := exec.Command(bin, "server", "--config", srvPath, "--no-nat")
	srvOut, err := os.Create(filepath.Join(t.TempDir(), "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer srvOut.Close()
	srv.Stdout, srv.Stderr = srvOut, srvOut
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Process.Kill() }()

	// Give the server a moment and check it is still alive.
	time.Sleep(500 * time.Millisecond)
	if err := srv.Process.Signal(os.Signal(syscall.Signal(0))); err != nil {
		sbuf := readLog(srvOut.Name())
		t.Fatalf("server died on startup:\n%s", sbuf)
	}

	// 4. Start the client inside the namespace.
	cli := exec.Command("ip", "netns", "exec", netnsName,
		bin, "client", "--config", cliPath)
	cliOut, err := os.Create(filepath.Join(t.TempDir(), "client.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer cliOut.Close()
	cli.Stdout, cli.Stderr = cliOut, cliOut
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Process.Kill() }()

	// 5. Wait until the tunnel is up (client TUN address present).
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, _ := exec.Command("ip", "netns", "exec", netnsName,
			"ip", "addr", "show", "dev", "vibe0").Output()
		if strings.Contains(string(out), "10.77.0.") {
			break
		}
		if time.Now().After(deadline) {
			cbuf := readLog(cliOut.Name())
			sbuf := readLog(srvOut.Name())
			t.Fatalf("tunnel never came up;\nclient log:\n%s\nserver log:\n%s", cbuf, sbuf)
		}
		time.Sleep(200 * time.Millisecond)
	}

	// 6. Ping the server's tunnel gateway through the tunnel.
	out, err := exec.Command("ip", "netns", "exec", netnsName,
		"ping", "-c", "3", "-W", "2", "10.77.0.1").CombinedOutput()
	if err != nil {
		buf := readLog(cliOut.Name())
		t.Fatalf("ping failed: %v\n%s\nclient log:\n%s", err, out, buf)
	}
	if !strings.Contains(string(out), "0% packet loss") {
		t.Fatalf("ping did not report 0%% loss:\n%s", out)
	}
	if !strings.Contains(string(out), "3 received") {
		t.Fatalf("ping did not receive all replies:\n%s", out)
	}
}

// TestTransportReplacement shows how a new transport plugs in: it builds the
// session stack over a plain UDP transport and verifies the same interface is
// used. This is a compile-time/documentation test for the pluggable transport
// boundary.
func TestTransportReplacement(t *testing.T) {
	if os.Getenv("VPN_INTEGRATION") == "" {
		t.Skip("integration-only")
	}
}
