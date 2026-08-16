package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSoak runs the real tunnel under sustained traffic for a duration and
// checks stability: the client stays connected, no unexpected reconnects and
// traffic keeps flowing.
//
//	Gated: VPN_SOAK=1, root. Duration via VPN_SOAK_DURATION (seconds, default 30).
func TestSoak(t *testing.T) {
	if os.Getenv("VPN_SOAK") == "" {
		t.Skip("set VPN_SOAK=1 to run the soak test")
	}
	mustHaveRoot(t)
	cleanup()
	t.Cleanup(cleanup)

	dur := 30 * time.Second
	if d := os.Getenv("VPN_SOAK_DURATION"); d != "" {
		var secs int
		if _, err := fmt.Sscanf(d, "%d", &secs); err == nil && secs > 0 {
			dur = time.Duration(secs) * time.Second
		}
	}

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
  keepalive_interval: 5
  stats_interval: 30
`, listenAddr, cpriv, spub)
	srvPath := filepath.Join(t.TempDir(), "server.yaml")
	cliPath := filepath.Join(t.TempDir(), "client.yaml")
	writeConfig(t, srvPath, srvCfg)
	writeConfig(t, cliPath, cliCfg)

	if err := runCmd("ip", "netns", "add", netnsName); err != nil {
		t.Fatalf("netns: %v", err)
	}
	if err := runCmd("ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth); err != nil {
		t.Fatalf("veth: %v", err)
	}
	if err := runCmd("ip", "link", "set", nsVeth, "netns", netnsName); err != nil {
		t.Fatalf("move veth: %v", err)
	}
	if err := runCmd("ip", "addr", "add", lanServerIP+"/24", "dev", hostVeth); err != nil {
		t.Fatalf("host veth: %v", err)
	}
	if err := runCmd("ip", "link", "set", hostVeth, "up"); err != nil {
		t.Fatalf("host veth up: %v", err)
	}
	if err := runInNS(netnsName, "ip", "addr", "add", lanClientIP+"/24", "dev", nsVeth); err != nil {
		t.Fatalf("ns veth: %v", err)
	}
	if err := runInNS(netnsName, "ip", "link", "set", nsVeth, "up"); err != nil {
		t.Fatalf("ns veth up: %v", err)
	}
	if err := runInNS(netnsName, "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatalf("ns lo: %v", err)
	}
	_ = runCmd("nft", "insert", "rule", "ip", "filter", "INPUT", "iifname", hostVeth, "accept")
	_ = runCmd("nft", "insert", "rule", "ip", "filter", "INPUT", "iifname", serverIf, "accept")
	_ = runCmd("nft", "insert", "rule", "ip", "filter", "INPUT", "ip", "protocol", "icmp", "accept")

	srv := exec.Command(bin, "server", "--config", srvPath, "--no-nat")
	srvOut, _ := os.Create(filepath.Join(t.TempDir(), "server.log"))
	defer srvOut.Close()
	srv.Stdout, srv.Stderr = srvOut, srvOut
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Process.Kill() }()

	cli := exec.Command("ip", "netns", "exec", netnsName, bin, "client", "--config", cliPath)
	cliOut, _ := os.Create(filepath.Join(t.TempDir(), "client.log"))
	defer cliOut.Close()
	cli.Stdout, cli.Stderr = cliOut, cliOut
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Process.Kill() }()

	// Wait for the tunnel to come up.
	deadline := time.Now().Add(15 * time.Second)
	for {
		out, _ := exec.Command("ip", "netns", "exec", netnsName,
			"ip", "addr", "show", "dev", "vibe0").Output()
		if strings.Contains(string(out), "10.77.0.") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tunnel never came up;\nclient log:\n%s\nserver log:\n%s",
				readLog(cliOut.Name()), readLog(srvOut.Name()))
		}
		time.Sleep(200 * time.Millisecond)
	}

	// Pump traffic: ping flood for the duration.
	t.Logf("soaking for %v...", dur)
	pump := exec.Command("ip", "netns", "exec", netnsName, "ping", "-f", "-q", "-W", "1", "10.77.0.1")
	if err := pump.Start(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(dur)
	_ = pump.Process.Kill()
	_, _ = pump.Output()

	// The tunnel must still be up and functional after the soak.
	out, err := exec.Command("ip", "netns", "exec", netnsName,
		"ping", "-c", "3", "-W", "2", "10.77.0.1").CombinedOutput()
	if err != nil {
		t.Fatalf("tunnel did not survive the soak:\n%s\nclient log:\n%s", out, readLog(cliOut.Name()))
	}
	if !strings.Contains(string(out), "0% packet loss") {
		t.Fatalf("tunnel degraded after soak:\n%s", out)
	}
	// The client must not have reconnected during the soak.
	buf := readLog(cliOut.Name())
	lastStats := ""
	for _, line := range strings.Split(buf, "\n") {
		if strings.Contains(line, "reconnects=") {
			lastStats = line
		}
	}
	if lastStats != "" && !strings.Contains(lastStats, "reconnects=0") {
		t.Fatalf("client reconnected during soak: %s", lastStats)
	}
}
