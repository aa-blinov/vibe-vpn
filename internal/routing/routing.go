// Package routing configures host networking for the tunnel (TUN addresses,
// routes, IPv4 forwarding and nftables NAT). All operations are delegated to
// standard tools (ip, sysctl, nft) so the setup stays visible and easy to
// reproduce by hand. Every function is idempotent.
package routing

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// EnableIPForward turns on IPv4 forwarding for the host.
func EnableIPForward() error {
	return run("sysctl", "-w", "net.ipv4.ip_forward=1")
}

// SetupServerTUN assigns the subnet gateway address to the server's TUN
// interface, sets it up and configures the MTU.
func SetupServerTUN(name string, addr net.IP, prefix int, mtu int) error {
	ipnet := fmt.Sprintf("%s/%d", addr, prefix)
	if err := run("ip", "addr", "replace", ipnet, "dev", name); err != nil {
		return err
	}
	if err := run("ip", "link", "set", "dev", name, "up"); err != nil {
		return err
	}
	if mtu > 0 {
		if err := run("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu)); err != nil {
			return err
		}
	}
	return nil
}

// SetupClientTUN assigns the client address, brings the interface up and
// installs routing so the tunnel carries traffic without capturing the VPN's
// own UDP flow to the server.
func SetupClientTUN(name string, clientIP net.IP, prefix int, gw net.IP, serverAddr string, mtu int) error {
	if err := run("ip", "addr", "replace", fmt.Sprintf("%s/%d", clientIP, prefix), "dev", name); err != nil {
		return err
	}
	if err := run("ip", "link", "set", "dev", name, "up"); err != nil {
		return err
	}
	if mtu > 0 {
		if err := run("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu)); err != nil {
			return err
		}
	}
	// Pin the route to the VPN server so the tunnel does not route our own UDP
	// traffic into itself. Derive it from the current default route.
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}
	via, dev, err := routeTo(host)
	if err != nil {
		return err
	}
	if via != "" {
		if err := run("ip", "route", "replace", host, "via", via); err != nil {
			return err
		}
	} else if dev != "" {
		if err := run("ip", "route", "replace", host, "dev", dev); err != nil {
			return err
		}
	}
	// Point default traffic into the tunnel.
	return run("ip", "route", "replace", "default", "via", gw.String(), "dev", name)
}

// routeTo resolves the next hop for a destination using "ip route get".
func routeTo(dst string) (via, dev string, err error) {
	out, err := exec.Command("ip", "route", "get", dst).Output()
	if err != nil {
		return "", "", err
	}
	via, dev = parseRouteGet(string(out))
	return via, dev, nil
}

// parseRouteGet extracts the "via" and "dev" fields from `ip route get` output.
func parseRouteGet(out string) (via, dev string) {
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			via = fields[i+1]
		}
		if f == "dev" && i+1 < len(fields) {
			dev = fields[i+1]
		}
	}
	return via, dev
}

// SetupServerNAT installs a masquerade rule so tunnel clients can reach the
// internet through the server's outbound interface.
func SetupServerNAT(subnet string, outIf string) error {
	const table = "vibe"
	// Drop the old chain to make the setup idempotent.
	_ = exec.Command("nft", "delete", "table", "ip", table).Run()
	// "flush" the chain inside the shell string is avoided by using an explicit
	// single nft invocation for the whole ruleset.
	rule := fmt.Sprintf(`
table ip %s {
	chain postrouting {
		type nat hook postrouting priority 100;
		ip saddr %s oifname %q masquerade
	}
}`, table, subnet, outIf)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rule)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft: %w", err)
	}
	return nil
}
