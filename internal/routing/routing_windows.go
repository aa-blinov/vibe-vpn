//go:build windows

package routing

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// run executes a command and returns any error.
func run(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// netshSetAddr assigns a static address to an interface.
func netshSetAddr(name string, ip net.IP, mask net.IPMask) error {
	return run("netsh", "interface", "ip", "set", "address",
		"name="+name, "static", ip.String(), net.IP(mask).String())
}

// netshSetMTU sets the interface MTU.
func netshSetMTU(name string, mtu int) error {
	return run("netsh", "interface", "ipv4", "set", "subinterface",
		name, "mtu="+fmt.Sprint(mtu), "store=active")
}

// defaultGateway returns the active IPv4 default gateway.
func defaultGateway() (string, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			return fields[2], nil
		}
	}
	return "", fmt.Errorf("routing: no default gateway found")
}

// SetupServerTUN is not used on Windows (the server is Linux-only).
func SetupServerTUN(name string, addr net.IP, prefix int, mtu int) error {
	return nil
}

// SetupClientTUN assigns the client address, brings the interface up, pins the
// route to the VPN server via the current default gateway, and points the
// default route through the tunnel.
func SetupClientTUN(name string, clientIP net.IP, prefix int, gw net.IP, serverAddr string, mtu int) error {
	mask := net.CIDRMask(prefix, 32)
	if err := netshSetAddr(name, clientIP, mask); err != nil {
		return err
	}
	if mtu > 0 {
		if err := netshSetMTU(name, mtu); err != nil {
			return err
		}
	}
	host, _, err := net.SplitHostPort(serverAddr)
	if err != nil {
		host = serverAddr
	}
	if dev, err := defaultGateway(); err == nil && dev != "" {
		_ = run("route", "add", host, "mask", "255.255.255.255", dev)
	}
	return run("route", "add", "0.0.0.0", "mask", "0.0.0.0", gw.String(), "metric", "5")
}

// EnableIPForward is a no-op on Windows clients.
func EnableIPForward() error { return nil }

// SetupServerNAT is not supported on Windows (the server is Linux-only).
func SetupServerNAT(subnet, outIf string) error {
	return nil
}
