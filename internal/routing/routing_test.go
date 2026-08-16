package routing

import "testing"

func TestParseRouteGet(t *testing.T) {
	via, dev := parseRouteGet("10.0.0.5 via 172.17.0.1 dev eth0 src 10.0.0.2 uid 0")
	if via != "172.17.0.1" || dev != "eth0" {
		t.Fatalf("via=%q dev=%q", via, dev)
	}
	// On-link route: no via.
	via, dev = parseRouteGet("10.88.0.2 dev veth0 src 10.88.0.1 uid 0")
	if via != "" || dev != "veth0" {
		t.Fatalf("on-link: via=%q dev=%q", via, dev)
	}
	via, dev = parseRouteGet("")
	if via != "" || dev != "" {
		t.Fatalf("empty output: via=%q dev=%q", via, dev)
	}
}
