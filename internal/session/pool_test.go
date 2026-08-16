package session

import (
	"net"
	"testing"
)

func TestIPPoolSkipsGateway(t *testing.T) {
	_, n, _ := net.ParseCIDR("10.77.0.0/24")
	p := newIPPool(n)
	t.Logf("gateway=%v base=%v mask=%v", net.IP(p.gateway[:]), p.network.IP, p.network.Mask)
	ip, err := p.alloc(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("first alloc = %v", ip)
	if !ip.Equal(net.ParseIP("10.77.0.2")) {
		t.Fatalf("first client IP should be .2, got %v", ip)
	}
}
