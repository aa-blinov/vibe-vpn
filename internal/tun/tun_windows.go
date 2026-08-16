//go:build windows

package tun

import (
	"fmt"

	"golang.zx2c4.com/wintun"
)

// wintunDevice is a Wintun adapter session. Wintun is the TUN driver from the
// WireGuard project, loaded as wintun.dll at runtime (no cgo).
type wintunDevice struct {
	adapter *wintun.Adapter
	session wintun.Session
	name    string
}

// Open creates a Wintun adapter and starts a packet session. The MTU is
// applied later via the routing layer (netsh), as Wintun does not expose an
// MTU setter.
func Open(name string, _ int) (Device, error) {
	if name == "" {
		name = "vibe-vpn"
	}
	adapter, err := wintun.CreateAdapter(name, "VibeVPN", nil)
	if err != nil {
		return nil, fmt.Errorf("tun: create wintun adapter: %w", err)
	}
	session, err := adapter.StartSession(0x400000) // 4 MiB ring
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("tun: start wintun session: %w", err)
	}
	return &wintunDevice{adapter: adapter, session: session, name: name}, nil
}

func (d *wintunDevice) Name() string { return d.name }

func (d *wintunDevice) Close() error {
	d.session.End()
	return d.adapter.Close()
}

func (d *wintunDevice) ReadPacket() ([]byte, error) {
	pkt, err := d.session.ReceivePacket()
	if err != nil {
		return nil, err
	}
	// Wintun ring buffers must be released before the next ReceivePacket, so
	// the packet is copied out.
	cp := append([]byte(nil), pkt...)
	d.session.ReleaseReceivePacket(pkt)
	return cp, nil
}

func (d *wintunDevice) WritePacket(b []byte) error {
	pkt, err := d.session.AllocateSendPacket(len(b))
	if err != nil {
		return err
	}
	copy(pkt, b)
	d.session.SendPacket(pkt)
	return nil
}
