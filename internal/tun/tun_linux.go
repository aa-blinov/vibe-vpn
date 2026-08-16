//go:build linux

package tun

import (
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

// Tun is a Linux TUN interface.
type Tun struct {
	fd   int
	name string

	closeOnce sync.Once
}

// Open creates (or opens an existing) TUN device with the given name and MTU.
// It requires CAP_NET_ADMIN.
func Open(name string, mtu int) (Device, error) {
	if name == "" {
		name = "vibe%d"
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF %s: %w", name, err)
	}
	if mtu > 0 {
		if err := setMTU(ifr.Name(), mtu); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("tun: set mtu: %w", err)
		}
	}
	return &Tun{fd: fd, name: ifr.Name()}, nil
}

func setMTU(name string, mtu int) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(s) }()
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ifr.SetUint32(uint32(mtu)) // #nosec G115 -- mtu is bounded by config validation

	return unix.IoctlIfreq(s, unix.SIOCSIFMTU, ifr)
}

// Name returns the interface name that was actually created.
func (t *Tun) Name() string { return t.name }

// Read reads one IP packet into buf and returns its length.
func (t *Tun) Read(buf []byte) (int, error) {
	return unix.Read(t.fd, buf)
}

// ReadPacket reads one IP packet into a fresh buffer.
func (t *Tun) ReadPacket() ([]byte, error) {
	buf := make([]byte, 65536)
	n, err := t.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// Write writes one complete IP packet.
func (t *Tun) Write(b []byte) (int, error) {
	return unix.Write(t.fd, b)
}

// WritePacket writes one complete IP packet, discarding the byte count.
func (t *Tun) WritePacket(b []byte) error {
	_, err := t.Write(b)
	return err
}

// Close releases the device.
func (t *Tun) Close() error {
	t.closeOnce.Do(func() {
		_ = unix.Close(t.fd)
	})
	return nil
}
